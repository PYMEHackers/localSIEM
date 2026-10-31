"""Administrator API: accounts, access tokens of the direct sign-in, SOC
connection, channels (Telegram), settings, the audit log of the searches and the record of the
sign-ins (/api/admin/...). The modules (state, settings, sources, doctor and
rules) are in api_modules.py."""

import asyncio
import ssl

from fastapi import Body, HTTPException, Query, Request

from backend.core.channels import (
  TelegramClient, TelegramError, cChatIdRegex, cTokenRegex, fBotId, fChannelSettings, fTestMessage, lChannels, lLanguages
)
from backend.core.config import (
  cVersion, cWebPort, fDeleteTelegramToken, fMaskSecret, fReadSocToken, fReadTelegramToken, fSaveSettings, fSaveSocToken,
  fSaveTelegramToken
)
from backend.core.soc import SocClient, SocError
from backend.core.timeutil import fStorageFromNow, fStorageToDisplay
from backend.web.auth import fGeneratePassword, fIsAllowed, fParseAllowList, fValidateAllowList

lSeverities = ["low", "medium", "high", "critical"]
dNumberSettings = {
  "retention_days": (1, 3650),
  "alert_retention_days": (7, 3650),
  "max_disk_bytes": (0, 1 << 50),
  "group_window_seconds": (60, 86400),
  "group_buffer_seconds": (0, 3600),
  "correlation_window_seconds": (1, 60),
  "search_timeout_seconds": (1, 60),
  "export_max_rows": (100, 100000)
}


def fUserRow(pUser: dict) -> dict:
  dRow = dict(pUser)
  for vName in ("created_at", "last_login_at", "totp_enabled_at"):
    if dRow.get(vName):
      dRow[vName] = fStorageToDisplay(dRow[vName])
  dRow["is_active"] = bool(dRow.get("is_active"))
  dRow["must_change_password"] = bool(dRow.get("must_change_password"))
  return dRow


def fTokenRow(pToken: dict) -> dict:
  dRow = dict(pToken)
  for vName in ("created_at", "expires_at", "last_used_at", "revoked_at"):
    if dRow.get(vName):
      dRow[vName] = fStorageToDisplay(dRow[vName])
  dRow["is_active"] = bool(dRow.get("is_active"))
  return dRow


def fRegisterAdmin(pApp, pContext) -> None:

  async def fAdmin(pRequest: Request, pWrite: bool = False) -> dict:
    return await asyncio.to_thread(pContext.mRequireAdmin, pRequest, pWrite)

  def fNotifyCollector(pCommand: str) -> bool:
    try:
      pContext.mCollector({"command": pCommand}, 5)
      return True
    except HTTPException:
      return False

  # Users

  @pApp.get("/api/admin/users", tags=["admin"], summary="Accounts")
  async def fUsers(pRequest: Request):
    await fAdmin(pRequest)
    return {"users": [fUserRow(dUser) for dUser in await asyncio.to_thread(pContext.vAccounts.mListUsers)]}

  @pApp.post("/api/admin/users", tags=["admin"], summary="Create an account")
  async def fCreateUser(pRequest: Request, dBody: dict = Body(...)):
    """username, role (admin or analyst), full_name, language. Answers a generated password, shown once; it must be changed at the first sign-in."""
    await fAdmin(pRequest, True)
    vPassword = fGeneratePassword()
    try:
      vId = await asyncio.to_thread(
        pContext.vAccounts.mCreateUser, str(dBody.get("username", "")), str(dBody.get("role", "analyst")), vPassword,
        str(dBody.get("full_name", "")), str(dBody.get("language", "en-US"))
      )
    except ValueError as vError:
      raise HTTPException(status_code=422, detail=str(vError)) from None
    return {"id": vId, "password": vPassword}

  @pApp.patch("/api/admin/users/{pUserId}", tags=["admin"], summary="Change an account (role, name, active)")
  async def fPatchUser(pUserId: int, pRequest: Request, dBody: dict = Body(...)):
    dSession = await fAdmin(pRequest, True)
    dUser = await asyncio.to_thread(pContext.vAccounts.mGetUser, pUserId)
    if dUser is None:
      raise HTTPException(status_code=404, detail="not_found")
    vDemotes = dUser["role"] == "admin" and (dBody.get("role", "admin") != "admin" or dBody.get("is_active", True) is False)
    if vDemotes and await asyncio.to_thread(pContext.vAccounts.mActiveAdminCount) <= 1:
      raise HTTPException(status_code=422, detail="last_admin")
    if pUserId == dSession["id"] and (dBody.get("is_active") is False or dBody.get("role", "admin") != "admin"):
      raise HTTPException(status_code=422, detail="cannot_change_self")
    try:
      await asyncio.to_thread(pContext.vAccounts.mUpdateUser, pUserId, {vKey: dBody[vKey] for vKey in ("role", "full_name", "is_active") if vKey in dBody})
    except ValueError as vError:
      raise HTTPException(status_code=422, detail=str(vError)) from None
    return {"ok": True}

  @pApp.post("/api/admin/users/{pUserId}/password", tags=["admin"], summary="Reset the password of an account")
  async def fResetPassword(pUserId: int, pRequest: Request):
    """Answers a generated password, shown once. The sessions of the account are closed."""
    await fAdmin(pRequest, True)
    if await asyncio.to_thread(pContext.vAccounts.mGetUser, pUserId) is None:
      raise HTTPException(status_code=404, detail="not_found")
    vPassword = fGeneratePassword()
    await asyncio.to_thread(pContext.vAccounts.mSetPassword, pUserId, vPassword, True, None)
    return {"password": vPassword}

  @pApp.post("/api/admin/users/{pUserId}/totp-reset", tags=["admin"], summary="Reset the two-step verification of an account")
  async def fResetTotp(pUserId: int, pRequest: Request):
    """The next sign-in shows a new QR code."""
    await fAdmin(pRequest, True)
    if await asyncio.to_thread(pContext.vAccounts.mGetUser, pUserId) is None:
      raise HTTPException(status_code=404, detail="not_found")
    await asyncio.to_thread(pContext.vAccounts.mResetTotp, pUserId)
    return {"ok": True}

  @pApp.delete("/api/admin/users/{pUserId}", tags=["admin"], summary="Delete an account")
  async def fDeleteUser(pUserId: int, pRequest: Request):
    dSession = await fAdmin(pRequest, True)
    dUser = await asyncio.to_thread(pContext.vAccounts.mGetUser, pUserId)
    if dUser is None:
      raise HTTPException(status_code=404, detail="not_found")
    if pUserId == dSession["id"]:
      raise HTTPException(status_code=422, detail="cannot_change_self")
    if dUser["role"] == "admin" and dUser["is_active"] and await asyncio.to_thread(pContext.vAccounts.mActiveAdminCount) <= 1:
      raise HTTPException(status_code=422, detail="last_admin")
    await asyncio.to_thread(pContext.vAccounts.mDeleteUser, pUserId)
    return {"ok": True}

  # SOC

  def fSocSettings() -> dict:
    vToken = fReadSocToken()
    return {
      "url": pContext.dSettings.get("soc_url", ""), "enabled": bool(pContext.dSettings.get("soc_enabled", True)),
      "ca_file": pContext.dSettings.get("soc_ca_file", ""), "token": fMaskSecret(vToken), "token_set": bool(vToken),
      "host": pContext.dSettings.get("host", ""), "port": cWebPort
    }

  @pApp.get("/api/admin/soc", tags=["admin"], summary="SOC connection, queue, last heartbeat and last error")
  async def fSoc(pRequest: Request):
    """The token is never shown whole."""
    await fAdmin(pRequest)
    dResult = {"settings": fSocSettings(), "status": None, "heartbeat": None, "queue": None}
    try:
      vStorage = pContext.mEvents()
    except HTTPException:
      return dResult
    dStatus = await asyncio.to_thread(vStorage.mGetState, "soc.status", None)
    dHeartbeat = await asyncio.to_thread(vStorage.mGetState, "soc.heartbeat", None)
    dQueue = await asyncio.to_thread(vStorage.mQueueStatistics)
    for dValue in (dStatus, dHeartbeat):
      if isinstance(dValue, dict):
        for vName in ("time", "last_success", "last_ok"):
          if dValue.get(vName):
            dValue[vName] = fStorageToDisplay(dValue[vName])
    if dQueue.get("oldest_pending"):
      dQueue["oldest_pending"] = fStorageToDisplay(dQueue["oldest_pending"])
    dResult.update({"status": dStatus, "heartbeat": dHeartbeat, "queue": dQueue})
    return dResult

  @pApp.post("/api/admin/soc", tags=["admin"], summary="Change the SOC URL, token or CA file")
  async def fSaveSoc(pRequest: Request, dBody: dict = Body(...)):
    """url (https://), token (only when it changes), ca_file (optional, for a SOC with a private certificate), enabled."""
    await fAdmin(pRequest, True)
    dChanges = {}
    if "url" in dBody:
      vUrl = str(dBody["url"] or "").strip().rstrip("/")
      if not vUrl.startswith("https://") or len(vUrl) > 300:
        raise HTTPException(status_code=422, detail="invalid_url")
      dChanges["soc_url"] = vUrl
    if "ca_file" in dBody:
      dChanges["soc_ca_file"] = str(dBody["ca_file"] or "").strip()
    if "enabled" in dBody:
      dChanges["soc_enabled"] = bool(dBody["enabled"])
    if dChanges:
      await asyncio.to_thread(fSaveSettings, dChanges)
    if dBody.get("token"):
      vToken = str(dBody["token"]).strip()
      if len(vToken) < 16 or len(vToken) > 512 or any(vChar.isspace() for vChar in vToken):
        raise HTTPException(status_code=422, detail="invalid_token")
      await asyncio.to_thread(fSaveSocToken, vToken)
    pContext.mApplySettings()
    vNotified = await asyncio.to_thread(fNotifyCollector, "reload")
    return {"ok": True, "collector_notified": vNotified, "settings": fSocSettings()}

  @pApp.post("/api/admin/soc/test", tags=["admin"], summary="Test the connection to the SOC (sends a heartbeat)")
  async def fTestSoc(pRequest: Request):
    await fAdmin(pRequest, True)
    vToken = fReadSocToken()
    if not vToken:
      raise HTTPException(status_code=422, detail="soc_token_missing")

    def fTest():
      try:
        vClient = SocClient(pContext.dSettings.get("soc_url", ""), vToken, pContext.dSettings.get("soc_ca_file", ""))
        vClient.mHeartbeat()
        return {"ok": True, "status": 200}
      except SocError as vError:
        return {"ok": False, "status": vError.vStatus, "error": vError.vCode}
      except (OSError, ssl.SSLError, ValueError) as vError:
        return {"ok": False, "status": 0, "error": type(vError).__name__ + ": " + str(vError)[:300]}
    return await asyncio.to_thread(fTest)

  @pApp.post("/api/admin/soc/retry", tags=["admin"], summary="Send the queue now")
  async def fRetrySoc(pRequest: Request):
    await fAdmin(pRequest, True)
    return await asyncio.to_thread(pContext.mCollector, {"command": "soc_retry"}, 5)

  @pApp.post("/api/admin/soc/requeue", tags=["admin"], summary="Queue the rejected alerts again")
  async def fRequeueSoc(pRequest: Request):
    await fAdmin(pRequest, True)
    return await asyncio.to_thread(pContext.mCollector, {"command": "soc_requeue_rejected"}, 5)

  # Channels (backend/core/channels.py): the general settings and Telegram

  def fChannelsView() -> dict:
    dChannels = fChannelSettings(pContext.dSettings)
    vToken = fReadTelegramToken()
    dChannels["telegram"].update({"token": fMaskSecret(vToken), "token_set": bool(vToken), "bot_id": fBotId(vToken)})
    return dChannels

  @pApp.get("/api/admin/channels", tags=["channels"], summary="Settings and state of the channels (Telegram)")
  async def fChannels(pRequest: Request):
    """settings: enabled (all the channels), min_severity (the alerts of that severity or above are sent), language (of the messages) and one block per channel; telegram: enabled, chat_id, token (never whole), token_set and bot_id (the part of the token before the colon). status, written by the collector, per channel: state (off, not_configured, ok or error), sent, failed, dropped, pending, last_sent, last_error and last_error_time. Also the lists severities, languages and channels."""
    await fAdmin(pRequest)
    dResult = {"settings": fChannelsView(), "status": None, "severities": lSeverities, "languages": lLanguages, "channels": lChannels}
    try:
      vStorage = pContext.mEvents()
    except HTTPException:
      return dResult
    dStatus = await asyncio.to_thread(vStorage.mGetState, "channels.status", None)
    if isinstance(dStatus, dict):
      if dStatus.get("time"):
        dStatus["time"] = fStorageToDisplay(dStatus["time"])
      for vName in lChannels:
        dChannel = dStatus.get(vName)
        if isinstance(dChannel, dict):
          for vKey in ("last_sent", "last_error_time"):
            if dChannel.get(vKey):
              dChannel[vKey] = fStorageToDisplay(dChannel[vKey])
      dResult["status"] = dStatus
    return dResult

  @pApp.post("/api/admin/channels", tags=["channels"], summary="Save the general settings of the channels")
  async def fSaveChannels(pRequest: Request, dBody: dict = Body(...)):
    """enabled (true or false: all the channels at once), min_severity (low, medium, high or critical: the alerts of that severity or above are sent) and language of the messages (en-GB, en-US, es-AR or es-ES). The collector applies them at once."""
    await fAdmin(pRequest, True)
    dChanges = {}
    if "enabled" in dBody:
      if not isinstance(dBody["enabled"], bool):
        raise HTTPException(status_code=422, detail="invalid_enabled")
      dChanges["enabled"] = dBody["enabled"]
    if "min_severity" in dBody:
      if dBody["min_severity"] not in lSeverities:
        raise HTTPException(status_code=422, detail="invalid_severity")
      dChanges["min_severity"] = dBody["min_severity"]
    if "language" in dBody:
      if dBody["language"] not in lLanguages:
        raise HTTPException(status_code=422, detail="invalid_language")
      dChanges["language"] = dBody["language"]
    if dChanges:
      await asyncio.to_thread(fSaveSettings, {"channels": dChanges})
      pContext.mApplySettings()
    vNotified = await asyncio.to_thread(fNotifyCollector, "reload")
    return {"ok": True, "collector_notified": vNotified, "settings": fChannelsView()}

  @pApp.post("/api/admin/channels/telegram", tags=["channels"], summary="Save the Telegram channel: token of the bot, chat id, on or off")
  async def fSaveTelegram(pRequest: Request, dBody: dict = Body(...)):
    """token (only when it changes: the one @BotFather gives, <id of the bot>:<secret>; kept in config/telegram-bot-token, mode 600), remove_token (true deletes the saved token and turns the channel off), chat_id (the numeric id of a person, a group or a channel, or the @username of a public channel or group; empty clears it) and enabled. It can only be turned on with a token and a chat id (telegram_incomplete)."""
    await fAdmin(pRequest, True)
    dChanges = {}
    if "chat_id" in dBody:
      vChatId = str(dBody["chat_id"] or "").strip()
      if vChatId and not cChatIdRegex.match(vChatId):
        raise HTTPException(status_code=422, detail="invalid_chat_id")
      dChanges["chat_id"] = vChatId
    vToken = str(dBody.get("token") or "").strip()
    if vToken and not cTokenRegex.match(vToken):
      raise HTTPException(status_code=422, detail="invalid_bot_token")
    if "enabled" in dBody:
      if not isinstance(dBody["enabled"], bool):
        raise HTTPException(status_code=422, detail="invalid_enabled")
      dChanges["enabled"] = dBody["enabled"]
    vRemove = dBody.get("remove_token") is True and not vToken
    if vRemove:
      dChanges["enabled"] = False
    vFinalToken = vToken or ("" if vRemove else fReadTelegramToken())
    vFinalChatId = dChanges.get("chat_id", fChannelSettings(pContext.dSettings)["telegram"]["chat_id"])
    if dChanges.get("enabled") and (not vFinalToken or not vFinalChatId):
      raise HTTPException(status_code=422, detail="telegram_incomplete")
    if vToken:
      await asyncio.to_thread(fSaveTelegramToken, vToken)
    elif vRemove:
      await asyncio.to_thread(fDeleteTelegramToken)
    if dChanges:
      await asyncio.to_thread(fSaveSettings, {"channels": {"telegram": dChanges}})
      pContext.mApplySettings()
    vNotified = await asyncio.to_thread(fNotifyCollector, "reload")
    return {"ok": True, "collector_notified": vNotified, "settings": fChannelsView()}

  @pApp.post("/api/admin/channels/telegram/test", tags=["channels"], summary="Send a test message through Telegram")
  async def fTestTelegram(pRequest: Request):
    """With the saved token and chat id, also while the channel is off, in the language of the messages. Answers ok and the bot (id and username) when Telegram took the message; otherwise ok false, status (the HTTP status of Telegram; 0 when it could not be reached) and error (the description of Telegram, for example «Unauthorized» or «Bad Request: chat not found»)."""
    await fAdmin(pRequest, True)
    vToken = fReadTelegramToken()
    dChannels = fChannelSettings(pContext.dSettings)
    if not vToken:
      raise HTTPException(status_code=422, detail="telegram_token_missing")
    if not dChannels["telegram"]["chat_id"]:
      raise HTTPException(status_code=422, detail="telegram_chat_missing")

    def fTest():
      try:
        vClient = TelegramClient(vToken)
        dBot = vClient.mGetMe()
        vClient.mSendMessage(dChannels["telegram"]["chat_id"], fTestMessage(pContext.dSettings.get("host", ""), dChannels["language"], dChannels["min_severity"]))
        return {"ok": True, "bot": {"id": dBot.get("id"), "username": dBot.get("username", "")}}
      except TelegramError as vError:
        return {"ok": False, "status": vError.vStatus, "error": vError.vDescription}
    return await asyncio.to_thread(fTest)

  # Settings

  def fSettingsView() -> dict:
    dSettings = pContext.dSettings
    dView = {vName: dSettings.get(vName) for vName in dNumberSettings}
    dView.update({
      "allow_from": dSettings.get("allow_from", []),
      "below_threshold_severity": dSettings.get("below_threshold_severity", "low"),
      "mfa_enabled": bool(dSettings.get("mfa_enabled", False)),
      "host": dSettings.get("host", ""),
      "port": cWebPort,
      "version": cVersion
    })
    return dView

  @pApp.get("/api/admin/settings", tags=["admin"], summary="Retention, disk, allowed IPs, two-step verification, windows and severity below the threshold")
  async def fGetSettings(pRequest: Request):
    await fAdmin(pRequest)
    dView = fSettingsView()
    try:
      dStatus = await asyncio.to_thread(pContext.mEvents().mGetState, "collector.status", None)
    except HTTPException:
      dStatus = None
    if dStatus:
      dView["database"] = dStatus.get("database")
      dView["disk"] = dStatus.get("disk")
    return dView

  @pApp.post("/api/admin/settings", tags=["admin"], summary="Save the settings")
  async def fSaveSettingsRoute(pRequest: Request, dBody: dict = Body(...)):
    """The collector applies them at once. The allowed IPs must include the address of the administrator saving them. mfa_enabled (true or false) turns two-step verification on or off for every account: once on, the sessions of the accounts that have not set it up close, and they set it up at their next sign-in; session_closed is true when that closed the session of the administrator saving it."""
    dSession = await fAdmin(pRequest, True)
    dChanges = {}
    for vName, (vMinimum, vMaximum) in dNumberSettings.items():
      if vName in dBody:
        try:
          vValue = int(dBody[vName])
        except (TypeError, ValueError):
          raise HTTPException(status_code=422, detail="invalid_" + vName) from None
        if not vMinimum <= vValue <= vMaximum:
          raise HTTPException(status_code=422, detail="invalid_" + vName)
        if vName == "max_disk_bytes" and 0 < vValue < 100 * 1024 * 1024:
          raise HTTPException(status_code=422, detail="invalid_" + vName)
        dChanges[vName] = vValue
    if "below_threshold_severity" in dBody:
      if dBody["below_threshold_severity"] not in lSeverities:
        raise HTTPException(status_code=422, detail="invalid_severity")
      dChanges["below_threshold_severity"] = dBody["below_threshold_severity"]
    if "allow_from" in dBody:
      lEntries = dBody["allow_from"] if isinstance(dBody["allow_from"], list) else str(dBody["allow_from"] or "").replace("\n", ",").split(",")
      try:
        lClean = fValidateAllowList(lEntries)
      except ValueError:
        raise HTTPException(status_code=422, detail="invalid_allow_from") from None
      vIp = pContext.mClientIp(pRequest)
      if lClean and not fIsAllowed(vIp, fParseAllowList(lClean), False):
        raise HTTPException(status_code=422, detail={"error": "allow_from_excludes_you", "ip": vIp})
      dChanges["allow_from"] = lClean
    if "mfa_enabled" in dBody:
      if not isinstance(dBody["mfa_enabled"], bool):
        raise HTTPException(status_code=422, detail="invalid_mfa_enabled")
      dChanges["mfa_enabled"] = dBody["mfa_enabled"]
    if dChanges:
      await asyncio.to_thread(fSaveSettings, dChanges)
      pContext.mApplySettings()
    vNotified = await asyncio.to_thread(fNotifyCollector, "reload")
    # Turned on: a session without the second factor is not valid any more
    # (Accounts.mLoadSession), the one of this administrator included.
    vSessionClosed = bool(pContext.dSettings.get("mfa_enabled", False)) and not dSession["totp_enabled_at"]
    return {"ok": True, "collector_notified": vNotified, "settings": fSettingsView(), "session_closed": vSessionClosed}

  # Audit log of the searches

  @pApp.get("/api/admin/audit", tags=["admin"], summary="Audit log of the searches: who searched what and when")
  async def fAudit(pRequest: Request, before: int | None = Query(None), limit: int = Query(100, ge=1, le=500)):
    await fAdmin(pRequest)
    await asyncio.to_thread(pContext.vAccounts.mDeleteOldAudit, fStorageFromNow(-86400 * float(pContext.dSettings.get("retention_days", 90))))
    ldRows = await asyncio.to_thread(pContext.vAccounts.mListAudit, before, limit)
    for dRow in ldRows:
      for vName in ("time", "range_from", "range_to"):
        dRow[vName] = fStorageToDisplay(dRow[vName])
    return {"entries": ldRows, "next": ldRows[-1]["id"] if len(ldRows) == limit else None}

  # Access tokens of the direct sign-in (/auth/login/auto?token=...)

  @pApp.get("/api/admin/tokens", tags=["admin"], summary="Access tokens of the direct sign-in")
  async def fTokens(pRequest: Request):
    """Each token: account, label, last 4 characters (token_hint), created (when and by whom), expiry, last use (when and from which IP) and state: active, expired, revoked or unusable (the account is disabled or no longer an analyst). The token itself is never shown again."""
    await fAdmin(pRequest)
    return {"tokens": [fTokenRow(dToken) for dToken in await asyncio.to_thread(pContext.vAccounts.mListAccessTokens)]}

  @pApp.post("/api/admin/tokens", tags=["admin"], summary="Create an access token for an analyst account")
  async def fCreateToken(pRequest: Request, dBody: dict = Body(...)):
    """user_id (an active analyst account: administrators always sign in with their password, and with the second factor when two-step verification is on), label, and days of validity (1 to 365, default 90). The answer carries the token, shown only this time, and path: /auth/login/auto?token=..., which opens a session of that account without password nor second factor from an allowed IP."""
    dSession = await fAdmin(pRequest, True)
    try:
      vUserId = int(dBody.get("user_id"))
      vDays = int(dBody.get("days", 90))
    except (TypeError, ValueError):
      raise HTTPException(status_code=422, detail="invalid_request") from None
    try:
      vId, vToken = await asyncio.to_thread(pContext.vAccounts.mCreateAccessToken, vUserId, str(dBody.get("label") or ""), vDays, dSession["username"])
    except ValueError as vError:
      raise HTTPException(status_code=404 if str(vError) == "not_found" else 422, detail=str(vError)) from None
    return {"ok": True, "id": vId, "token": vToken, "path": "/auth/login/auto?token=" + vToken}

  @pApp.delete("/api/admin/tokens/{pTokenId}", tags=["admin"], summary="Revoke an access token")
  async def fRevokeToken(pTokenId: int, pRequest: Request):
    """The token stops working at once; the sessions it already opened end when they expire. It stays in the list, as revoked."""
    await fAdmin(pRequest, True)
    if not await asyncio.to_thread(pContext.vAccounts.mRevokeAccessToken, pTokenId):
      raise HTTPException(status_code=404, detail="not_found")
    return {"ok": True}

  # Record of the sign-ins

  @pApp.get("/api/admin/logins", tags=["admin"], summary="Record of the sign-ins: who, when, how and from where, also the failed attempts")
  async def fLogins(pRequest: Request, before: int | None = Query(None), limit: int = Query(100, ge=1, le=500), result: str = Query("", pattern="^(|ok|failed)$")):
    """method: password (two-step verification off), password_totp or token (direct sign-in). result: ok or failed, with the reason (invalid_credentials, invalid_code, login_blocked, challenge_expired, token_invalid, token_expired, token_revoked, account_disabled, token_needs_analyst). Kept as long as the alerts (alert_retention_days)."""
    await fAdmin(pRequest)
    await asyncio.to_thread(pContext.vAccounts.mDeleteOldLogins, fStorageFromNow(-86400 * float(pContext.dSettings.get("alert_retention_days", 365))))
    ldRows = await asyncio.to_thread(pContext.vAccounts.mListLogins, before, limit, result)
    for dRow in ldRows:
      dRow["time"] = fStorageToDisplay(dRow["time"])
    return {"entries": ldRows, "next": ldRows[-1]["id"] if len(ldRows) == limit else None}
