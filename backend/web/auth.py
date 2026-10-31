"""Accounts, sessions, two-step verification, CSRF and the allowed IPs.

  - Local accounts created by an administrator; no open registration.
  - Two-step verification (TOTP) off by default. An administrator turns it
    on in Settings (or the installer with --enable-mfa), and from then on it
    is mandatory for everybody.
  - Passwords of at least 8 characters (PBKDF2-SHA256, backend/security.py).
  - Temporary lockout after several failed attempts (per account and IP,
    and per IP).
  - Session cookie HttpOnly, Secure, SameSite=Lax; every write needs the
    X-CSRF-Token header of the session and the page's own origin.
  - List of allowed IPs and CIDR applied by the application to the whole
    web, login included. Loopback is always allowed.
  - Direct sign-in with an access token (/auth/login/auto?token=...), which
    an administrator creates for an analyst account: no password and no
    second factor, so it only works for analysts, it expires, it can be
    revoked, and only its hash is kept. A session opened this way asks for
    neither two-step verification nor a password change.
  - Every sign-in, and every failed attempt, is recorded (logins).
"""

import datetime
import hashlib
import hmac
import ipaddress
import re
import secrets
import urllib.parse

import jwt

from backend.core.timeutil import fNowStorage, fStorageFromNow
from backend.security import fHashPassword, fVerifyPassword
from backend.web import totp

cSessionCookie = "localsiem_session"
cMinimumPasswordLength = 8
cMaximumPasswordLength = 256
cRoles = ("admin", "analyst")
cUsernameRegex = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")
cChallengeSeconds = 300
# Failed direct sign-ins count, for the lockout, as attempts of this name.
cTokenAttempt = "(access token)"
cMaximumTokenDays = 365
vDummyHash = None


def fHashToken(pToken: str) -> str:
  return hashlib.sha256(pToken.encode("utf-8")).hexdigest()


def fGeneratePassword() -> str:
  # 20 characters from an alphabet without look-alike glyphs.
  cAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
  return "".join(secrets.choice(cAlphabet) for _ in range(20))


def fValidatePassword(pPassword: str) -> str | None:
  if len(pPassword or "") < cMinimumPasswordLength:
    return "password_too_short"
  if len(pPassword) > cMaximumPasswordLength:
    return "password_too_long"
  return None


def fNormalizeIp(pValue: str) -> str:
  vValue = str(pValue or "")
  try:
    vAddress = ipaddress.ip_address(vValue)
    if isinstance(vAddress, ipaddress.IPv6Address) and vAddress.ipv4_mapped:
      return str(vAddress.ipv4_mapped)
    return str(vAddress)
  except ValueError:
    return vValue


def fParseAllowList(pEntries: list) -> list:
  lNetworks = []
  for vEntry in pEntries or []:
    vText = str(vEntry).strip()
    if not vText:
      continue
    try:
      lNetworks.append(ipaddress.ip_network(vText, strict=False))
    except ValueError:
      continue
  return lNetworks


def fIsLoopback(pIp: str) -> bool:
  try:
    return ipaddress.ip_address(fNormalizeIp(pIp)).is_loopback
  except ValueError:
    return False


def fIsAllowed(pIp: str, pNetworks: list, pOpenWhenEmpty: bool = True) -> bool:
  vIp = fNormalizeIp(pIp)
  try:
    vAddress = ipaddress.ip_address(vIp)
  except ValueError:
    return False
  if vAddress.is_loopback:
    return True
  if not pNetworks:
    return pOpenWhenEmpty
  return any(vAddress.version == vNetwork.version and vAddress in vNetwork for vNetwork in pNetworks)


def fValidateAllowList(pEntries: list) -> list[str]:
  lClean = []
  for vEntry in pEntries or []:
    vText = str(vEntry).strip()
    if not vText:
      continue
    ipaddress.ip_network(vText, strict=False)
    lClean.append(vText)
  return lClean


def fClientIp(pRequest) -> str:
  # localSIEM serves HTTPS directly, with no proxy in front: the peer address
  # is the client.
  vClient = pRequest.client
  return fNormalizeIp(vClient.host) if vClient and vClient.host else "unknown"


class Accounts:

  def __init__(self, pDatabase, pSettings: dict, pSecret: str):
    self.vDatabase = pDatabase
    self.dSettings = pSettings
    self.vSecret = pSecret

  # Users

  def mUserCount(self) -> int:
    return self.vDatabase.mOne("SELECT COUNT(*) AS n FROM users")["n"]

  def mGetUser(self, pUserId: int) -> dict | None:
    return self.vDatabase.mOne("SELECT * FROM users WHERE id = ?", (int(pUserId),))

  def mGetUserByName(self, pUsername: str) -> dict | None:
    return self.vDatabase.mOne("SELECT * FROM users WHERE username = ?", (str(pUsername or "").strip(),))

  def mListUsers(self) -> list[dict]:
    return self.vDatabase.mAll(
      "SELECT id, username, full_name, role, is_active, language, totp_enabled_at, must_change_password, created_at, last_login_at FROM users ORDER BY username"
    )

  def mCreateUser(self, pUsername: str, pRole: str, pPassword: str, pFullName: str = "", pLanguage: str = "en-US") -> int:
    vUsername = str(pUsername or "").strip()
    if not cUsernameRegex.match(vUsername):
      raise ValueError("invalid_username")
    if pRole not in cRoles:
      raise ValueError("invalid_role")
    vProblem = fValidatePassword(pPassword)
    if vProblem:
      raise ValueError(vProblem)
    if self.mGetUserByName(vUsername):
      raise ValueError("username_taken")
    vHash = fHashPassword(pPassword)
    vNow = fNowStorage()
    return self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "INSERT INTO users (username, full_name, role, password_hash, language, must_change_password, created_at, password_changed_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
      (vUsername, str(pFullName or "")[:120], pRole, vHash, pLanguage, vNow, vNow)
    ).lastrowid)

  def mUpdateUser(self, pUserId: int, pChanges: dict) -> None:
    lSets = []
    lValues = []
    if "role" in pChanges:
      if pChanges["role"] not in cRoles:
        raise ValueError("invalid_role")
      lSets.append("role = ?")
      lValues.append(pChanges["role"])
    if "full_name" in pChanges:
      lSets.append("full_name = ?")
      lValues.append(str(pChanges["full_name"] or "")[:120])
    if "is_active" in pChanges:
      lSets.append("is_active = ?")
      lValues.append(1 if pChanges["is_active"] else 0)
    if "language" in pChanges:
      lSets.append("language = ?")
      lValues.append(str(pChanges["language"]))
    if not lSets:
      return
    lValues.append(int(pUserId))

    def fWrite(pConnection):
      pConnection.execute("UPDATE users SET " + ", ".join(lSets) + " WHERE id = ?", lValues)
      if pChanges.get("is_active") is False:
        pConnection.execute("DELETE FROM sessions WHERE user_id = ?", (int(pUserId),))
    self.vDatabase.mWrite(fWrite)

  def mSetPassword(self, pUserId: int, pPassword: str, pMustChange: bool, pKeepSession: int | None = None) -> None:
    vProblem = fValidatePassword(pPassword)
    if vProblem:
      raise ValueError(vProblem)
    vHash = fHashPassword(pPassword)

    def fWrite(pConnection):
      pConnection.execute(
        "UPDATE users SET password_hash = ?, must_change_password = ?, password_changed_at = ? WHERE id = ?",
        (vHash, 1 if pMustChange else 0, fNowStorage(), int(pUserId))
      )
      if pKeepSession is None:
        pConnection.execute("DELETE FROM sessions WHERE user_id = ?", (int(pUserId),))
      else:
        pConnection.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (int(pUserId), int(pKeepSession)))
    self.vDatabase.mWrite(fWrite)

  def mResetTotp(self, pUserId: int) -> None:
    def fWrite(pConnection):
      pConnection.execute(
        "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled_at = NULL, totp_last_step = 0 WHERE id = ?",
        (int(pUserId),)
      )
      pConnection.execute("DELETE FROM sessions WHERE user_id = ?", (int(pUserId),))
    self.vDatabase.mWrite(fWrite)

  def mDeleteUser(self, pUserId: int) -> None:
    def fWrite(pConnection):
      pConnection.execute("DELETE FROM sessions WHERE user_id = ?", (int(pUserId),))
      pConnection.execute("DELETE FROM access_tokens WHERE user_id = ?", (int(pUserId),))
      pConnection.execute("DELETE FROM users WHERE id = ?", (int(pUserId),))
    self.vDatabase.mWrite(fWrite)

  def mActiveAdminCount(self) -> int:
    return self.vDatabase.mOne("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1")["n"]

  # Login

  def mIsBlocked(self, pUsername: str, pIp: str) -> bool:
    vSince = fStorageFromNow(-int(self.dSettings.get("login_window_seconds", 900)))
    vMaximum = int(self.dSettings.get("login_max_failures", 5))
    vPair = self.vDatabase.mOne(
      "SELECT COUNT(*) AS n FROM login_attempts WHERE username = ? AND ip = ? AND success = 0 AND attempted_at >= ?",
      (str(pUsername).lower(), pIp, vSince)
    )["n"]
    vPerIp = self.vDatabase.mOne(
      "SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND success = 0 AND attempted_at >= ?",
      (pIp, vSince)
    )["n"]
    return vPair >= vMaximum or vPerIp >= vMaximum * 10

  def mRecordAttempt(self, pUsername: str, pIp: str, pSuccess: bool) -> None:
    def fWrite(pConnection):
      if pSuccess:
        pConnection.execute("DELETE FROM login_attempts WHERE username = ? AND ip = ?", (str(pUsername).lower(), pIp))
      pConnection.execute(
        "INSERT INTO login_attempts (username, ip, success, attempted_at) VALUES (?, ?, ?, ?)",
        (str(pUsername).lower()[:128], pIp, 1 if pSuccess else 0, fNowStorage())
      )
      pConnection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (fStorageFromNow(-86400),))
    self.vDatabase.mWrite(fWrite)

  def mCheckPassword(self, pUsername: str, pPassword: str) -> dict | None:
    global vDummyHash
    dUser = self.mGetUserByName(pUsername)
    if dUser is None or not dUser["is_active"]:
      # Same work for unknown accounts, so the answer time does not tell.
      if vDummyHash is None:
        vDummyHash = fHashPassword(secrets.token_urlsafe(16))
      fVerifyPassword(str(pPassword or ""), vDummyHash)
      return None
    if not fVerifyPassword(str(pPassword or ""), dUser["password_hash"]):
      return None
    return dUser

  def mChallenge(self, pUser: dict, pStage: str) -> str:
    vNow = datetime.datetime.now(datetime.UTC)
    return jwt.encode({
      "sub": str(pUser["id"]), "stage": pStage, "iat": vNow, "exp": vNow + datetime.timedelta(seconds=cChallengeSeconds),
      "iss": "localSIEM-login", "aud": "localSIEM-login", "pwd": pUser["password_changed_at"] or ""
    }, self.vSecret, algorithm="HS256")

  def mReadChallenge(self, pChallenge: str) -> tuple[dict, str] | None:
    try:
      dPayload = jwt.decode(
        str(pChallenge or ""), self.vSecret, algorithms=["HS256"], audience="localSIEM-login", issuer="localSIEM-login",
        options={"require": ["sub", "stage", "exp", "iat"]}
      )
    except jwt.InvalidTokenError:
      return None
    dUser = self.mGetUser(int(dPayload["sub"]))
    if dUser is None or not dUser["is_active"] or (dUser["password_changed_at"] or "") != dPayload.get("pwd", ""):
      return None
    return dUser, dPayload["stage"]

  def mStartEnrollment(self, pUser: dict) -> dict:
    vSecret = totp.fNewSecret()
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "UPDATE users SET totp_pending_secret = ? WHERE id = ?", (vSecret, pUser["id"])
    ))
    vUri = totp.fOtpauthUri(vSecret)
    return {"secret": vSecret, "otpauth": vUri, "qr": totp.fQrDataUri(vUri)}

  def mVerifyTotp(self, pUser: dict, pStage: str, pCode: str) -> bool:
    if pStage == "enroll":
      vSecret = pUser.get("totp_pending_secret")
    else:
      vSecret = pUser.get("totp_secret")
    if not vSecret:
      return False
    vStep = totp.fMatchCode(vSecret, pCode, pUser.get("totp_last_step") or 0)
    if vStep is None:
      return False

    def fWrite(pConnection):
      if pStage == "enroll":
        pConnection.execute(
          "UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_enabled_at = ?, totp_last_step = ? WHERE id = ?",
          (fNowStorage(), vStep, pUser["id"])
        )
      else:
        pConnection.execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?", (vStep, pUser["id"], vStep))
    self.vDatabase.mWrite(fWrite)
    return True

  # Sessions

  def mCreateSession(self, pUserId: int, pIp: str, pUserAgent: str, pMethod: str = "password") -> tuple[str, str]:
    # pMethod: "password" or "token" (direct sign-in).
    vToken = secrets.token_urlsafe(32)
    vCsrf = secrets.token_urlsafe(32)
    vNow = fNowStorage()
    vExpires = fStorageFromNow(float(self.dSettings.get("session_hours", 8)) * 3600)

    def fWrite(pConnection):
      pConnection.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent, method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (fHashToken(vToken), int(pUserId), vCsrf, vNow, vNow, vExpires, pIp, str(pUserAgent or "")[:300], pMethod)
      )
      pConnection.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (vNow, int(pUserId)))
      pConnection.execute("DELETE FROM sessions WHERE expires_at < ?", (vNow,))
    self.vDatabase.mWrite(fWrite)
    return vToken, vCsrf

  def mLoadSession(self, pToken: str) -> dict | None:
    if not pToken:
      return None
    vNow = fNowStorage()
    dRow = self.vDatabase.mOne(
      "SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.last_seen_at, s.method, u.id, u.username, u.full_name, u.role, u.is_active, u.language, "
      "u.totp_enabled_at, u.must_change_password FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
      (fHashToken(pToken),)
    )
    if dRow is None or dRow["expires_at"] < vNow or not dRow["is_active"]:
      return None
    if dRow["method"] == "token":
      # Opened with an access token: only analysts, and it asks for neither
      # the second factor nor a password change.
      if dRow["role"] != "analyst":
        return None
      dRow["must_change_password"] = 0
    elif self.dSettings.get("mfa_enabled", False) and not dRow["totp_enabled_at"]:
      # Two-step verification is on, so it is mandatory: a session without
      # it (opened while it was off, or after a reset) is not valid any more.
      return None
    if dRow["last_seen_at"][:16] != vNow[:16]:
      self.vDatabase.mWrite(lambda pConnection: pConnection.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (vNow, dRow["session_id"])))
    return dRow

  def mDeleteSession(self, pToken: str) -> None:
    if pToken:
      self.vDatabase.mWrite(lambda pConnection: pConnection.execute("DELETE FROM sessions WHERE token_hash = ?", (fHashToken(pToken),)))

  # Access tokens (direct sign-in)

  def mCreateAccessToken(self, pUserId: int, pLabel: str, pDays: int, pCreatedBy: str) -> tuple[int, str]:
    # Returns (id, token). The token is shown once; only its hash is kept.
    dUser = self.mGetUser(pUserId)
    if dUser is None:
      raise ValueError("not_found")
    if dUser["role"] != "analyst":
      raise ValueError("token_needs_analyst")
    if not dUser["is_active"]:
      raise ValueError("account_disabled")
    if not 1 <= int(pDays) <= cMaximumTokenDays:
      raise ValueError("invalid_days")
    vToken = secrets.token_urlsafe(32)
    vNow = fNowStorage()
    vId = self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "INSERT INTO access_tokens (user_id, label, token_hash, token_hint, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      (int(pUserId), str(pLabel or "").strip()[:80], fHashToken(vToken), vToken[-4:], vNow, str(pCreatedBy)[:64], fStorageFromNow(int(pDays) * 86400))
    ).lastrowid)
    return vId, vToken

  def mListAccessTokens(self) -> list[dict]:
    ldTokens = self.vDatabase.mAll(
      "SELECT t.id, t.user_id, COALESCE(u.username, '') AS username, u.role, u.is_active, t.label, t.token_hint, t.created_at, t.created_by, "
      "t.expires_at, t.last_used_at, t.last_used_ip, t.revoked_at FROM access_tokens t LEFT JOIN users u ON u.id = t.user_id ORDER BY t.id DESC"
    )
    vNow = fNowStorage()
    for dToken in ldTokens:
      if dToken["revoked_at"]:
        dToken["state"] = "revoked"
      elif dToken["expires_at"] < vNow:
        dToken["state"] = "expired"
      elif dToken["role"] != "analyst" or not dToken["is_active"]:
        dToken["state"] = "unusable"
      else:
        dToken["state"] = "active"
    return ldTokens

  def mRevokeAccessToken(self, pTokenId: int) -> bool:
    return bool(self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "UPDATE access_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (fNowStorage(), int(pTokenId))
    ).rowcount))

  def mCheckAccessToken(self, pToken: str) -> tuple[dict | None, dict | None, str]:
    # (user, token, "") when it opens a session; (None, token or None,
    # reason) when not: token_invalid, token_revoked, token_expired,
    # account_disabled or token_needs_analyst.
    vToken = str(pToken or "").strip()
    if not 20 <= len(vToken) <= 200:
      return None, None, "token_invalid"
    dToken = self.vDatabase.mOne("SELECT * FROM access_tokens WHERE token_hash = ?", (fHashToken(vToken),))
    if dToken is None:
      return None, None, "token_invalid"
    if dToken["revoked_at"]:
      return None, dToken, "token_revoked"
    if dToken["expires_at"] < fNowStorage():
      return None, dToken, "token_expired"
    dUser = self.mGetUser(dToken["user_id"])
    if dUser is None or not dUser["is_active"]:
      return None, dToken, "account_disabled"
    if dUser["role"] != "analyst":
      return None, dToken, "token_needs_analyst"
    return dUser, dToken, ""

  def mMarkAccessTokenUsed(self, pTokenId: int, pIp: str) -> None:
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "UPDATE access_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?", (fNowStorage(), pIp, int(pTokenId))
    ))

  # Record of the sign-ins

  def mRecordLogin(self, pUsername: str, pMethod: str, pResult: str, pReason: str, pIp: str, pUserAgent: str, pTokenId: int | None = None) -> None:
    # pMethod: password, password_totp or token; pResult: ok or failed.
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "INSERT INTO logins (time, username, method, result, reason, ip, user_agent, token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      (fNowStorage(), str(pUsername or "")[:128], pMethod, pResult, str(pReason or "")[:64], pIp, str(pUserAgent or "")[:300], pTokenId)
    ))

  def mListLogins(self, pBefore: int | None, pLimit: int, pResult: str = "") -> list[dict]:
    lWhere = []
    lValues = []
    if pBefore:
      lWhere.append("id < ?")
      lValues.append(int(pBefore))
    if pResult in ("ok", "failed"):
      lWhere.append("result = ?")
      lValues.append(pResult)
    vWhere = (" WHERE " + " AND ".join(lWhere)) if lWhere else ""
    return self.vDatabase.mAll("SELECT * FROM logins" + vWhere + " ORDER BY id DESC LIMIT ?", (*lValues, int(pLimit)))

  def mDeleteOldLogins(self, pBefore: str) -> None:
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute("DELETE FROM logins WHERE time < ?", (pBefore,)))

  # Search audit

  def mAudit(self, pUsername: str, pIp: str, pKind: str, pQuery: str, pFrom: str, pTo: str, pResults: int | None, pTook: int | None) -> None:
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute(
      "INSERT INTO search_audit (time, username, ip, kind, query, range_from, range_to, results, took_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      (fNowStorage(), pUsername, pIp, pKind, str(pQuery or "")[:2000], pFrom, pTo, pResults, pTook)
    ))

  def mListAudit(self, pBefore: int | None, pLimit: int) -> list[dict]:
    if pBefore:
      return self.vDatabase.mAll("SELECT * FROM search_audit WHERE id < ? ORDER BY id DESC LIMIT ?", (int(pBefore), int(pLimit)))
    return self.vDatabase.mAll("SELECT * FROM search_audit ORDER BY id DESC LIMIT ?", (int(pLimit),))

  def mDeleteOldAudit(self, pBefore: str) -> None:
    self.vDatabase.mWrite(lambda pConnection: pConnection.execute("DELETE FROM search_audit WHERE time < ?", (pBefore,)))


def fCheckCsrf(pSession: dict, pRequest) -> bool:
  vSent = pRequest.headers.get("x-csrf-token", "")
  return bool(vSent) and hmac.compare_digest(vSent, pSession["csrf_token"])


def fIsSameOrigin(pRequest) -> bool:
  # Browser writes must come from the page's own origin. Without Origin the
  # Referer decides.
  vValue = pRequest.headers.get("origin") or pRequest.headers.get("referer")
  if not vValue:
    return False
  vParsed = urllib.parse.urlsplit(vValue)
  vHost = pRequest.headers.get("host", "").lower()
  return bool(vHost) and vParsed.netloc.lower() == vHost and vParsed.scheme == "https"
