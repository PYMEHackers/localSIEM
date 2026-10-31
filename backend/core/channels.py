"""Channels: the messages localSIEM sends to its administrators, besides the
alerts it delivers to the SOC.

  - Settings, block channels of settings.json: enabled (all the channels),
    min_severity (the alerts of that severity or above are sent), language
    (of the messages: en-GB, en-US, es-AR or es-ES) and one block per
    channel.
  - Telegram (channels.telegram: enabled and chat_id; the token of the bot
    in config/telegram-bot-token, mode 600): POST
    https://api.telegram.org/bot<token>/sendMessage, plain text.
  - Best effort: the messages wait in memory (at most cMaxPending per
    channel; beyond it the oldest one is dropped and counted), one per
    second at most, with retries (the retry_after of Telegram on 429,
    growing waits on network errors) up to cMaxAttempts. An answer that will
    not change by retrying (wrong token, unknown chat, bot blocked) drops the
    message at once. A restart loses the messages waiting: the SOC queue is
    the one that never loses an alert.
  - The token is never logged nor shown whole: the URL that carries it is
    never written anywhere, and an error that could contain it is cleaned.
  - State for the web: channels.status in the events database (written by
    the collector only).
"""

import collections
import json
import re
import threading
import time
import urllib.error
import urllib.request

from backend.core.config import cVersion, fReadTelegramToken
from backend.core.masking import fTrim
from backend.core.timeutil import fNowStorage, fStorageToDisplay

lSeverities = ["low", "medium", "high", "critical"]
lLanguages = ["en-GB", "en-US", "es-AR", "es-ES"]
# Every channel localSIEM can send through (one section each in the web).
lChannels = ["telegram"]
cTelegramApi = "https://api.telegram.org"
cMaxPending = 200
cMaxAttempts = 5
cMinimumIntervalSeconds = 1.0
cMaxBackoffSeconds = 300
cPublishSeconds = 30
# Telegram accepts up to 4096 characters in a message.
cMaxTextLength = 4000
cMaxDescriptionLength = 1000
# <id of the bot>:<secret>, as @BotFather gives it.
cTokenRegex = re.compile(r"^[0-9]{3,20}:[A-Za-z0-9_-]{20,100}$")
# The numeric id of a person, a group (-...) or a channel (-100...), or the
# @username of a public channel or group.
cChatIdRegex = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$")
# Telegram answers that will not change by retrying the same message.
lPermanentStatuses = [400, 401, 403, 404]
dSeverityMarks = {"low": "🟦", "medium": "🟨", "high": "🟧", "critical": "🟥"}

dEnglish = {
  "severity": {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"},
  "module": "Module",
  "events": "Events",
  "first_seen": "First seen",
  "last_seen": "Last seen",
  "search": "Search",
  "test": "Test message from localSIEM on {host}: the Telegram channel works. The alerts of severity {severity} or above will arrive here."
}
dSpanishSpain = {
  "severity": {"low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica"},
  "module": "Módulo",
  "events": "Eventos",
  "first_seen": "Primera vez",
  "last_seen": "Última vez",
  "search": "Búsqueda",
  "test": "Mensaje de prueba de localSIEM en {host}: el canal de Telegram funciona. Aquí llegarán las alertas de severidad {severity} o superior."
}
dSpanishArgentina = {
  "severity": {"low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica"},
  "module": "Módulo",
  "events": "Eventos",
  "first_seen": "Primera vez",
  "last_seen": "Última vez",
  "search": "Búsqueda",
  "test": "Mensaje de prueba de localSIEM en {host}: el canal de Telegram funciona. Acá van a llegar las alertas de severidad {severity} o superior."
}
dTexts = {"en-GB": dEnglish, "en-US": dEnglish, "es-AR": dSpanishArgentina, "es-ES": dSpanishSpain}


def fChannelSettings(pSettings: dict) -> dict:
  # The block channels of the settings, with every value valid.
  dChannels = pSettings.get("channels") or {}
  dTelegram = dChannels.get("telegram") or {}
  return {
    "enabled": bool(dChannels.get("enabled", True)),
    "min_severity": dChannels.get("min_severity") if dChannels.get("min_severity") in lSeverities else "high",
    "language": dChannels.get("language") if dChannels.get("language") in lLanguages else "en-US",
    "telegram": {"enabled": bool(dTelegram.get("enabled", False)), "chat_id": str(dTelegram.get("chat_id") or "").strip()}
  }


def fSeverityReached(pSeverity: str, pMinimum: str) -> bool:
  if pSeverity not in lSeverities:
    return False
  return lSeverities.index(pSeverity) >= lSeverities.index(pMinimum if pMinimum in lSeverities else "high")


def fBotId(pToken: str) -> str:
  # The id of the bot is the part of the token before the colon (not secret).
  return pToken.partition(":")[0] if cTokenRegex.match(pToken or "") else ""


def fBuildMessage(pGroup: dict, pHost: str, pLanguage: str) -> str:
  # Plain text (no parse_mode: nothing to escape). Times in the display
  # format, UTC.
  dText = dTexts.get(pLanguage, dEnglish)
  vSeverity = str(pGroup.get("severity") or "")
  lLines = [
    f"{dSeverityMarks.get(vSeverity, '⬜')} localSIEM · {pHost}",
    f"{dText['severity'].get(vSeverity, vSeverity)}: {pGroup.get('rule') or ''}"
  ]
  vDescription = fTrim(str(pGroup.get("description") or ""), cMaxDescriptionLength)
  if vDescription:
    lLines.append(vDescription)
  lLines.append(f"{dText['module']}: {pGroup.get('module') or ''} · {dText['events']}: {pGroup.get('count') or 0}")
  lLines.append(f"{dText['first_seen']}: {fStorageToDisplay(pGroup.get('first_seen'))}")
  if pGroup.get("last_seen") and pGroup.get("last_seen") != pGroup.get("first_seen"):
    lLines.append(f"{dText['last_seen']}: {fStorageToDisplay(pGroup.get('last_seen'))}")
  if pGroup.get("search"):
    lLines.append(f"{dText['search']}: {pGroup['search']}")
  return "\n".join(lLines)[:cMaxTextLength]


def fTestMessage(pHost: str, pLanguage: str, pMinimum: str) -> str:
  dText = dTexts.get(pLanguage, dEnglish)
  return dText["test"].format(host=pHost, severity=dText["severity"].get(pMinimum, pMinimum))


class TelegramError(Exception):

  def __init__(self, pStatus: int, pDescription: str, pRetryAfter: float = 0.0):
    super().__init__(f"HTTP {pStatus} {pDescription}")
    self.vStatus = pStatus
    self.vDescription = pDescription
    self.vRetryAfter = pRetryAfter


class TelegramClient:

  def __init__(self, pToken: str, pTimeout: float = 20):
    if not cTokenRegex.match(pToken or ""):
      raise TelegramError(0, "invalid_bot_token")
    self.vToken = pToken
    self.vTimeout = pTimeout

  def mClean(self, pText: str) -> str:
    # An error never carries the token.
    return str(pText).replace(self.vToken, "***")[:300]

  def mCall(self, pMethod: str, pBody: dict) -> dict:
    vRequest = urllib.request.Request(
      f"{cTelegramApi}/bot{self.vToken}/{pMethod}", data=json.dumps(pBody, ensure_ascii=False).encode("utf-8"), method="POST"
    )
    vRequest.add_header("Content-Type", "application/json")
    vRequest.add_header("User-Agent", "localSIEM/" + cVersion)
    try:
      with urllib.request.urlopen(vRequest, timeout=self.vTimeout) as vResponse:
        dAnswer = json.loads(vResponse.read(1024 * 1024).decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as vError:
      dAnswer = {}
      try:
        dAnswer = json.loads(vError.read(65536).decode("utf-8", errors="replace") or "{}")
      except (OSError, ValueError):
        pass
      dParameters = dAnswer.get("parameters") if isinstance(dAnswer, dict) and isinstance(dAnswer.get("parameters"), dict) else {}
      vDescription = dAnswer.get("description") if isinstance(dAnswer, dict) else ""
      raise TelegramError(vError.code, self.mClean(vDescription or f"HTTP {vError.code}"), float(dParameters.get("retry_after") or 0)) from None
    except (urllib.error.URLError, OSError, ValueError) as vError:
      raise TelegramError(0, self.mClean(type(vError).__name__ + ": " + str(getattr(vError, "reason", None) or vError))) from None
    if not isinstance(dAnswer, dict) or not dAnswer.get("ok"):
      raise TelegramError(200, self.mClean(dAnswer.get("description") if isinstance(dAnswer, dict) else "invalid_answer"))
    return dAnswer.get("result") or {}

  def mGetMe(self) -> dict:
    return self.mCall("getMe", {})

  def mSendMessage(self, pChatId: str, pText: str) -> dict:
    return self.mCall("sendMessage", {"chat_id": pChatId, "text": pText[:cMaxTextLength], "disable_web_page_preview": True})


class ChannelSender(threading.Thread):

  def __init__(self, pCollector):
    super().__init__(name="channel-sender", daemon=True)
    self.vCollector = pCollector
    self.vStop = threading.Event()
    self.vWake = threading.Event()
    self.vLock = threading.Lock()
    self.dPending = {vName: collections.deque() for vName in lChannels}
    self.dStatus = {vName: {"state": "off", "sent": 0, "failed": 0, "dropped": 0, "last_sent": None, "last_error": "", "last_error_time": None} for vName in lChannels}
    self.vLastSend = 0.0
    self.vLastPublish = 0.0
    self.vChanged = True

  def mStop(self) -> None:
    self.vStop.set()
    self.vWake.set()

  def mConfigured(self, pName: str, pSettings: dict) -> bool:
    # On (all the channels and this one) and with what it needs to send.
    if not pSettings["enabled"] or not pSettings[pName]["enabled"]:
      return False
    if pName == "telegram":
      return bool(cChatIdRegex.match(pSettings["telegram"]["chat_id"])) and bool(cTokenRegex.match(fReadTelegramToken()))
    return False

  def mNotify(self, pGroup: dict) -> None:
    # The collector calls it for every alert it queues for the SOC.
    dSettings = fChannelSettings(self.vCollector.dSettings)
    if not dSettings["enabled"] or not fSeverityReached(str(pGroup.get("severity") or ""), dSettings["min_severity"]):
      return
    vText = fBuildMessage(pGroup, self.vCollector.dSettings.get("host", ""), dSettings["language"])
    vQueued = False
    for vName in lChannels:
      if not self.mConfigured(vName, dSettings):
        continue
      with self.vLock:
        dQueue = self.dPending[vName]
        if len(dQueue) >= cMaxPending:
          dQueue.popleft()
          self.dStatus[vName]["dropped"] += 1
        dQueue.append({"text": vText, "attempts": 0, "next": 0.0})
        self.vChanged = True
      vQueued = True
    if vQueued:
      self.vWake.set()

  def mLoadStatus(self) -> None:
    # The counters and the last message and error survive a restart.
    dStored = self.vCollector.vStorage.mGetState("channels.status", {}) or {}
    for vName in lChannels:
      dChannel = dStored.get(vName) if isinstance(dStored.get(vName), dict) else {}
      for vKey in ("sent", "failed", "dropped"):
        if isinstance(dChannel.get(vKey), int):
          self.dStatus[vName][vKey] = dChannel[vKey]
      for vKey in ("last_sent", "last_error", "last_error_time"):
        if dChannel.get(vKey):
          self.dStatus[vName][vKey] = dChannel[vKey]

  def mPublish(self) -> None:
    with self.vLock:
      dState = {"time": fNowStorage()}
      for vName in lChannels:
        dState[vName] = dict(self.dStatus[vName], pending=len(self.dPending[vName]))
      self.vChanged = False
    self.vLastPublish = time.time()
    self.vCollector.vStorage.mSetState("channels.status", dState)

  def run(self) -> None:
    try:
      self.mLoadStatus()
    except Exception as vError:
      self.vCollector.mLog("Channel state not loaded: " + type(vError).__name__ + ": " + str(vError))
    while not self.vStop.is_set():
      try:
        self.mCycle()
      except Exception as vError:
        self.vCollector.mLog("Channel sender error: " + type(vError).__name__ + ": " + str(vError))
      self.vWake.wait(1.0)
      self.vWake.clear()

  def mCycle(self) -> None:
    dSettings = fChannelSettings(self.vCollector.dSettings)
    for vName in lChannels:
      vConfigured = self.mConfigured(vName, dSettings)
      with self.vLock:
        dStatus = self.dStatus[vName]
        dQueue = self.dPending[vName]
        if not vConfigured:
          # Turned off or left without token or chat: what was waiting is not sent.
          if dQueue:
            dStatus["dropped"] += len(dQueue)
            dQueue.clear()
            self.vChanged = True
          vState = "off" if not dSettings["enabled"] or not dSettings[vName]["enabled"] else "not_configured"
          if dStatus["state"] != vState:
            dStatus["state"] = vState
            self.vChanged = True
          continue
        if dStatus["state"] in ("off", "not_configured"):
          dStatus["state"] = "ok"
          self.vChanged = True
        dItem = dQueue[0] if dQueue else None
      vNow = time.time()
      if dItem is None or vNow < dItem["next"] or vNow - self.vLastSend < cMinimumIntervalSeconds:
        continue
      self.mDeliver(vName, dSettings, dItem)
    if self.vChanged or time.time() - self.vLastPublish >= cPublishSeconds:
      self.mPublish()

  def mDeliver(self, pName: str, pSettings: dict, pItem: dict) -> None:
    self.vLastSend = time.time()
    try:
      if pName == "telegram":
        TelegramClient(fReadTelegramToken()).mSendMessage(pSettings["telegram"]["chat_id"], pItem["text"])
    except TelegramError as vError:
      with self.vLock:
        dStatus = self.dStatus[pName]
        pItem["attempts"] += 1
        vGiveUp = vError.vStatus in lPermanentStatuses or pItem["attempts"] >= cMaxAttempts
        if vGiveUp:
          if self.dPending[pName] and self.dPending[pName][0] is pItem:
            self.dPending[pName].popleft()
          dStatus["failed"] += 1
        else:
          vWait = vError.vRetryAfter if vError.vRetryAfter > 0 else min(cMaxBackoffSeconds, 5 * 2 ** pItem["attempts"])
          pItem["next"] = time.time() + vWait
        dStatus.update({"state": "error", "last_error": vError.vDescription, "last_error_time": fNowStorage()})
        self.vChanged = True
      self.vCollector.mLog(f"Channel {pName}: message not sent (HTTP {vError.vStatus} {vError.vDescription})" + (", dropped." if vGiveUp else ", will retry."))
      return
    with self.vLock:
      if self.dPending[pName] and self.dPending[pName][0] is pItem:
        self.dPending[pName].popleft()
      self.dStatus[pName].update({"state": "ok", "sent": self.dStatus[pName]["sent"] + 1, "last_sent": fNowStorage()})
      self.vChanged = True
