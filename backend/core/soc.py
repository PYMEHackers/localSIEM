"""Delivery of alerts to the SOC, and the heartbeat.

  POST <soc_url>/api/ingest/generic     {"alerts": [GenericAlert, ...]}
  POST <soc_url>/api/ingest/heartbeat   no body, every 5 minutes
  Authorization: Bearer <token>

  - Persistent queue in SQLite: no alert is lost to a restart or a network
    cut. Batches of up to 100 alerts and 1 MiB.
  - Retries with exponential backoff and some randomness, up to a maximum
    (5 minutes). Delivery is at least once; external_id makes it safe.
  - 401: the queue is kept, retried and shown in the panel.
    413: the batch is split.
    422: the SOC rejects the whole request when one alert is invalid, so the
         batch is split in halves until the invalid alert is alone; that one
         is set aside and the queue goes on.
    507: the client has used every alert number: sending stops, the queue is
         kept and the panel warns; it is tried again every hour.
  - TLS is always verified. The token is never logged.
  - The SOC is optional. Without one (no token or no URL) or with the
    sending turned off, the alerts stay in localSIEM as not sent («local»)
    and are never sent later, also the ones that were waiting in the queue:
    the SOC only gets the alerts that come after it is configured.
"""

import json
import random
import ssl
import threading
import time
import urllib.error
import urllib.request

from backend.core.config import cVersion, fReadSocToken
from backend.core.masking import fTrim
from backend.core.timeutil import fNowStorage, fStorageFromNow

cMaxAlertsPerRequest = 100
cMaxBodyBytes = 1024 * 1024
cMaxDetailKeys = 200
cMaxDetailValueLength = 5000


def fSocConfigured(pSettings: dict) -> bool:
  # A SOC to send to: its URL, its token and the sending turned on.
  return bool(pSettings.get("soc_enabled", True) and pSettings.get("soc_url") and fReadSocToken())


def fFlattenCount(pValue, pPrefix: str = "") -> int:
  # Number of keys the SOC will create (nested objects become dotted keys).
  if isinstance(pValue, dict):
    return sum(fFlattenCount(vItem, f"{pPrefix}.{vKey}") for vKey, vItem in pValue.items()) or 1
  if isinstance(pValue, list) and pValue and all(isinstance(vItem, (dict, list)) for vItem in pValue):
    return sum(fFlattenCount(vItem, pPrefix) for vItem in pValue)
  return 1


def fLimitDetails(pValue, pDepth: int = 0):
  if isinstance(pValue, dict):
    return {str(vKey)[:120]: fLimitDetails(vItem, pDepth + 1) for vKey, vItem in pValue.items() if vItem is not None}
  if isinstance(pValue, list):
    return [fLimitDetails(vItem, pDepth + 1) for vItem in pValue[:50]]
  if isinstance(pValue, str):
    return fTrim(pValue, cMaxDetailValueLength - 10)
  return pValue


def fBuildAlert(pGroup: dict, pContext: dict, pHost: str) -> dict:
  dDetails = dict(pGroup.get("details") or {})
  dDetails["localsiem"] = {
    "host": pHost, "module": pGroup["module"], "version": cVersion, "search": pGroup.get("search") or "",
    "group_id": pGroup["id"]
  }
  dDetails["group"] = {
    "count": pGroup["count"],
    "first_seen": pGroup["first_seen"],
    "last_seen": pGroup["last_seen"],
    "sample_unique_ids": pGroup.get("sample_uids") or []
  }
  if pContext:
    dDetails["context"] = pContext
  dDetails = fLimitDetails(dDetails)
  if fFlattenCount(dDetails) > cMaxDetailKeys:
    for vKey in ("modsecurity", "record"):
      if isinstance(dDetails.get(vKey), dict):
        dDetails[vKey] = {vName: vValue for vName, vValue in list(dDetails[vKey].items())[:20]}
  return {
    "rule": fTrim(pGroup["rule"], 299),
    "severity": pGroup["severity"],
    "type": pGroup["type"],
    "description": fTrim(pGroup.get("description") or "", 9990),
    "external_id": pGroup["external_id"][:200],
    # The SOC records the alert: its times go in the storage format.
    "event_time": pGroup["first_seen"],
    "details": dDetails
  }


class SocError(Exception):

  def __init__(self, pStatus: int, pCode: str, pBody: str = ""):
    super().__init__(f"HTTP {pStatus} {pCode}")
    self.vStatus = pStatus
    self.vCode = pCode
    self.vBody = pBody


class SocClient:

  def __init__(self, pUrl: str, pToken: str, pCaFile: str = "", pTimeout: float = 20):
    self.vUrl = pUrl.rstrip("/")
    self.vToken = pToken
    self.vTimeout = pTimeout
    self.vContext = ssl.create_default_context()
    if pCaFile:
      self.vContext.load_verify_locations(cafile=pCaFile)

  def mPost(self, pPath: str, pBody: bytes | None) -> dict:
    vRequest = urllib.request.Request(self.vUrl + pPath, data=pBody if pBody is not None else b"", method="POST")
    vRequest.add_header("Authorization", "Bearer " + self.vToken)
    vRequest.add_header("User-Agent", "localSIEM/" + cVersion)
    if pBody is not None:
      vRequest.add_header("Content-Type", "application/json")
    try:
      with urllib.request.urlopen(vRequest, timeout=self.vTimeout, context=self.vContext) as vResponse:
        vText = vResponse.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
        try:
          return json.loads(vText) if vText else {}
        except ValueError:
          return {}
    except urllib.error.HTTPError as vError:
      vText = ""
      try:
        vText = vError.read(65536).decode("utf-8", errors="replace")
      except OSError:
        pass
      vCode = ""
      try:
        dBody = json.loads(vText)
        vDetail = dBody.get("detail")
        vCode = vDetail if isinstance(vDetail, str) else json.dumps(vDetail)[:300]
      except (ValueError, AttributeError):
        vCode = vText[:300]
      raise SocError(vError.code, vCode, vText) from None

  def mSendAlerts(self, pAlerts: list[dict]) -> dict:
    vBody = json.dumps({"alerts": pAlerts}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return self.mPost("/api/ingest/generic", vBody)

  def mHeartbeat(self) -> dict:
    return self.mPost("/api/ingest/heartbeat", None)


class SocSender(threading.Thread):

  def __init__(self, pCollector):
    super().__init__(name="soc-sender", daemon=True)
    self.vCollector = pCollector
    self.vStop = threading.Event()
    self.vWake = threading.Event()
    self.vBackoff = 0.0
    self.vNextSend = 0.0
    self.vNextHeartbeat = 0.0
    self.vExhaustedUntil = 0.0
    self.vState = "starting"

  def mStop(self) -> None:
    self.vStop.set()
    self.vWake.set()

  def mWakeUp(self) -> None:
    self.vNextSend = 0.0
    self.vExhaustedUntil = 0.0
    self.vWake.set()

  def mHeartbeatNow(self) -> None:
    self.vNextHeartbeat = 0.0
    self.vWake.set()

  def mClient(self) -> SocClient | None:
    dSettings = self.vCollector.dSettings
    if not fSocConfigured(dSettings):
      return None
    return SocClient(dSettings["soc_url"], fReadSocToken(), dSettings.get("soc_ca_file", ""))

  def mSetState(self, pState: str, pError: str = "") -> None:
    self.vState = pState
    vStorage = self.vCollector.vStorage
    dCurrent = vStorage.mGetState("soc.status", {}) or {}
    dCurrent.update({"state": pState, "error": pError[:500], "time": fNowStorage()})
    if pState in ("ok", "idle"):
      dCurrent["last_success"] = fNowStorage()
    vStorage.mSetState("soc.status", dCurrent)

  def mNextBackoff(self) -> float:
    vMaximum = float(self.vCollector.dSettings.get("soc_max_backoff_seconds", 300))
    self.vBackoff = min(vMaximum, max(5.0, self.vBackoff * 2 or 5.0))
    return self.vBackoff * (0.75 + random.random() * 0.5)

  def run(self) -> None:
    while not self.vStop.is_set():
      try:
        self.mCycle()
      except Exception as vError:
        self.vCollector.mLog("SOC sender error: " + type(vError).__name__ + ": " + str(vError))
        self.vNextSend = time.time() + self.mNextBackoff()
      self.vWake.wait(2.0)
      self.vWake.clear()

  def mCycle(self) -> None:
    vNow = time.time()
    vClient = self.mClient()
    if vClient is None:
      if self.vState != "not_configured":
        self.mSetState("not_configured")
      # Without a SOC nothing waits for one: what was in the queue stays in
      # localSIEM as not sent.
      vSkipped = self.vCollector.vStorage.mSkipPending("soc_not_configured")
      if vSkipped:
        self.vCollector.mLog(f"SOC not configured: {vSkipped} alerts kept in localSIEM, not sent.")
      return
    if vNow >= self.vNextHeartbeat:
      self.mSendHeartbeat(vClient)
    if vNow < self.vNextSend or vNow < self.vExhaustedUntil:
      return
    vStorage = self.vCollector.vStorage
    ldBatch = vStorage.mGetQueueBatch(fNowStorage(), cMaxAlertsPerRequest, cMaxBodyBytes - 64)
    if not ldBatch:
      if self.vState not in ("ok", "idle", "exhausted", "token_invalid"):
        self.mSetState("idle")
      return
    self.mDeliver(vClient, ldBatch)

  def mSendHeartbeat(self, pClient: SocClient) -> None:
    vInterval = float(self.vCollector.dSettings.get("heartbeat_seconds", 300))
    dResult = {"time": fNowStorage()}
    try:
      pClient.mHeartbeat()
      dResult.update({"ok": True, "status": 200})
      self.vNextHeartbeat = time.time() + vInterval
    except SocError as vError:
      dResult.update({"ok": False, "status": vError.vStatus, "error": vError.vCode})
      self.vNextHeartbeat = time.time() + (vInterval if vError.vStatus != 401 else 60)
      if vError.vStatus == 401:
        self.mSetState("token_invalid", "ingest_token_invalid")
    except (OSError, ssl.SSLError, ValueError) as vError:
      dResult.update({"ok": False, "status": 0, "error": type(vError).__name__ + ": " + str(vError)[:300]})
      self.vNextHeartbeat = time.time() + 60
    vStorage = self.vCollector.vStorage
    dPrevious = vStorage.mGetState("soc.heartbeat", {}) or {}
    if dResult.get("ok"):
      dResult["last_ok"] = dResult["time"]
    elif dPrevious.get("last_ok"):
      dResult["last_ok"] = dPrevious["last_ok"]
    vStorage.mSetState("soc.heartbeat", dResult)

  def mDeliver(self, pClient: SocClient, pBatch: list[dict]) -> None:
    # Sends pBatch; splits it on 413 and 422 until the faulty alert is alone.
    vStorage = self.vCollector.vStorage
    lPending = [pBatch]
    while lPending:
      ldPart = lPending.pop(0)
      lAlerts = [json.loads(dItem["payload"]) for dItem in ldPart]
      try:
        dAnswer = pClient.mSendAlerts(lAlerts)
      except SocError as vError:
        if vError.vStatus in (413, 422):
          if len(ldPart) > 1:
            vHalf = len(ldPart) // 2
            lPending[0:0] = [ldPart[:vHalf], ldPart[vHalf:]]
            continue
          vStorage.mMarkQueueRejected(ldPart[0]["id"], f"HTTP {vError.vStatus} {vError.vCode}", fNowStorage())
          self.vCollector.mLog(f"SOC rejected alert of group {ldPart[0]['group_id']}: HTTP {vError.vStatus} {vError.vCode}")
          continue
        lIds = [dItem["id"] for dPartItem in [ldPart] + lPending for dItem in dPartItem]
        if vError.vStatus == 507:
          vRetry = float(self.vCollector.dSettings.get("soc_exhausted_retry_seconds", 3600))
          self.vExhaustedUntil = time.time() + vRetry
          vStorage.mDeferQueue(lIds, fStorageFromNow(vRetry), f"HTTP 507 {vError.vCode}")
          self.mSetState("exhausted", "alert_numbers_exhausted")
          return
        vDelay = self.mNextBackoff()
        vStorage.mDeferQueue(lIds, fStorageFromNow(vDelay), f"HTTP {vError.vStatus} {vError.vCode}")
        self.vNextSend = time.time() + vDelay
        self.mSetState("token_invalid" if vError.vStatus == 401 else "error", f"HTTP {vError.vStatus} {vError.vCode}")
        return
      except (OSError, ssl.SSLError, ValueError) as vError:
        lIds = [dItem["id"] for dPartItem in [ldPart] + lPending for dItem in dPartItem]
        vDelay = self.mNextBackoff()
        vMessage = type(vError).__name__ + ": " + str(vError)[:300]
        vStorage.mDeferQueue(lIds, fStorageFromNow(vDelay), vMessage)
        self.vNextSend = time.time() + vDelay
        self.mSetState("unreachable", vMessage)
        return
      ldResults = dAnswer.get("alerts") if isinstance(dAnswer, dict) else None
      lResults = []
      for vIndex, dItem in enumerate(ldPart):
        vCode = None
        if isinstance(ldResults, list) and vIndex < len(ldResults) and isinstance(ldResults[vIndex], dict):
          vCode = ldResults[vIndex].get("alert_id")
        lResults.append((dItem["id"], vCode))
      vStorage.mMarkQueueSent(lResults, fNowStorage())
      self.vBackoff = 0.0
      self.mSetState("ok")
