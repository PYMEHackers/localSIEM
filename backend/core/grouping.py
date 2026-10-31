"""Grouping of detections into SOC alerts.

  - Group key: module, vhost, IP, category and severity, inside a window
    (10 minutes by default) that starts with the first detection.
  - First detection of a group: critical is sent at once; the other
    severities wait a short buffer (60 s) to gather the burst, and leave with
    the accumulated count.
  - Later detections inside the window create no new alert: they are stored
    and linked to the group.
  - When the window closes and the activity goes on, a new window opens with
    its own alert. A higher severity is another group, sent at once if it
    is critical.
  - external_id is deterministic: localsiem:<host>:<module>:<hash of the group
    key and its window start>. Sending it again is safe; the SOC drops
    duplicates.
"""

import datetime
import hashlib

from backend.core.timeutil import fFormatStorage, fNowStorage, fParseStorage, fStorageFromNow


def fGroupKey(pDetection: dict) -> str:
  return "|".join([
    str(pDetection.get("module") or ""), str(pDetection.get("vhost") or "").lower(),
    str(pDetection.get("ip") or ""), str(pDetection.get("category") or ""), str(pDetection.get("severity") or "")
  ])


def fExternalId(pHost: str, pModule: str, pGroupKey: str, pWindowStart: str) -> str:
  vDigest = hashlib.sha256((pGroupKey + "|" + pWindowStart).encode("utf-8")).hexdigest()[:20]
  vHost = "".join(vChar for vChar in str(pHost) if vChar.isalnum() or vChar in "-_.")[:60] or "host"
  vModule = "".join(vChar for vChar in str(pModule) if vChar.isalnum() or vChar in "-_")[:30] or "module"
  return f"localsiem:{vHost}:{vModule}:{vDigest}"


class Grouper:

  def __init__(self, pStorage, pSettings: dict):
    self.vStorage = pStorage
    self.mReload(pSettings)

  def mReload(self, pSettings: dict) -> None:
    self.vHost = pSettings["host"]
    self.vWindow = int(pSettings.get("group_window_seconds", 600))
    self.vBuffer = int(pSettings.get("group_buffer_seconds", 60))

  def mAdd(self, pDetection: dict) -> int:
    # pDetection: module, vhost, ip, category, severity, rule, type,
    # description, search, details, event_id, time (storage), uid.
    vGroupKey = fGroupKey(pDetection)
    vTime = pDetection.get("time") or fNowStorage()
    dGroup = self.vStorage.mFindOpenGroup(vGroupKey, vTime)
    if dGroup is not None:
      self.vStorage.mAddToGroup(dGroup["id"], pDetection.get("event_id"), vTime, pDetection.get("uid") or "")
      return dGroup["id"]
    vStart = fParseStorage(vTime) or datetime.datetime.now(datetime.UTC)
    vWindowEnd = fFormatStorage(vStart + datetime.timedelta(seconds=self.vWindow))
    vSendAt = fNowStorage() if pDetection.get("severity") == "critical" else fStorageFromNow(self.vBuffer)
    dNew = {
      "group_key": vGroupKey,
      "module": pDetection.get("module") or "",
      "vhost": (pDetection.get("vhost") or "").lower(),
      "ip": pDetection.get("ip") or "",
      "category": pDetection.get("category") or "",
      "severity": pDetection.get("severity") or "medium",
      "rule": pDetection.get("rule") or "localSIEM detection",
      "type": pDetection.get("type") or "other",
      "description": pDetection.get("description") or "",
      "window_start": vTime,
      "window_end": vWindowEnd,
      "first_seen": vTime,
      "last_seen": vTime,
      "count": 1,
      "send_at": vSendAt,
      "external_id": fExternalId(self.vHost, pDetection.get("module") or "", vGroupKey, vTime),
      "details": pDetection.get("details") or {},
      "search": pDetection.get("search") or "",
      "sample_uids": [pDetection["uid"]] if pDetection.get("uid") else [],
      "created": fNowStorage(),
      "event_id": pDetection.get("event_id")
    }
    return self.vStorage.mCreateGroup(dNew)
