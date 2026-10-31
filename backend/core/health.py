"""Health of localSIEM and anti-forensics signals.

These situations are also things nobody has resolved, so they go to the SOC
(module "localsiem", rule names starting with "localSIEM health: "). They are
grouped like any other detection, so they do not repeat:

  log truncated or gone outside a rotation (possible trace deletion)  high
  log replaced by another file outside a rotation                     high
  source no longer readable, or silent for long when it had data       medium
  more than 5 % of the lines of a source not parsed                    low
  little free disk, or retention trimmed for lack of space             medium

Module-specific signals (ModSecurity unloaded or Off, real client IP missing)
come from each module's mHealth.
"""

import collections
import shutil
import time

from backend.core.timeutil import fNowStorage

dNoticeSignals = {
  "truncated": ("high", "health-truncated", "localSIEM health: log truncated outside a rotation (possible trace deletion)"),
  "missing": ("high", "health-missing", "localSIEM health: log disappeared outside a rotation (possible trace deletion)"),
  "replaced": ("high", "health-replaced", "localSIEM health: log replaced outside a rotation (possible tampering)"),
  "unreadable": ("medium", "health-unreadable", "localSIEM health: log source not readable"),
  "rotated_lost": ("medium", "health-rotated-lost", "localSIEM health: log rotated while localSIEM was stopped, lines may be lost")
}
dDescriptions = {
  "truncated": "The file {path} became shorter ({previous} bytes read before, {size} now) and no rotated copy explains it. Someone may have emptied the log to hide activity. Check who had access to the server at that time.",
  "missing": "The file {path} disappeared and was not created again. If nobody removed it on purpose, someone may have deleted the log to hide activity.",
  "replaced": "The file {path} was replaced by another file that already had {size} bytes, while the old one is gone. A rotation creates an empty file; an edited copy put in its place looks like this.",
  "unreadable": "localSIEM cannot read {path}. Check its permissions (for example after a log rotation): the localsiem user must be able to read it.",
  "rotated_lost": "The file {path} was rotated while localSIEM was stopped and the old file is no longer there: the lines written between the stop and the rotation were not read."
}


def fHealthDetection(pCheck: str, pSeverity: str, pRule: str, pDescription: str, pTarget: str, pDetails: dict) -> dict:
  return {
    "module": "localsiem",
    "vhost": pTarget,
    "ip": "",
    "category": pCheck,
    "severity": pSeverity,
    "rule": pRule,
    "type": "other",
    "description": pDescription,
    "search": "module:localsiem",
    "details": pDetails,
    "time": fNowStorage(),
    "uid": ""
  }


def fNoticeDetection(pNotice: dict) -> dict | None:
  vKind = pNotice.get("kind")
  if vKind not in dNoticeSignals:
    return None
  vSeverity, vCheck, vRule = dNoticeSignals[vKind]
  dValues = {"path": pNotice.get("path", ""), "previous": pNotice.get("previous", ""), "size": pNotice.get("size", "")}
  vDescription = dDescriptions[vKind].format(**dValues)
  dDetails = {"check": vCheck, "path": pNotice.get("path", "")}
  for vKey in ("previous", "size", "error", "method"):
    if pNotice.get(vKey) not in (None, ""):
      dDetails[vKey] = pNotice[vKey]
  return fHealthDetection(vCheck, vSeverity, vRule, vDescription, pNotice.get("path", ""), dDetails)


class SourceStatistics:
  # Lines and unparsed lines per source, per minute, for the last hour.

  def __init__(self):
    self.dMinutes = collections.defaultdict(lambda: collections.deque(maxlen=60))
    self.dLastData = {}
    self.dTotals = collections.defaultdict(lambda: {"lines": 0, "unparsed": 0, "partial": 0})

  def mAdd(self, pSourceKey: str, pStatus: str) -> None:
    vMinute = int(time.time() // 60)
    vDeque = self.dMinutes[pSourceKey]
    if not vDeque or vDeque[-1][0] != vMinute:
      vDeque.append([vMinute, 0, 0])
    vDeque[-1][1] += 1
    if pStatus == "unparsed":
      vDeque[-1][2] += 1
    self.dLastData[pSourceKey] = time.time()
    dTotal = self.dTotals[pSourceKey]
    dTotal["lines"] += 1
    if pStatus in ("unparsed", "partial"):
      dTotal[pStatus] += 1

  def mLastHour(self, pSourceKey: str) -> tuple[int, int]:
    vLimit = int(time.time() // 60) - 60
    vLines = 0
    vUnparsed = 0
    for vMinute, vCount, vBad in self.dMinutes.get(pSourceKey, []):
      if vMinute > vLimit:
        vLines += vCount
        vUnparsed += vBad
    return vLines, vUnparsed


class HealthMonitor:

  def __init__(self, pCollector):
    self.vCollector = pCollector
    self.vStatistics = SourceStatistics()
    self.dSilentReported = {}

  def mCheckSources(self, pSources: dict) -> list[dict]:
    # pSources: key -> {"source": dict, "tailer": FileTailer}
    dHealth = self.vCollector.dSettings.get("health", {})
    vPercent = float(dHealth.get("unparsed_percent", 5))
    vMinimum = int(dHealth.get("unparsed_minimum_lines", 100))
    vSilentSeconds = float(dHealth.get("silent_hours", 24)) * 3600
    ldDetections = []
    vNow = time.time()
    for vKey, dEntry in pSources.items():
      vLines, vUnparsed = self.vStatistics.mLastHour(vKey)
      if vLines >= vMinimum and vUnparsed * 100.0 / vLines > vPercent:
        ldDetections.append(fHealthDetection(
          "health-unparsed", "low", "localSIEM health: many log lines could not be parsed",
          f"{vUnparsed} of the last {vLines} lines of {dEntry['source']['path']} could not be parsed (more than {vPercent:g} %). The log format may have changed: check the localSIEM doctor in the Sources tab.",
          dEntry["source"]["path"], {"check": "health-unparsed", "path": dEntry["source"]["path"], "lines": vLines, "unparsed": vUnparsed}
        ))
      # Only access logs are expected to have constant traffic.
      if dEntry["source"].get("kind") != "access":
        continue
      vLast = self.vStatistics.dLastData.get(vKey) or (dEntry["tailer"].vLastData or None)
      if vLast and vNow - vLast > vSilentSeconds:
        if self.dSilentReported.get(vKey) != int(vLast):
          self.dSilentReported[vKey] = int(vLast)
          ldDetections.append(fHealthDetection(
            "health-silent", "medium", "localSIEM health: log source silent for a long time",
            f"{dEntry['source']['path']} has had no new lines for more than {vSilentSeconds / 3600:g} hours although it had data before. Check that the web server still writes to it.",
            dEntry["source"]["path"], {"check": "health-silent", "path": dEntry["source"]["path"]}
          ))
    return ldDetections

  def mDiskUsage(self) -> dict:
    from backend.core.config import cDatabasePath
    try:
      vUsage = shutil.disk_usage(cDatabasePath)
    except OSError:
      return {"total": 0, "free": 0}
    return {"total": vUsage.total, "free": vUsage.free}

  def mDiskLevel(self) -> str:
    # normal, low (no bulky detail) or critical (only alerted events).
    dSettings = self.vCollector.dSettings
    dUsage = self.mDiskUsage()
    if not dUsage["total"]:
      return "normal"
    vFreePercent = dUsage["free"] * 100.0 / dUsage["total"]
    if vFreePercent < float(dSettings["critical_disk_free_percent"]) or dUsage["free"] < int(dSettings["critical_disk_free_bytes"]):
      return "critical"
    if vFreePercent < float(dSettings["low_disk_free_percent"]) or dUsage["free"] < int(dSettings["low_disk_free_bytes"]):
      return "low"
    return "normal"

  def mMaxDatabaseBytes(self) -> int:
    dSettings = self.vCollector.dSettings
    if int(dSettings.get("max_disk_bytes") or 0) > 0:
      return int(dSettings["max_disk_bytes"])
    dUsage = self.mDiskUsage()
    vPercent = int(dUsage["total"] * float(dSettings.get("max_disk_percent", 15)) / 100.0) if dUsage["total"] else 0
    vCap = int(dSettings.get("max_disk_cap_bytes", 10 * 1024 ** 3))
    return min(vPercent, vCap) if vPercent else vCap


def fDiskDetection(pLevel: str, pFree: int, pTotal: int, pTrimmed: bool) -> dict:
  if pTrimmed:
    vRule = "localSIEM health: retention trimmed for lack of space"
    vDescription = "localSIEM reached its maximum disk size and deleted the oldest events before their retention period. Raise the maximum disk size in Settings or free space on the server."
  else:
    vRule = "localSIEM health: little free disk space"
    vDescription = (
      f"Only {pFree // (1024 * 1024)} MB of {pTotal // (1024 * 1024)} MB are free on the disk of localSIEM. "
      + ("localSIEM now stores only the events that take part in an alert." if pLevel == "critical" else "localSIEM no longer stores the bulky detail (audit bodies and headers) of new events.")
    )
  return fHealthDetection("health-disk", "medium", vRule, vDescription, "disk", {"check": "health-disk", "free_bytes": pFree, "total_bytes": pTotal, "level": pLevel})
