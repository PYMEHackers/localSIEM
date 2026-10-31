#!/usr/bin/env -S PYTHONDONTWRITEBYTECODE=1 python3

"""localSIEM collector (service localsiem).

Reads the sources of every module, normalises, correlates, applies the
rules, stores the events, groups the detections and delivers the alerts to
the SOC with its heartbeat, and sends the ones of the chosen severity through
the channels (Telegram). It is the only process that writes to the events
database. If the web stops, collecting and alerting go on.

Usage: ./backend/collector.py [--from-start] [--once]
  --from-start   read the files from their beginning the first time they are
                 seen (default: from their end, so old history is never
                 alerted: neither on the first run nor for the files of a
                 module installed or turned on later, nor for a file that
                 could not be read at first; only a file that appears while
                 its module is followed, such as a new vhost, is read from
                 its beginning when it is small)
  --once         read what is there, evaluate it and exit (tests, imports)
"""

import sys

if sys.version_info < (3, 13):
  raise SystemExit("Python 3.13 or newer is required.")

import fcntl
import json
import os
import signal
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.channels import ChannelSender
from backend.core.config import (
  cCollectorSocket, cEventsDatabaseFile, cRunPath, cVersion, fLoadSettings, fSettingsMtime
)
from backend.core.grouping import Grouper
from backend.core.health import HealthMonitor, fDiskDetection, fNoticeDetection
from backend.core.ipc import IpcServer
from backend.core.masking import fCreateMasker
from backend.core.registry import fCheckRequirements, fCreateModules
from backend.core.rules import RulesEngine
from backend.core.soc import SocSender, fBuildAlert, fSocConfigured
from backend.core.storage_sqlite import SqliteStorage
from backend.core.tailer import FileTailer
from backend.core.timeutil import fEpochToStorage, fNowStorage, fStorageFromNow, fStorageToEpoch

cFlushSeconds = 1.0
cFlushRecords = 500
cCatchUpLeadSeconds = 5


class Collector:

  def __init__(self, pFromStart: bool = False, pOnce: bool = False):
    self.vFromStart = pFromStart
    self.vOnce = pOnce
    self.dSettings = fLoadSettings()
    self.vSettingsMtime = fSettingsMtime()
    self.vMasker = fCreateMasker(self.dSettings)
    self.vStorage = SqliteStorage(cEventsDatabaseFile)
    self.vStop = threading.Event()
    self.vReloadRequested = threading.Event()
    self.vDoctorRequested = threading.Event()
    self.dModules = {}
    self.ldManifests = []
    self.ldModuleErrors = []
    self.dEnabled = {}
    self.dRequirements = {}
    self.dCorrelators = {}
    self.dSources = {}
    # Modules whose sources this process already follows (mDiscover). Only a
    # source of theirs that has no saved position is new (a new vhost); the
    # sources of any other module start at their end.
    self.sFollowedModules = set()
    self.vRules = RulesEngine()
    self.vGrouper = None
    self.vHealth = HealthMonitor(self)
    self.vSender = None
    self.vChannels = None
    self.vIpc = None
    self.vLastDiscovery = 0.0
    self.vLastHealth = 0.0
    self.vLastRetention = 0.0
    self.vLastState = 0.0
    self.vLastGroups = 0.0
    self.vLastRulesCleanup = 0.0
    self.vDiskLevel = "normal"
    self.vLastTrimAlert = 0.0
    self.dCounters = {"records": 0, "events": 0, "detections": 0, "started": fNowStorage()}

  # Logging

  def mLog(self, pMessage: str) -> None:
    print(f"{fNowStorage()} {pMessage}", flush=True)

  # Setup

  def mSetup(self) -> None:
    self.vStorage.mInitialize()
    self.vGrouper = Grouper(self.vStorage, self.dSettings)
    # The modules installed in /opt/localsiem/modules; one that fails to load
    # is reported and the others go on.
    self.dModules, self.ldManifests, self.ldModuleErrors = fCreateModules(self.dSettings, self.vMasker, self.vStorage)
    for dError in self.ldModuleErrors:
      self.mLog(f"Module {dError['id']} not loaded: {dError['error']}")
    for vName, vModule in list(self.dModules.items()):
      try:
        vModule.mStart()
        self.dCorrelators[vName] = vModule.mCreateCorrelator()
      except Exception as vError:
        self.ldModuleErrors.append({"id": vName, "path": vModule.dManifest.get("path", ""), "error": f"{type(vError).__name__}: {vError}"[:500]})
        self.mLog(f"Module {vName} not started: {vError}")
        del self.dModules[vName]
    self.mLog("Modules: " + (", ".join(f"{vName} {vModule.dManifest.get('version', '')} ({'on' if vModule.mEnabled() else 'off'})" for vName, vModule in self.dModules.items()) or "none"))
    self.mCheckRequirements()
    self.mLoadRules()
    self.mDiscover()
    # Records stored before a stop whose correlation window had not ended.
    ldPending = self.vStorage.mLoadPendingRecords()
    for dRecord in ldPending:
      vCorrelator = self.dCorrelators.get(dRecord["module"])
      if vCorrelator is not None:
        vCorrelator.mAdd(dRecord)
    if ldPending:
      self.mLog(f"Resumed {len(ldPending)} records waiting for correlation.")
    self.mPublishDoctor()

  def mCheckRequirements(self) -> None:
    # What each module needs before it can be turned on (mRequirements), kept
    # for the web: state <name>.requirements. Only when the collector starts
    # and when it reloads, never in every cycle: a module may read the
    # configuration of its service to check them. Nothing is turned on or off
    # here: a module that is on and no longer meets them stays on, and its
    # doctor and its health say what is missing.
    for vName, vModule in self.dModules.items():
      dResult = fCheckRequirements(vModule)
      lMissing = [str(dCheck.get("id", "")) for dCheck in dResult["checks"] if dCheck.get("status") == "error"]
      lBefore = [str(dCheck.get("id", "")) for dCheck in (self.dRequirements.get(vName) or {}).get("checks", []) if dCheck.get("status") == "error"]
      if lMissing and lMissing != lBefore:
        self.mLog(f"Module {vName}: requirements missing: {', '.join(lMissing)}.")
      elif lBefore and not lMissing:
        self.mLog(f"Module {vName}: requirements met.")
      self.dRequirements[vName] = dResult
      try:
        self.vStorage.mSetState(f"{vName}.requirements", dResult)
      except Exception as vError:
        self.mLog(f"Requirements of {vName} not saved: {vError}")

  def mLoadRules(self) -> None:
    lPaths = []
    for vName, vModule in self.dModules.items():
      lPaths.append((vName, vModule.mRulesPath(), vModule.mRuleFunctions()))
    self.vRules.mLoad(lPaths, self.dSettings.get("rules", {}))
    for vError in self.vRules.lErrors:
      self.mLog("Rule error: " + vError)

  def mDiscover(self) -> None:
    self.vLastDiscovery = time.time()
    dPositions = self.vStorage.mGetPositions()
    sCurrent = set()
    for vName, vModule in self.dModules.items():
      vEnabled = vModule.mEnabled()
      if vName in self.dEnabled and self.dEnabled[vName] != vEnabled:
        self.mLog(f"Module {vName} " + ("enabled." if vEnabled else "disabled."))
      self.dEnabled[vName] = vEnabled
      if not vEnabled:
        # Turned on again, its sources go on from their saved positions and
        # the ones without a position start at their end.
        self.sFollowedModules.discard(vName)
        continue
      try:
        ldSources = vModule.mDiscover()
      except Exception as vError:
        self.mLog(f"Discovery of {vName} failed: {vError}")
        continue
      vFollowed = vName in self.sFollowedModules
      for dSource in ldSources:
        vKey = dSource["key"]
        sCurrent.add(vKey)
        if vKey in self.dSources:
          self.dSources[vKey]["source"] = dSource
          continue
        dPosition = dPositions.get(vKey)
        vStartAtEnd = not self.vFromStart
        if dPosition is None and vFollowed and not self.vFromStart:
          # A source that appeared while its module was already followed (a
          # new vhost): from its start if it is small, else from its end.
          # Any other source without a saved position (the first discovery
          # of this process, a module installed or turned on later, a file
          # that could not be read until now) starts at its end: what it
          # already had is history and is never alerted.
          try:
            vStartAtEnd = os.path.getsize(dSource["path"]) > 5 * 1024 * 1024
          except OSError:
            vStartAtEnd = False
        vTailer = FileTailer(vKey, dSource["path"], dPosition, vStartAtEnd, int(self.dSettings.get("health", {}).get("missing_grace_seconds", 60)))
        self.dSources[vKey] = {"source": dSource, "tailer": vTailer, "framer": vModule.mCreateFramer(dSource), "module": vName}
      self.sFollowedModules.add(vName)
    for vKey in list(self.dSources):
      if vKey not in sCurrent:
        self.dSources[vKey]["tailer"].mClose()
        del self.dSources[vKey]
    self.mLog(f"Discovery: {len(self.dSources)} sources.")

  def mReloadSettings(self) -> None:
    self.dSettings = fLoadSettings()
    self.vSettingsMtime = fSettingsMtime()
    self.vMasker = fCreateMasker(self.dSettings)
    for vModule in self.dModules.values():
      vModule.mReload(self.dSettings, self.vMasker)
    # With the new settings (the Apache configuration file, for example);
    # Reconfigure in the web asks for this reload too.
    self.mCheckRequirements()
    self.vGrouper.mReload(self.dSettings)
    self.mLoadRules()
    self.mDiscover()
    self.mPublishDoctor()
    # The web shows at once a module turned on or off.
    self.mPublishState()
    self.mLog("Settings reloaded.")

  # Main loop

  def mRun(self) -> None:
    self.mSetup()
    self.vSender = SocSender(self)
    self.vSender.start()
    self.vChannels = ChannelSender(self)
    self.vChannels.start()
    if not self.vOnce:
      self.vIpc = IpcServer(cCollectorSocket, self.mHandleIpc)
      self.vIpc.mBind()
      self.vIpc.start()
    self.mLog(f"localSIEM collector {cVersion} started (host {self.dSettings['host']}).")
    try:
      while not self.vStop.is_set():
        vStart = time.time()
        try:
          self.mCycle()
        except Exception as vError:
          self.mLog("Cycle error: " + type(vError).__name__ + ": " + str(vError))
          traceback.print_exc()
          time.sleep(2)
        if self.vOnce:
          self.mFinishOnce()
          break
        vElapsed = time.time() - vStart
        if any(dEntry["tailer"].vBacklog for dEntry in self.dSources.values()):
          # Catching up (a burst, or the lines written while stopped): the
          # next cycle starts at once.
          continue
        self.vStop.wait(max(0.05, cFlushSeconds - vElapsed))
    finally:
      if self.vIpc is not None:
        self.vIpc.mStop()
      if self.vSender is not None:
        self.vSender.mStop()
        self.vSender.join(timeout=5)
      if self.vChannels is not None:
        self.vChannels.mStop()
        self.vChannels.join(timeout=5)
      for dEntry in self.dSources.values():
        dEntry["tailer"].mClose()
      self.mPublishState()
      self.vStorage.mClose()
      self.mLog("localSIEM collector stopped.")

  def mFinishOnce(self) -> None:
    # Everything read is evaluated now and the SOC queue is filled.
    for _ in range(50):
      if not self.mReadSources():
        break
    self.mProcessDue(pForce=True)
    self.mProcessGroups(pForceAll=True)
    self.mPublishState()
    if self.vSender is not None:
      self.vSender.mWakeUp()
      time.sleep(3)

  def mCycle(self) -> None:
    vNow = time.time()
    if self.vReloadRequested.is_set() or fSettingsMtime() != self.vSettingsMtime:
      self.vReloadRequested.clear()
      self.mReloadSettings()
    if vNow - self.vLastDiscovery >= self.mDiscoveryInterval():
      self.mDiscover()
      self.mPublishDoctor()
    if self.vDoctorRequested.is_set():
      self.vDoctorRequested.clear()
      self.mDiscover()
      self.mPublishDoctor()
    self.mReadSources()
    self.mProcessDue()
    if vNow - self.vLastGroups >= 1.0:
      self.vLastGroups = vNow
      self.mProcessGroups()
    if vNow - self.vLastHealth >= 60:
      self.vLastHealth = vNow
      self.mCheckHealth()
    if vNow - self.vLastRetention >= 600:
      self.vLastRetention = vNow
      self.mRetention()
    if vNow - self.vLastRulesCleanup >= 300:
      self.vLastRulesCleanup = vNow
      self.vRules.mCleanup()
    if vNow - self.vLastState >= 10:
      self.vLastState = vNow
      self.mPublishState()

  def mDiscoveryInterval(self) -> float:
    # The shortest one among the enabled modules.
    lIntervals = []
    for vModule in self.dModules.values():
      if vModule.mEnabled():
        try:
          lIntervals.append(max(60.0, vModule.mDiscoveryInterval()))
        except (TypeError, ValueError):
          continue
    return min(lIntervals) if lIntervals else 3600.0

  def mReadSources(self) -> bool:
    # Returns True when something was read (for --once).
    ldRecords = []
    dPositions = {}
    ldNotices = []
    vReceived = fNowStorage()
    # While catching up, the sources are read at the same pace in log time:
    # one that is more than 5 s ahead of the slowest one waits, so the
    # requests do not pile up in memory waiting for their other records.
    dSlowest = {}
    for dEntry in self.dSources.values():
      if dEntry["tailer"].vBacklog:
        vMark = dEntry.get("watermark", 0.0)
        dSlowest[dEntry["module"]] = min(dSlowest.get(dEntry["module"], vMark), vMark)
    for vKey, dEntry in self.dSources.items():
      vTailer = dEntry["tailer"]
      vSlowest = dSlowest.get(dEntry["module"])
      if vSlowest is not None and dEntry.get("watermark", 0.0) > vSlowest + cCatchUpLeadSeconds:
        continue
      try:
        lLines, lNotices = vTailer.mPoll(2 * 1024 * 1024)
      except OSError as vError:
        lLines, lNotices = [], [{"kind": "unreadable", "path": dEntry["source"]["path"], "error": str(vError)}]
      for dNotice in lNotices:
        dNotice["source_key"] = vKey
        ldNotices.append(dNotice)
      vFramer = dEntry["framer"]
      if not lLines:
        # A file just opened that has nothing new yet: its position is saved
        # now, so that after a restart it goes on from here and is not taken
        # for a new file. Never while its framer holds part of a unit.
        if vTailer.vOpenedUnsaved and vFramer.mSafeCommit() is None:
          vTailer.vOpenedUnsaved = False
          dPositions[vKey] = vTailer.mPosition(None)
        continue
      vModule = self.dModules[dEntry["module"]]
      vLastCommit = None
      for vText, vDevice, vInode, vOffset in lLines:
        for vUnit, vCommit in vFramer.mFeed(vText, vDevice, vInode, vOffset):
          try:
            dRecord = vModule.mParse(dEntry["source"], vUnit, vReceived)
          except Exception as vError:
            dRecord = {
              "time": vReceived, "received": vReceived, "module": dEntry["module"], "source": dEntry["source"]["kind"],
              "source_key": vKey, "correlation": None, "parse_status": "unparsed", "fields": {"parser_error": str(vError)[:300]},
              "raw": self.vMasker.mMaskText(vUnit)[:65536]
            }
          ldRecords.append(dRecord)
          self.vHealth.vStatistics.mAdd(vKey, dRecord["parse_status"])
          if dRecord.get("time") and dRecord["parse_status"] != "unparsed":
            dEntry["watermark"] = max(dEntry.get("watermark", 0.0), fStorageToEpoch(dRecord["time"]))
          vLastCommit = vCommit
        vLastCommit = (vDevice, vInode, vOffset) if vFramer.mSafeCommit() is None else vLastCommit
      vSafe = vFramer.mSafeCommit()
      if vSafe is None:
        vSafe = vLastCommit
      if vSafe:
        dPositions[vKey] = vTailer.mPosition(vSafe)
        vTailer.vOpenedUnsaved = False
      if len(ldRecords) >= cFlushRecords:
        self.mStoreRecords(ldRecords, dPositions)
        ldRecords = []
        dPositions = {}
    if ldRecords or dPositions:
      self.mStoreRecords(ldRecords, dPositions)
    for dNotice in ldNotices:
      self.mHandleNotice(dNotice)
    return bool(ldRecords)

  def mStoreRecords(self, pRecords: list[dict], pPositions: dict) -> None:
    self.vStorage.mSaveRecords(pRecords, pPositions)
    self.dCounters["records"] += len(pRecords)
    for dRecord in pRecords:
      self.dCorrelators[dRecord["module"]].mAdd(dRecord)

  def mHandleNotice(self, pNotice: dict) -> None:
    vKind = pNotice["kind"]
    self.mLog(f"Source {pNotice.get('path')}: {vKind}" + (f" ({pNotice['method']})" if pNotice.get("method") else ""))
    dDetection = fNoticeDetection(pNotice)
    if dDetection is not None:
      self.mDetect(dDetection)

  def mWatermark(self, pModule: str) -> float | None:
    # Lowest log time read among the sources of the module that are behind.
    lMarks = [
      dEntry.get("watermark", 0.0) for dEntry in self.dSources.values()
      if dEntry["module"] == pModule and dEntry["tailer"].vBacklog
    ]
    return min(lMarks) if lMarks else None

  def mProcessDue(self, pForce: bool = False) -> None:
    ldEvents = []
    for vName, vCorrelator in self.dCorrelators.items():
      vModule = self.dModules[vName]
      for dTransaction in vCorrelator.mDue(pForce=pForce, pWatermark=self.mWatermark(vName)):
        try:
          dEvent = vModule.mBuildEvent(dTransaction)
        except Exception as vError:
          self.mLog(f"Event of {vName} failed: {type(vError).__name__}: {vError}")
          traceback.print_exc()
          continue
        ldEvents.append(dEvent)
    if not ldEvents:
      return
    ldSignals = []
    for dEvent in ldEvents:
      lSignals = self.vRules.mEvaluate(dEvent, fStorageToEpoch(dEvent["time"]))
      dEvent["signals"] = lSignals
      for dSignal in lSignals:
        dEvent["rule_hits"].append({"rule": dSignal["rule_id"], "category": dSignal["category"]})
        if dSignal["rule_id"] not in dEvent["rules"]:
          dEvent["rules"].append(dSignal["rule_id"])
        if not dEvent.get("category"):
          dEvent["category"] = dSignal["category"]
        ldSignals.append((dEvent, dSignal))
    lStored = ldEvents
    if self.vDiskLevel == "critical":
      # Out of space: only what takes part in an alert is kept.
      lStored = [dEvent for dEvent in ldEvents if dEvent["detections"] or dEvent["signals"]]
      lDropped = [vId for dEvent in ldEvents if not (dEvent["detections"] or dEvent["signals"]) for vId in dEvent["record_ids"]]
      self.vStorage.mDeleteRecords(lDropped)
    lIds = self.vStorage.mSaveEvents(lStored)
    self.dCounters["events"] += len(lStored)
    for dEvent, vId in zip(lStored, lIds):
      dEvent["id"] = vId
      for dDetection in dEvent["detections"]:
        dDetection["event_id"] = vId
        self.mDetect(dDetection)
      for dSignal in dEvent["signals"]:
        vModule = self.dModules.get(dEvent["module"])
        if hasattr(vModule, "mDetectionFromSignal"):
          dDetection = vModule.mDetectionFromSignal(dEvent, dSignal)
        else:
          dDetection = {
            "module": dEvent["module"], "vhost": dEvent.get("vhost") or "", "ip": dEvent.get("ip") or "",
            "category": dSignal["category"], "severity": dSignal["severity"], "rule": dSignal["name"],
            "type": dSignal["type"], "description": dSignal["description"], "search": dSignal["search"],
            "details": {}, "time": dEvent["time"], "uid": dEvent.get("uid") or ""
          }
        dDetection["event_id"] = vId
        self.mDetect(dDetection)
        self.vStorage.mSetEventSeverity(vId, dSignal["severity"])

  def mDetect(self, pDetection: dict) -> None:
    try:
      self.vGrouper.mAdd(pDetection)
      self.dCounters["detections"] += 1
    except Exception as vError:
      self.mLog(f"Grouping failed: {type(vError).__name__}: {vError}")
      traceback.print_exc()

  def mProcessGroups(self, pForceAll: bool = False) -> None:
    vNow = fStorageFromNow(86400 * 365) if pForceAll else fNowStorage()
    ldGroups = self.vStorage.mGetDueGroups(vNow)
    # The SOC is optional: without one (or with the sending turned off) the
    # alerts stay in localSIEM as not sent and are never sent later.
    vSocConfigured = fSocConfigured(self.dSettings) if ldGroups else False
    for dGroup in ldGroups:
      vModule = self.dModules.get(dGroup["module"])
      dContext = {}
      if vModule is not None:
        try:
          dContext = vModule.mEnrich(dGroup)
        except Exception as vError:
          self.mLog(f"Enrichment failed: {vError}")
      if vSocConfigured:
        dAlert = fBuildAlert(dGroup, dContext, self.dSettings["host"])
        self.vStorage.mQueueGroup(dGroup["id"], json.dumps(dAlert, ensure_ascii=False, separators=(",", ":")), fNowStorage())
      else:
        self.vStorage.mSkipGroup(dGroup["id"], "soc_not_configured")
      # The same alert through the channels, when its severity reaches the
      # minimum (backend/core/channels.py).
      if self.vChannels is not None:
        self.vChannels.mNotify(dGroup)
    if ldGroups and self.vSender is not None:
      self.vSender.mWakeUp()

  # Health and retention

  def mCheckHealth(self) -> None:
    for dDetection in self.vHealth.mCheckSources(self.dSources):
      self.mDetect(dDetection)
    for vModule in self.dModules.values():
      if not vModule.mEnabled():
        continue
      try:
        for dDetection in vModule.mHealth(time.time()):
          self.mDetect(dDetection)
      except Exception as vError:
        self.mLog(f"Health of {vModule.vName} failed: {vError}")
    vLevel = self.vHealth.mDiskLevel()
    if vLevel != self.vDiskLevel:
      self.mLog(f"Disk level: {vLevel}")
      if vLevel != "normal":
        dUsage = self.vHealth.mDiskUsage()
        self.mDetect(fDiskDetection(vLevel, dUsage["free"], dUsage["total"], False))
      self.vDiskLevel = vLevel
      for vModule in self.dModules.values():
        vModule.mSetLowDisk(vLevel != "normal")

  def mRetention(self) -> None:
    vStart = time.time()
    vDeleted = 0
    vCutoff = fStorageFromNow(-86400 * float(self.dSettings.get("retention_days", 90)))
    while time.time() - vStart < 5:
      vCount = self.vStorage.mDeleteOldEvents(vCutoff, 500)
      vDeleted += vCount
      if vCount < 500:
        break
    self.vStorage.mDeleteOldAlerts(fStorageFromNow(-86400 * float(self.dSettings.get("alert_retention_days", 365))), 500)
    vMaximum = self.vHealth.mMaxDatabaseBytes()
    vTrimmed = False
    while time.time() - vStart < 20 and self.vStorage.mGetUsedBytes() > vMaximum * 0.95:
      vOldest = self.vStorage.mOldestEventTime()
      if not vOldest:
        break
      # One hour of the oldest events at a time.
      vLimit = fEpochToStorage(fStorageToEpoch(vOldest) + 3600)
      vCount = self.vStorage.mDeleteOldEvents(vLimit, 2000)
      vDeleted += vCount
      vTrimmed = True
      if vCount == 0:
        break
    if vDeleted:
      self.vStorage.mReleaseSpace()
      self.mLog(f"Retention: {vDeleted} events deleted" + (" (disk limit)" if vTrimmed else ""))
    if vTrimmed and time.time() - self.vLastTrimAlert > 86400:
      self.vLastTrimAlert = time.time()
      dUsage = self.vHealth.mDiskUsage()
      self.mDetect(fDiskDetection("trimmed", dUsage["free"], dUsage["total"], True))
    self.vStorage.mSetState("collector.retention", {"time": fNowStorage(), "deleted": vDeleted, "trimmed": vTrimmed})
    self.vStorage.mOptimize()

  # State for the web

  def mPublishState(self) -> None:
    ldSources = []
    for vKey, dEntry in self.dSources.items():
      dSource = dEntry["source"]
      vTailer = dEntry["tailer"]
      vLines, vUnparsed = self.vHealth.vStatistics.mLastHour(vKey)
      dTotals = self.vHealth.vStatistics.dTotals.get(vKey, {"lines": 0, "unparsed": 0, "partial": 0})
      vLast = self.vHealth.vStatistics.dLastData.get(vKey) or vTailer.vLastData or None
      ldSources.append({
        "key": vKey, "module": dEntry["module"], "kind": dSource["kind"], "path": dSource["path"],
        "vhost": dSource.get("vhost", ""), "format": dSource.get("format", ""),
        "exists": os.path.exists(dSource["path"]), "open": vTailer.vFile is not None,
        "unreadable": vTailer.vUnreadableReported, "offset": vTailer.vOffset,
        "lines_hour": vLines, "unparsed_hour": vUnparsed,
        "lines_total": dTotals["lines"], "unparsed_total": dTotals["unparsed"], "partial_total": dTotals["partial"],
        "last_data": fEpochToStorage(vLast) if vLast else None
      })
    dDisk = self.vHealth.mDiskUsage()
    ldSkipped = []
    dModules = {}
    for vName, vModule in self.dModules.items():
      vEnabled = vModule.mEnabled()
      if vEnabled:
        for dSkipped in vModule.mSkipped():
          ldSkipped.append({**dSkipped, "module": vName})
      dModules[vName] = {
        "enabled": vEnabled, "version": vModule.dManifest.get("version", ""),
        "sources": sum(1 for dEntry in self.dSources.values() if dEntry["module"] == vName),
        "pending": self.dCorrelators[vName].mPendingCount() if vName in self.dCorrelators else 0
      }
    dState = {
      "time": fNowStorage(), "version": cVersion, "pid": os.getpid(), "host": self.dSettings["host"],
      "counters": self.dCounters, "sources": ldSources,
      "pending": {vName: vCorrelator.mPendingCount() for vName, vCorrelator in self.dCorrelators.items()},
      "disk": {"total": dDisk["total"], "free": dDisk["free"], "level": self.vDiskLevel},
      "database": {"used": self.vStorage.mGetUsedBytes(), "file": self.vStorage.mGetFileBytes(), "maximum": self.vHealth.mMaxDatabaseBytes()},
      "rules": self.vRules.mDescribe(), "rule_errors": self.vRules.lErrors[-20:],
      "skipped": ldSkipped,
      "modules": dModules, "module_errors": self.ldModuleErrors,
      "sender": self.vSender.vState if self.vSender is not None else "stopped"
    }
    self.vStorage.mSetState("collector.status", dState)

  def mPublishDoctor(self) -> None:
    for vName, vModule in self.dModules.items():
      try:
        if not vModule.mEnabled():
          self.vStorage.mSetState(f"{vName}.doctor", {"time": fNowStorage(), "checks": [], "enabled": False})
          continue
        self.vStorage.mSetState(f"{vName}.doctor", {"time": fNowStorage(), "checks": vModule.mDoctor(), "enabled": True})
      except Exception as vError:
        self.mLog(f"Doctor of {vName} failed: {vError}")

  # Local socket

  def mHandleIpc(self, pMessage: dict) -> dict:
    vCommand = pMessage.get("command")
    if vCommand == "reload":
      self.vReloadRequested.set()
      return {"ok": True}
    if vCommand == "doctor":
      self.vDoctorRequested.set()
      return {"ok": True}
    if vCommand == "restart":
      # A module was installed or uninstalled from the web: the collector
      # stops as on SIGTERM (positions and pending records are kept) and
      # systemd or supervise-daemon starts it again, with the new code or
      # without the module.
      self.mLog("Restart requested: modules installed, updated or uninstalled.")
      self.vStop.set()
      return {"ok": True}
    if vCommand == "soc_retry":
      vCount = self.vStorage.mRetryQueueNow(fNowStorage())
      if self.vSender is not None:
        self.vSender.mWakeUp()
      return {"ok": True, "pending": vCount}
    if vCommand == "soc_requeue_rejected":
      vCount = self.vStorage.mRequeueRejected(fNowStorage())
      if self.vSender is not None:
        self.vSender.mWakeUp()
      return {"ok": True, "requeued": vCount}
    if vCommand == "heartbeat":
      if self.vSender is not None:
        self.vSender.mHeartbeatNow()
      return {"ok": True}
    if vCommand == "status":
      return {"ok": True, "version": cVersion, "sources": len(self.dSources), "counters": self.dCounters}
    return {"ok": False, "error": "unknown_command"}

  def mRequestStop(self, *pArguments) -> None:
    self.vStop.set()


def fMain(pArguments: list[str]) -> None:
  if any(vArgument in ("-h", "--help") for vArgument in pArguments):
    print(__doc__.strip())
    return
  for vArgument in pArguments:
    if vArgument not in ("--from-start", "--once"):
      raise ValueError(f"Unsupported option: {vArgument}")
  os.umask(0o077)
  cRunPath.mkdir(parents=True, exist_ok=True)
  with (cRunPath / "collector.lock").open("w") as vLock:
    try:
      fcntl.flock(vLock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      raise ValueError("Another collector is already running.") from None
    vCollector = Collector("--from-start" in pArguments, "--once" in pArguments)
    signal.signal(signal.SIGTERM, vCollector.mRequestStop)
    signal.signal(signal.SIGINT, vCollector.mRequestStop)
    signal.signal(signal.SIGHUP, lambda *pArguments: vCollector.vReloadRequested.set())
    try:
      vCollector.mRun()
    finally:
      fcntl.flock(vLock, fcntl.LOCK_UN)


if __name__ == "__main__":
  try:
    fMain(sys.argv[1:])
  except (OSError, ValueError) as vError:
    print(f"Collector failed: {vError}", file=sys.stderr)
    raise SystemExit(1) from vError
