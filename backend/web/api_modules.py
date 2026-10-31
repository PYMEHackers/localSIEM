"""Modules and the overview of both dashboards (/api/modules,
/api/admin/modules/..., /api/overview).

State of each module, for everybody signed in:

  ok         on, loaded by the collector and reading its sources (doctor
             warnings are listed as notes, they do not change it)
  warning    on, but without sources, with a missing source or installed
             after the collector started
  error      it does not load, its doctor reports an error or a source
             cannot be read
  pending    just turned on or off; the collector is applying it
  disabled   off (modules.<name>.enabled false);
             with the reason requirements_missing while the server lacks
             what the module needs (mRequirements)
  unknown    the collector is not running (no state in the last 2 minutes)

Administrators also get its settings (described by its module.json), its
requirements, its sources, its doctor and its rules, and can turn it on and
off and save them: they go to settings.json under modules.<name> (rules under
rules.<id>) and the collector applies them at once, without restarting
anything. A module is turned on only while it meets its requirements;
Reconfigure checks them again. Installing a module never installs the
software it watches, and nothing turns a module off by itself.

Modules are installed and uninstalled only here: administrators list the
modules of the localSIEM-modules repository and install or update one
(/api/admin/module-catalog), and uninstall an installed one (DELETE
/api/admin/modules/<name>); the web reloads its modules and the collector
restarts with the new code, or without the module. On its first
installation, a module that lacks its requirements is installed turned off.
"""

import asyncio

from fastapi import Body, HTTPException, Request

from backend.core.catalog import CatalogError, fFetchAndInstall, fFetchCatalog, fRemove, fRepository, fRootCommand
from backend.core.config import fDeepMerge, fReadSettingsFile, fSaveSettings
from backend.core.query import fParseQuery
from backend.core.registry import fModuleSettings, fValidateSettings
from backend.core.rules import fDescribeFolder
from backend.core.storage_sqlite import SearchTimeout
from backend.core.timeutil import fNow, fStorageFromNow, fStorageToDisplay, fStorageToEpoch

lSeverities = ["low", "medium", "high", "critical"]
cStaleSeconds = 120
lErrorReasons = ["load_error", "doctor_error", "source_unreadable"]
# Advice that does not stop the module from working.
lNoteReasons = ["doctor_warning"]


def fRead(pContext) -> dict:
  # Everything the collector published, in one go.
  dData = {"status": None, "running": False, "doctor": {}, "requirements": {}, "counts": {}, "storage": None}
  try:
    vStorage = pContext.mEvents()
  except HTTPException:
    return dData
  dData["storage"] = vStorage
  dStatus = vStorage.mGetState("collector.status", None)
  if isinstance(dStatus, dict) and dStatus.get("time"):
    dData["status"] = dStatus
    dData["running"] = fNow().timestamp() - fStorageToEpoch(dStatus["time"]) < cStaleSeconds
  for vKey, dValue in vStorage.mGetStates("").items():
    if vKey.endswith(".doctor") and isinstance(dValue.get("value"), dict):
      dData["doctor"][vKey[:-len(".doctor")]] = dValue["value"]
    elif vKey.endswith(".requirements") and isinstance(dValue.get("value"), dict):
      dData["requirements"][vKey[:-len(".requirements")]] = dValue["value"]
  try:
    dData["counts"] = vStorage.mModuleCounts(fStorageFromNow(-86400), float(pContext.dSettings.get("search_timeout_seconds", 5)))
  except SearchTimeout:
    dData["counts"] = {}
  return dData


def fEnabled(pContext, pManifest: dict) -> bool:
  vModule = pContext.mModule(pManifest["id"])
  if vModule is None:
    return bool(fModuleSettings(pManifest, pContext.dSettings).get("enabled"))
  vModule.mReload(pContext.dSettings, vModule.vMasker)
  return bool(vModule.mEnabled())


def fRequirements(pContext, pId: str, pData: dict) -> dict:
  # The newest check of the requirements of a module: the collector's (when
  # it starts and reloads: <name>.requirements) or the web's own (first
  # installation, turning it on, Reconfigure). {} if never checked.
  dNewest = {}
  for dResult in (pData["requirements"].get(pId), pContext.dRequirements.get(pId)):
    if isinstance(dResult, dict) and dResult.get("time") and str(dResult["time"]) > str(dNewest.get("time", "")):
      dNewest = dResult
  return dNewest


def fMissing(pRequirements: dict) -> list[dict]:
  # The checks of mRequirements() that are not met.
  return [dCheck for dCheck in pRequirements.get("checks") or [] if isinstance(dCheck, dict) and dCheck.get("status") == "error"]


def fSummary(pContext, pManifest: dict, pData: dict) -> dict:
  vId = pManifest["id"]
  dStatus = pData["status"] or {}
  ldSources = [dSource for dSource in dStatus.get("sources", []) if dSource.get("module") == vId]
  dDoctor = pData["doctor"].get(vId) or {}
  dChecks = {"ok": 0, "warning": 0, "error": 0, "info": 0}
  for dCheck in dDoctor.get("checks", []) or []:
    if dCheck.get("status") in dChecks:
      dChecks[dCheck["status"]] += 1
  dCounts = pData["counts"].get(vId) or {}
  # Errors of this very folder only.
  lLoadErrors = [
    dError["error"] for dError in pContext.ldModuleErrors + list(dStatus.get("module_errors") or [])
    if dError.get("id") == vId and dError.get("path", pManifest["path"]) == pManifest["path"]
  ]
  vEnabled = fEnabled(pContext, pManifest)
  dRequirements = fRequirements(pContext, vId, pData)
  ldMissing = fMissing(dRequirements)
  lLast = [dSource["last_data"] for dSource in ldSources if dSource.get("last_data")]
  lReasons = []
  if lLoadErrors:
    vState = "error"
    lReasons.append("load_error")
  elif not vEnabled:
    vState = "disabled"
    # Off while the server lacks what it needs: it cannot be turned on yet.
    if ldMissing:
      lReasons.append("requirements_missing")
  elif not pData["running"]:
    vState = "unknown"
    lReasons.append("collector_stopped")
  elif vId not in (dStatus.get("modules") or {}):
    vState = "warning"
    lReasons.append("not_loaded")
  elif bool(dStatus["modules"][vId].get("enabled")) != vEnabled:
    vState = "pending"
    lReasons.append("applying")
  else:
    if dChecks["error"]:
      lReasons.append("doctor_error")
    if any(dSource.get("unreadable") for dSource in ldSources):
      lReasons.append("source_unreadable")
    if not ldSources:
      lReasons.append("no_sources")
    if any(not dSource.get("exists") for dSource in ldSources):
      lReasons.append("source_missing")
    if dChecks["warning"]:
      lReasons.append("doctor_warning")
    if any(vReason in lErrorReasons for vReason in lReasons):
      vState = "error"
    elif any(vReason not in lNoteReasons for vReason in lReasons):
      vState = "warning"
    else:
      vState = "ok"
  return {
    "id": vId, "version": pManifest.get("version", ""),
    "setup_option": pManifest.get("setup_option", ""), "texts": pManifest.get("texts", {}),
    "enabled": vEnabled, "state": vState, "reasons": lReasons, "error": lLoadErrors[0] if lLoadErrors else None,
    "sources": len(ldSources), "sources_reading": sum(1 for dSource in ldSources if dSource.get("open") and not dSource.get("unreadable")),
    "lines_hour": sum(int(dSource.get("lines_hour") or 0) for dSource in ldSources),
    "last_data": fStorageToDisplay(max(lLast)) if lLast else None,
    "events_24h": dCounts.get("events", 0), "blocked_24h": dCounts.get("blocked", 0), "alerted_24h": dCounts.get("alerted", 0),
    "last_event": fStorageToDisplay(dCounts["last"]) if dCounts.get("last") else None,
    "checks": dChecks, "doctor_time": fStorageToDisplay(dDoctor["time"]) if dDoctor.get("time") else None,
    # Whether it has requirements (Reconfigure) and the titles of the ones
    # missing: while it is off they lock its switch.
    "has_requirements": bool(dRequirements.get("checks")),
    "requirements_missing": [str(dCheck.get("title") or dCheck.get("id") or "") for dCheck in ldMissing]
  }


def fBrokenSummary(pError: dict) -> dict:
  # A folder with a module.json that cannot be used.
  return {
    "id": pError["id"], "version": "", "setup_option": "", "texts": {},
    "enabled": False, "state": "error", "reasons": ["load_error"], "error": pError["error"], "sources": 0, "sources_reading": 0,
    "lines_hour": 0, "last_data": None, "events_24h": 0, "blocked_24h": 0, "alerted_24h": 0, "last_event": None,
    "checks": {"ok": 0, "warning": 0, "error": 0, "info": 0}, "doctor_time": None,
    "has_requirements": False, "requirements_missing": []
  }


def fSummaries(pContext, pData: dict) -> list[dict]:
  ldModules = [fSummary(pContext, dManifest, pData) for dManifest in pContext.ldManifests]
  sPaths = {dManifest["path"] for dManifest in pContext.ldManifests}
  for dError in pContext.ldModuleErrors:
    if dError.get("path") not in sPaths:
      ldModules.append(fBrokenSummary(dError))
      sPaths.add(dError.get("path"))
  return ldModules


def fRules(pContext, pManifest: dict) -> tuple[list[dict], list[str]]:
  ldRules, lErrors = fDescribeFolder(pManifest["id"], f"{pManifest['path']}/rules")
  dOverrides = pContext.dSettings.get("rules", {}) or {}
  for dRule in ldRules:
    dOverride = dOverrides.get(dRule["id"], {}) if isinstance(dOverrides.get(dRule["id"]), dict) else {}
    dRule["enabled"] = dRule.pop("file_enabled") and dOverride.get("enabled") is not False
    dRule["severity"] = dOverride.get("severity", dRule["severity"])
    dRule["window"] = dOverride.get("window", dRule["window"])
    dRule["threshold"] = dOverride.get("first_threshold" if dRule["kind"] == "sequence" else "threshold", dRule["threshold"])
  return ldRules, lErrors


def fCleanRules(pRules: dict, pKnown: dict) -> dict:
  # Overrides of the rules of one module: {rule id: {enabled, severity,
  # threshold or first_threshold, window}}.
  dRules = {}
  for vRuleId, dOverride in pRules.items():
    if vRuleId not in pKnown or not isinstance(dOverride, dict):
      continue
    dClean = {}
    if "enabled" in dOverride:
      dClean["enabled"] = bool(dOverride["enabled"])
    if "severity" in dOverride:
      if dOverride["severity"] not in lSeverities:
        raise HTTPException(status_code=422, detail="invalid_severity")
      dClean["severity"] = dOverride["severity"]
    vThresholdKey = "first_threshold" if pKnown[vRuleId]["kind"] == "sequence" else "threshold"
    for vKey, vTarget, (vMinimum, vMaximum) in (("threshold", vThresholdKey, (1, 100000)), ("window", "window", (1, 86400))):
      if pKnown[vRuleId]["kind"] == "match" or dOverride.get(vKey) in (None, ""):
        continue
      try:
        vValue = int(dOverride[vKey])
      except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="invalid_rule_" + vKey) from None
      if not vMinimum <= vValue <= vMaximum:
        raise HTTPException(status_code=422, detail="invalid_rule_" + vKey)
      dClean[vTarget] = vValue
    dRules[vRuleId] = dClean
  return dRules


def fRegisterModules(pApp, pContext) -> None:

  def fRequireManifest(pName: str) -> dict:
    dManifest = pContext.mManifest(pName)
    if dManifest is None:
      raise HTTPException(status_code=404, detail="not_found")
    return dManifest

  @pApp.get("/api/modules", tags=["modules"], summary="Modules and their state")
  async def fModules(pRequest: Request):
    """Per module: name and summary (texts by language), version, on/off, state (ok, warning, error, pending, disabled, unknown) with its reasons (requirements_missing: off because the server lacks what it needs), sources read, lines in the last hour, last data, events, blocks and alerts of the last 24 hours, doctor counts, has_requirements and requirements_missing (the titles of the requirements not met: while the module is off they lock its switch). For every signed-in user; the administrator detail is /api/admin/modules/{name}."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dData = await asyncio.to_thread(fRead, pContext)
    return {"collector_running": dData["running"], "modules": await asyncio.to_thread(fSummaries, pContext, dData)}

  @pApp.get("/api/admin/modules/{pName}", tags=["modules"], summary="One module: state, settings, requirements, sources, doctor and rules")
  async def fModule(pName: str, pRequest: Request):
    """settings: the description of each setting (module.json); values: the current ones; requirements: the last check of what the server must have before the module can be turned on (time, met and the checks, with title, detail and fix; also while it is off); sources and skipped logs of the module; doctor checks with the snippet that fixes each one; rules with their overrides; root_command (installed modules): the command for root that lets localsiem read their logs and applies setup_option if added to it."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest)
    dManifest = fRequireManifest(pName)
    dData = await asyncio.to_thread(fRead, pContext)
    dResult = await asyncio.to_thread(fSummary, pContext, dManifest, dData)
    dRequirements = fRequirements(pContext, pName, dData)
    dStatus = dData["status"] or {}
    ldSources = []
    for dSource in dStatus.get("sources", []):
      if dSource.get("module") == pName:
        dSource = dict(dSource)
        dSource["last_data"] = fStorageToDisplay(dSource["last_data"]) if dSource.get("last_data") else None
        ldSources.append(dSource)
    dDoctor = dict(dData["doctor"].get(pName) or {})
    if dDoctor.get("time"):
      dDoctor["time"] = fStorageToDisplay(dDoctor["time"])
    ldRules, lRuleErrors = await asyncio.to_thread(fRules, pContext, dManifest)
    dValues = fModuleSettings(dManifest, pContext.dSettings)
    dResult.update({
      "settings": dManifest.get("settings", []),
      "values": {dSetting["key"]: dValues.get(dSetting["key"]) for dSetting in dManifest.get("settings", [])},
      "sources_detail": ldSources,
      "skipped": [dSkipped for dSkipped in dStatus.get("skipped", []) if dSkipped.get("module") == pName],
      "requirements": {
        "time": fStorageToDisplay(dRequirements["time"]) if dRequirements.get("time") else None,
        "checks": dRequirements.get("checks") or [], "met": not fMissing(dRequirements)
      },
      "doctor": dDoctor,
      "rules": ldRules,
      "rule_errors": lRuleErrors + [vError for vError in dStatus.get("rule_errors", []) if f"/{pName}/" in vError],
      "path": dManifest["path"],
      "root_command": fRootCommand()
    })
    return dResult

  @pApp.post("/api/admin/modules/{pName}", tags=["modules"], summary="Turn a module on or off and save its settings and rules")
  async def fSaveModule(pName: str, pRequest: Request, dBody: dict = Body(...)):
    """enabled (true/false), settings ({key: value} as module.json describes them) and rules ({rule id: {enabled, severity, threshold, window}}). The collector applies them at once. Turning a module on checks its requirements again (mRequirements, with the settings of the same request): while one is missing the answer is 422 requirements_missing, with requirements: the checks not met (title, detail, fix)."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest, True)
    dManifest = fRequireManifest(pName)
    dModule = {}
    if "enabled" in dBody:
      if not isinstance(dBody["enabled"], bool):
        raise HTTPException(status_code=422, detail="invalid_enabled")
      dModule["enabled"] = dBody["enabled"]
    if "settings" in dBody:
      try:
        dModule.update(fValidateSettings(dManifest, dBody["settings"]))
      except ValueError as vError:
        raise HTTPException(status_code=422, detail=str(vError)) from None
    if dModule.get("enabled") is True and not await asyncio.to_thread(fEnabled, pContext, dManifest):
      # A module is turned on only while the server has what it needs.
      dCandidate = fDeepMerge(pContext.dSettings, {"modules": {pName: dModule}}) if "settings" in dBody else None
      dRequirements = await asyncio.to_thread(pContext.mCheckRequirements, pName, dCandidate)
      if dRequirements is not None and not dRequirements["met"]:
        raise HTTPException(status_code=422, detail={"error": "requirements_missing", "detail": "requirements_missing", "requirements": fMissing(dRequirements)})
    dChanges = {}
    if dModule:
      dChanges["modules"] = {pName: dModule}
    if "rules" in dBody:
      if not isinstance(dBody["rules"], dict):
        raise HTTPException(status_code=422, detail="invalid_rules")
      ldRules, _ = await asyncio.to_thread(fRules, pContext, dManifest)
      dRules = fCleanRules(dBody["rules"], {dRule["id"]: dRule for dRule in ldRules})
      if dRules:
        dChanges["rules"] = dRules
    if dChanges:
      await asyncio.to_thread(fSaveSettings, dChanges)
      pContext.mApplySettings()
    try:
      await asyncio.to_thread(pContext.mCollector, {"command": "reload"}, 5)
      vNotified = True
    except HTTPException:
      vNotified = False
    return {"ok": True, "collector_notified": vNotified}

  @pApp.post("/api/admin/modules/{pName}/doctor", tags=["modules"], summary="Discover the sources again and run the doctor")
  async def fRunDoctor(pName: str, pRequest: Request):
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest, True)
    fRequireManifest(pName)
    await asyncio.to_thread(pContext.mCollector, {"command": "doctor"}, 5)
    return {"ok": True}

  @pApp.post("/api/admin/modules/{pName}/reconfigure", tags=["modules"], summary="Reconfigure: check the requirements of a module again")
  async def fReconfigure(pName: str, pRequest: Request):
    """Runs the requirement checks of the module (mRequirements) again with its saved settings (fix them first if needed, for example the Apache configuration file) and keeps the result for the state of the modules; the collector checks them again too. Also with the module off. It never turns the module on: the administrator does. Answer: requirements (time, met and the checks, with title, detail and fix), enabled and collector_notified. When they are met, root_command is the command to run as root so that localsiem can read the logs of the modules, also the ones created after installing the module, and setup_option the option to add to it to also apply the requirements of the module to its service, as after installing it. With the module on, the collector also discovers its sources again and runs its doctor."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest, True)
    dManifest = fRequireManifest(pName)
    dRequirements = await asyncio.to_thread(pContext.mCheckRequirements, pName)
    if dRequirements is None:
      raise HTTPException(status_code=422, detail="module_not_loaded")
    # On reload the collector checks the requirements again and keeps them,
    # and discovers the sources of the modules that are on and runs their
    # doctor (as «Discover again and run the doctor»).
    try:
      await asyncio.to_thread(pContext.mCollector, {"command": "reload"}, 5)
      vNotified = True
    except HTTPException:
      vNotified = False
    return {
      "ok": True, "enabled": await asyncio.to_thread(fEnabled, pContext, dManifest), "collector_notified": vNotified,
      "requirements": {"time": fStorageToDisplay(dRequirements["time"]), "checks": dRequirements["checks"], "met": dRequirements["met"]},
      "root_command": fRootCommand() if dRequirements["met"] else None,
      "setup_option": dManifest.get("setup_option", "")
    }

  # Modules of the localSIEM-modules repository (backend/core/catalog.py)

  def fCatalogFailure(pError: CatalogError) -> HTTPException:
    vCode = str(pError).split(":")[0]
    dStatuses = {
      "install_running": 409, "module_not_found": 404, "module_not_installed": 404, "download_failed": 502, "invalid_archive": 502,
      "archive_too_big": 502, "install_failed": 500, "uninstall_failed": 500
    }
    return HTTPException(status_code=dStatuses.get(vCode, 422), detail=vCode)

  def fFirstInstallation(pName: str) -> tuple[list[dict], bool]:
    # A module that lacks its requirements on its first installation (the
    # software it watches: installing it never installs that) is installed
    # turned off, unless the administrator already decided
    # (modules.<name>.enabled was saved). Returns (checks not met, turned off).
    ldMissing = fMissing(pContext.mCheckRequirements(pName) or {})
    if not ldMissing:
      return [], False
    dStored = (fReadSettingsFile().get("modules") or {}).get(pName)
    if isinstance(dStored, dict) and "enabled" in dStored:
      return ldMissing, False
    fSaveSettings({"modules": {pName: {"enabled": False}}})
    return ldMissing, True

  @pApp.get("/api/admin/module-catalog", tags=["modules"], summary="Modules of the localSIEM-modules repository")
  async def fGetCatalog(pRequest: Request):
    """Downloads the repository (settings modules_repository: url and ref; by default the branch main of https://github.com/PYMEHackers/localSIEM-modules) and lists its modules, the folders mod-<id>: id, version, the localSIEM version it needs, texts, installed version, newer (it is installed and the repository has a newer version, also one that this localSIEM cannot install) and action (install, update, reinstall, downgrade, incompatible or invalid). The web uses it in Modules › Installable (the modules not installed) and in Modules › Installed (Update, on the modules with action update)."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest)
    vUrl, vRef = fRepository(pContext.dSettings)
    try:
      ldModules = await asyncio.to_thread(fFetchCatalog, pContext.dSettings)
    except CatalogError as vError:
      raise fCatalogFailure(vError) from None
    return {"repository": vUrl, "ref": vRef, "modules": ldModules}

  @pApp.post("/api/admin/module-catalog/{pName}", tags=["modules"], summary="Install or update a module from the localSIEM-modules repository")
  async def fInstallFromCatalog(pName: str, pRequest: Request):
    """The only way to install a module. Downloads the repository again and installs the module (its folder mod-<name>) into /opt/localsiem/modules/<name>/, replacing the installed copy; the web reloads its modules and the collector restarts to load it. On a first installation it checks the requirements of the module (mRequirements of the installed copy): if one is missing and modules.<name>.enabled was never saved, the module is installed turned off (turned_off, requirements_missing: the checks not met, with title, detail and fix). An update or a reinstallation never turns it on or off, and keeps its settings. Letting localsiem read the logs of the module, and its setup option, need root: root_command is the command that does it (manage.py setup-modules; add setup_option to it to also apply the requirements of the module to its service). access_changed: whether the logs it reads (read_paths) or its setup option changed, always true on a first installation; when an update leaves them as they were, root has nothing to run again."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest, True)
    try:
      dManifest = await asyncio.to_thread(fFetchAndInstall, pContext.dSettings, pName)
    except CatalogError as vError:
      raise fCatalogFailure(vError) from None
    pContext.mReloadModules(pName)
    ldMissing, vTurnedOff = [], False
    if dManifest["previous"] is None:
      ldMissing, vTurnedOff = await asyncio.to_thread(fFirstInstallation, pName)
      if vTurnedOff:
        pContext.mApplySettings()
    try:
      await asyncio.to_thread(pContext.mCollector, {"command": "restart"}, 5)
      vRestarted = True
    except HTTPException:
      vRestarted = False
    return {
      "ok": True, "id": pName, "version": str(dManifest["version"]), "previous": dManifest["previous"],
      "collector_restarted": vRestarted, "read_paths": list(dManifest["read_paths"]), "setup_option": dManifest["setup_option"],
      "enabled": await asyncio.to_thread(fEnabled, pContext, pContext.mManifest(pName) or dManifest),
      "turned_off": vTurnedOff, "requirements_missing": ldMissing,
      "access_changed": dManifest["access_changed"], "root_command": fRootCommand()
    }

  @pApp.delete("/api/admin/modules/{pName}", tags=["modules"], summary="Uninstall an installed module")
  async def fUninstallModule(pName: str, pRequest: Request):
    """The only way to uninstall a module, also one that does not load: deletes /opt/localsiem/modules/<name>/ (404 module_not_installed when it is not there); the web reloads its modules and the collector restarts without it. Its settings (modules.<name> and the changes of its rules) stay in settings.json in case it is installed again, and so do the events and alerts it stored; the read access that root gave localsiem to its logs is not taken back. Answer: id, version and collector_restarted."""
    await asyncio.to_thread(pContext.mRequireAdmin, pRequest, True)
    try:
      dRemoved = await asyncio.to_thread(fRemove, pName)
    except CatalogError as vError:
      raise fCatalogFailure(vError) from None
    pContext.mReloadModules(pName)
    try:
      await asyncio.to_thread(pContext.mCollector, {"command": "restart"}, 5)
      vRestarted = True
    except HTTPException:
      vRestarted = False
    return {"ok": True, "id": pName, "version": dRemoved["version"], "collector_restarted": vRestarted}

  # Overview

  def fOverview() -> dict:
    dData = fRead(pContext)
    dResult = {
      "collector": {"running": dData["running"], "version": None, "started": None, "time": None},
      "modules": fSummaries(pContext, dData),
      "events_24h": 0, "blocked_24h": 0, "alerted_24h": 0,
      "alerts_24h": {"status": {}, "severity": {}}, "queue": {}, "soc": None, "heartbeat": None,
      "disk": None, "database": None, "histogram": [], "recent_alerts": []
    }
    vStorage = dData["storage"]
    if vStorage is None:
      return dResult
    dStatus = dData["status"] or {}
    dCounters = dStatus.get("counters") or {}
    dResult["collector"].update({
      "version": dStatus.get("version"), "time": fStorageToDisplay(dStatus["time"]) if dStatus.get("time") else None,
      "started": fStorageToDisplay(dCounters["started"]) if dCounters.get("started") else None
    })
    dResult["disk"] = dStatus.get("disk")
    dResult["database"] = dStatus.get("database")
    for dCounts in dData["counts"].values():
      dResult["events_24h"] += dCounts.get("events", 0)
      dResult["blocked_24h"] += dCounts.get("blocked", 0)
      dResult["alerted_24h"] += dCounts.get("alerted", 0)
    vSince = fStorageFromNow(-86400)
    dResult["alerts_24h"] = vStorage.mAlertCounts(vSince)
    dQueue = vStorage.mQueueStatistics()
    dResult["queue"] = dQueue.get("queue", {})
    dSoc = vStorage.mGetState("soc.status", None)
    dHeartbeat = vStorage.mGetState("soc.heartbeat", None)
    for dValue in (dSoc, dHeartbeat):
      if isinstance(dValue, dict):
        for vName in ("time", "last_success", "last_ok"):
          if dValue.get(vName):
            dValue[vName] = fStorageToDisplay(dValue[vName])
    dResult["soc"] = dSoc
    dResult["heartbeat"] = dHeartbeat
    try:
      ldBuckets = vStorage.mHistogram(fParseQuery(""), vSince, fStorageFromNow(0), 13, float(pContext.dSettings.get("search_timeout_seconds", 5)))
    except SearchTimeout:
      ldBuckets = []
    dResult["histogram"] = [
      {"start": fStorageToDisplay(dBucket["bucket"] + "-00-00.000"), "count": dBucket["count"], "blocked": dBucket["blocked"]}
      for dBucket in ldBuckets
    ]
    ldAlerts = vStorage.mListGroups("", 6, None)
    dResult["recent_alerts"] = [
      {
        "id": dAlert["id"], "severity": dAlert["severity"], "rule": dAlert["rule"], "ip": dAlert["ip"], "vhost": dAlert["vhost"],
        "module": dAlert["module"], "count": dAlert["count"], "status": dAlert["status"], "soc_code": dAlert.get("soc_code"),
        "last_seen": fStorageToDisplay(dAlert["last_seen"]) if dAlert.get("last_seen") else None
      }
      for dAlert in ldAlerts
    ]
    dResult["from"] = fStorageToDisplay(vSince)
    dResult["to"] = fStorageToDisplay(fStorageFromNow(0))
    return dResult

  @pApp.get("/api/overview", tags=["overview"], summary="Overview of the dashboards: last 24 hours, SOC, collector and modules")
  async def fGetOverview(pRequest: Request):
    """Events, blocks and alerts of the last 24 hours (with an hourly histogram), the last alerts, the SOC queue and heartbeat, the collector, disk and database, and the state of every module."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    return await asyncio.to_thread(fOverview)
