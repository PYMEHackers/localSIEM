"""Shared state of the web process and the request helpers."""

import hashlib
import importlib
import sys
import time
from pathlib import Path

from fastapi import HTTPException, Request

from backend.core.config import (
  cCollectorSocket, cEventsDatabaseFile, cProjectPath, cSettingsFile, cWebDatabaseFile, fGetSecret, fLoadSettings, fSettingsMtime
)
from backend.core.ipc import fRequest
from backend.core.masking import fCreateMasker
from backend.core.registry import cPackage, fCheckRequirements, fCreateModule, fListManifests
from backend.core.storage_sqlite import SqliteStorage
from backend.web.auth import Accounts, cSessionCookie, fCheckCsrf, fClientIp, fIsSameOrigin, fParseAllowList
from backend.web.webdb import WebDatabase

cFrontendPath = cProjectPath / "frontend"


class WebContext:

  def __init__(self):
    self.dSettings = fLoadSettings()
    self.vSettingsMtime = fSettingsMtime()
    self.vSettingsChecked = time.time()
    self.lAllowed = fParseAllowList(self.dSettings.get("allow_from", []))
    self.vSecret = fGetSecret("LOCALSIEM_SECRET_KEY")
    if len(self.vSecret) < 32:
      raise ValueError("LOCALSIEM_SECRET_KEY must have at least 32 characters (see /opt/localsiem/config/localsiem.env).")
    self.vDatabase = WebDatabase(cWebDatabaseFile)
    self.vDatabase.mInitialize()
    self.vAccounts = Accounts(self.vDatabase, self.dSettings, self.vSecret)
    self.vStorage = None
    self.dVersions = {}
    self.vIndex = ""
    self.mBuildIndex()
    # Modules: their module.json is read at start (the web installs and
    # uninstalls them and reloads them itself: mReloadModules); their code
    # only when a hook is needed.
    self.ldManifests, self.ldModuleErrors = fListManifests()
    self.dModuleInstances = {}
    # Requirements the web checked itself (first installation, turning a
    # module on, Reconfigure): newer than the ones the collector keeps
    # (<name>.requirements) until it checks them again.
    self.dRequirements = {}

  def mReloadModules(self, pName: str) -> None:
    # After the web installed, replaced or uninstalled pName: the module.json
    # files again, and the code of pName imported anew when a hook needs it.
    for vImported in list(sys.modules):
      if vImported == f"{cPackage}.{pName}" or vImported.startswith(f"{cPackage}.{pName}."):
        del sys.modules[vImported]
    importlib.invalidate_caches()
    self.ldManifests, self.ldModuleErrors = fListManifests()
    self.dModuleInstances = {}
    self.dRequirements.pop(pName, None)

  def mRefreshSettings(self) -> None:
    # The administrator panel and the installer write settings.json; it is
    # checked at most every 5 seconds.
    vNow = time.time()
    if vNow - self.vSettingsChecked < 5:
      return
    self.vSettingsChecked = vNow
    vMtime = fSettingsMtime()
    if vMtime != self.vSettingsMtime:
      self.mApplySettings()

  def mApplySettings(self) -> None:
    self.dSettings = fLoadSettings()
    self.vSettingsMtime = fSettingsMtime()
    self.lAllowed = fParseAllowList(self.dSettings.get("allow_from", []))
    self.vAccounts.dSettings = self.dSettings

  def mEvents(self) -> SqliteStorage:
    # The events database is created by the collector; until then searches
    # answer that there is no data yet.
    if self.vStorage is None:
      if not Path(cEventsDatabaseFile).exists():
        raise HTTPException(status_code=503, detail="collector_not_ready")
      self.vStorage = SqliteStorage(cEventsDatabaseFile, pReadOnly=True)
    return self.vStorage

  def mManifest(self, pName: str) -> dict | None:
    return next((dManifest for dManifest in self.ldManifests if dManifest["id"] == pName), None)

  def mModule(self, pName: str):
    # An instance of the module for the hooks the web uses (mDisplayRecord);
    # None when it is not installed or does not load.
    if pName not in self.dModuleInstances:
      dManifest = self.mManifest(pName)
      vModule = None
      if dManifest is not None:
        try:
          vModule = fCreateModule(dManifest, self.dSettings, fCreateMasker(self.dSettings), None)
        except Exception:
          vModule = None
      self.dModuleInstances[pName] = vModule
    return self.dModuleInstances[pName]

  def mCheckRequirements(self, pName: str, pSettings: dict | None = None) -> dict | None:
    # mRequirements() of the installed module (its code is the installed
    # copy, never the downloaded repository), on a new instance with the
    # saved settings, or with pSettings when they are about to be saved:
    # {"time", "checks", "met"}, or None when the module does not load. The
    # result with the saved settings is kept for the state of the modules.
    dManifest = self.mManifest(pName)
    if dManifest is None:
      return None
    dSettings = self.dSettings if pSettings is None else pSettings
    try:
      vModule = fCreateModule(dManifest, dSettings, fCreateMasker(dSettings), None)
    except Exception:
      return None
    dResult = fCheckRequirements(vModule)
    if pSettings is None:
      self.dRequirements[pName] = dResult
    return dResult

  def mCollector(self, pMessage: dict, pTimeout: float = 10.0) -> dict:
    try:
      return fRequest(cCollectorSocket, pMessage, pTimeout)
    except (OSError, ValueError):
      raise HTTPException(status_code=503, detail="collector_unreachable") from None

  def mBuildIndex(self) -> None:
    # Static files carry a hash of their content (?v=), so the browser never
    # mixes a new page with old scripts.
    dVersions = {}
    for vFile in sorted((cFrontendPath / "assets").rglob("*")):
      if vFile.is_file():
        dVersions["assets/" + vFile.relative_to(cFrontendPath / "assets").as_posix()] = hashlib.sha256(vFile.read_bytes()).hexdigest()[:12]
    vLocales = hashlib.sha256()
    for vFile in sorted((cFrontendPath / "locales").glob("*.json")):
      vLocales.update(vFile.read_bytes())
    dVersions["locales"] = vLocales.hexdigest()[:12]
    vText = (cFrontendPath / "index.html").read_text(encoding="utf-8")
    for vName, vVersion in dVersions.items():
      vText = vText.replace("@v:" + vName + "@", vVersion)
    self.dVersions = dVersions
    self.vIndex = vText

  # Request helpers

  def mSession(self, pRequest: Request) -> dict | None:
    return self.vAccounts.mLoadSession(pRequest.cookies.get(cSessionCookie, ""))

  def mRequireSession(self, pRequest: Request) -> dict:
    dSession = self.mSession(pRequest)
    if dSession is None:
      raise HTTPException(status_code=401, detail="authentication_required")
    return dSession

  def mRequireWrite(self, pRequest: Request) -> dict:
    dSession = self.mRequireSession(pRequest)
    if not fIsSameOrigin(pRequest) or not fCheckCsrf(dSession, pRequest):
      raise HTTPException(status_code=403, detail="csrf_failed")
    return dSession

  def mRequireAdmin(self, pRequest: Request, pWrite: bool = False) -> dict:
    dSession = self.mRequireWrite(pRequest) if pWrite else self.mRequireSession(pRequest)
    if dSession["role"] != "admin":
      raise HTTPException(status_code=403, detail="admin_required")
    return dSession

  def mClientIp(self, pRequest: Request) -> str:
    return fClientIp(pRequest)

  def mSettingsPath(self) -> Path:
    return cSettingsFile
