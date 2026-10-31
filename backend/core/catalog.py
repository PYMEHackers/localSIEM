"""Catalog of installable modules: the localSIEM-modules repository.

Modules are installed, updated and uninstalled only from the web (Modules ›
Installable, and Update and Uninstall on each module of Modules › Installed),
as the localsiem user, from one archive of the repository: by default the
branch main of
https://github.com/PYMEHackers/localSIEM-modules (settings
modules_repository.url and .ref; a url ending in .tar.gz is taken as the
archive itself). That repository has no installer of its own.

  - The archive is unpacked with the "data" filter of tarfile: no absolute
    paths, nothing out of the folder, no links out of it, no devices.
  - A module is a folder mod-<id> with a module.json at the top of the
    repository; the prefix is only of that folder: installed, the module is
    /opt/localsiem/modules/<id>/. A folder without the prefix is not a
    module. It is checked like an installed one (fReadManifest) before
    anything is copied, and its code is never imported here.
  - Installing copies the folder, without tests/ and __pycache__, next to
    the installed one and swaps them with a rename: the collector never sees
    a half-copied module.
    Uninstalling moves the installed folder away with a rename and deletes
    it (fRemove); the settings of the module stay in settings.json.
  - Letting localsiem read the logs of a module, and its setup option
    (--configure-apache), need root: the web only shows the command that
    does it (fRootCommand: manage.py setup-modules).
"""

import fcntl
import json
import os
import re
import shlex
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from backend.core.config import cModulesPath, cProjectPath, cRunPath, cVersion
from backend.core.registry import ManifestError, cNameRegex, fListManifests, fReadManifest, fVersionTuple

cDefaultRepository = "https://github.com/PYMEHackers/localSIEM-modules"
cDefaultRef = "main"
# The folder of each module in the repository is mod-<id>.
cFolderPrefix = "mod-"
cMaxArchiveBytes = 50 * 1024 * 1024
cMaxUnpackedBytes = 200 * 1024 * 1024
cMaxMembers = 20000
cTimeoutSeconds = 30
lSchemes = ["https", "http", "file"]
cRefRegex = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
cCommitRegex = re.compile(r"^[0-9a-f]{40}$")
cGitHubApi = "https://api.github.com/repos"
# Sent with every download: neither GitHub nor a proxy on the way may answer
# with a copy kept from before.
dNoCacheHeaders = {"Cache-Control": "no-cache", "Pragma": "no-cache"}


class CatalogError(ValueError):
  pass


def fRepository(pSettings: dict) -> tuple[str, str]:
  dRepository = pSettings.get("modules_repository") or {}
  return str(dRepository.get("url") or cDefaultRepository).rstrip("/"), str(dRepository.get("ref") or cDefaultRef)


def fCheckRepository(pUrl: str, pRef: str) -> None:
  if urllib.parse.urlsplit(pUrl).scheme.lower() not in lSchemes:
    raise CatalogError("invalid_repository_url")
  if not cRefRegex.match(pRef) or ".." in pRef:
    raise CatalogError("invalid_ref")


def fArchiveUrl(pUrl: str, pRef: str) -> str:
  # A repository (GitHub: /archive/<branch or tag>.tar.gz) or an archive.
  fCheckRepository(pUrl, pRef)
  if pUrl.endswith((".tar.gz", ".tgz")):
    return pUrl
  return f"{pUrl}/archive/{pRef}.tar.gz"


def fResolveRef(pUrl: str, pRef: str) -> str:
  # GitHub keeps what it serves of a branch in its cache for a few minutes
  # after a push, so a download right after it could bring the version
  # before. For a repository of github.com its API (which is not cached) is
  # asked for the commit of the branch or tag, and the archive of that
  # commit, which never changes, is the one downloaded. Another repository,
  # an archive, a ref that already is a commit, or an API that does not
  # answer (without a token it allows 60 requests per hour from each IP
  # address) keep pRef.
  fCheckRepository(pUrl, pRef)
  vParts = urllib.parse.urlsplit(pUrl)
  if (vParts.hostname or "").lower() != "github.com" or pUrl.endswith((".tar.gz", ".tgz")) or cCommitRegex.match(pRef):
    return pRef
  lPath = [vPart for vPart in vParts.path.split("/") if vPart]
  if len(lPath) != 2:
    return pRef
  vOwner = urllib.parse.quote(lPath[0], safe="")
  vName = urllib.parse.quote(lPath[1].removesuffix(".git"), safe="")
  vRequest = urllib.request.Request(
    f"{cGitHubApi}/{vOwner}/{vName}/commits/{urllib.parse.quote(pRef, safe='/')}",
    headers={"Accept": "application/vnd.github.sha", **dNoCacheHeaders}
  )
  try:
    with urllib.request.urlopen(vRequest, timeout=cTimeoutSeconds) as vResponse:
      vCommit = vResponse.read(100).decode("ascii", "replace").strip()
  except (urllib.error.URLError, OSError, ValueError):
    return pRef
  return vCommit if cCommitRegex.match(vCommit) else pRef


def fDownload(pUrl: str, pFolder: Path) -> Path:
  # Unpacks the archive into pFolder and returns the folder of the
  # repository in it (GitHub puts everything in <repository>-<ref>/).
  if urllib.parse.urlsplit(pUrl).scheme.lower() not in lSchemes:
    raise CatalogError("invalid_repository_url")
  vArchive = pFolder / "repository.tar.gz"
  vTotal = 0
  try:
    vRequest = urllib.request.Request(pUrl, headers=dNoCacheHeaders)
    with urllib.request.urlopen(vRequest, timeout=cTimeoutSeconds) as vResponse, vArchive.open("wb") as vFile:
      while True:
        vChunk = vResponse.read(1024 * 1024)
        if not vChunk:
          break
        vTotal += len(vChunk)
        if vTotal > cMaxArchiveBytes:
          raise CatalogError("archive_too_big")
        vFile.write(vChunk)
  except urllib.error.HTTPError as vError:
    raise CatalogError(f"download_failed: HTTP {vError.code}") from None
  except (urllib.error.URLError, OSError) as vError:
    raise CatalogError(f"download_failed: {getattr(vError, 'reason', None) or vError}") from None
  vTarget = pFolder / "repository"
  vTarget.mkdir()
  try:
    with tarfile.open(vArchive, "r:gz") as vTar:
      lMembers = vTar.getmembers()
      if len(lMembers) > cMaxMembers or sum(vMember.size for vMember in lMembers if vMember.isfile()) > cMaxUnpackedBytes:
        raise CatalogError("archive_too_big")
      vTar.extractall(vTarget, members=lMembers, filter="data")
  except (tarfile.TarError, OSError, EOFError) as vError:
    raise CatalogError(f"invalid_archive: {vError}") from None
  finally:
    vArchive.unlink(missing_ok=True)
  lTop = list(vTarget.iterdir())
  if len(lTop) == 1 and lTop[0].is_dir() and not lTop[0].is_symlink() and not (lTop[0] / "module.json").exists():
    return lTop[0]
  return vTarget


def fModuleFolders(pRoot: Path) -> list[tuple[str, Path]]:
  # (id, folder) of each module of the repository: the folders mod-<id> with
  # a module.json. A folder without the prefix (a copy of the repository
  # older than localSIEM 2.2.0) is not a module.
  return sorted(
    (vEntry.name[len(cFolderPrefix):], vEntry) for vEntry in pRoot.iterdir()
    if vEntry.name.startswith(cFolderPrefix) and vEntry.is_dir() and not vEntry.is_symlink() and (vEntry / "module.json").is_file()
  )


def fCatalog(pRoot: Path) -> list[dict]:
  # Each module of the repository and what is installed of it. action:
  # install, update, reinstall, downgrade, incompatible (needs a newer
  # localSIEM) or invalid. newer: the module is installed and the repository
  # has a newer version of it (also one that this localSIEM cannot install).
  dInstalled = {dManifest["id"]: dManifest for dManifest in fListManifests()[0]}
  ldModules = []
  for vId, vFolder in fModuleFolders(pRoot):
    dItem = {
      "id": vId, "version": "", "core": "", "texts": {}, "read_paths": [], "setup_option": "",
      "installed": None, "newer": False, "action": "install", "error": None
    }
    try:
      dRaw = json.loads((vFolder / "module.json").read_text(encoding="utf-8"))
      if isinstance(dRaw, dict):
        dItem["version"] = str(dRaw.get("version") or "")
        dItem["core"] = str(dRaw.get("core") or "")
    except (OSError, ValueError):
      pass
    try:
      if not cNameRegex.match(vId):
        raise ManifestError("invalid module folder name")
      dManifest = fReadManifest(vFolder, vId)
      dItem.update({
        "version": str(dManifest["version"]), "texts": dManifest["texts"],
        "read_paths": list(dManifest["read_paths"]), "setup_option": dManifest["setup_option"]
      })
    except ManifestError as vError:
      dItem["error"] = str(vError)
      dItem["action"] = "incompatible" if fVersionTuple(dItem["core"]) > fVersionTuple(cVersion) else "invalid"
    dCurrent = dInstalled.get(vId)
    if dCurrent is not None:
      dItem["installed"] = str(dCurrent.get("version") or "")
      dItem["newer"] = fVersionTuple(dItem["version"]) > fVersionTuple(dItem["installed"])
    if dItem["error"] is None and dItem["installed"] is not None:
      vNew = fVersionTuple(dItem["version"])
      vOld = fVersionTuple(dItem["installed"])
      dItem["action"] = "update" if vNew > vOld else ("reinstall" if vNew == vOld else "downgrade")
    ldModules.append(dItem)
  return ldModules


class InstallLock:
  # One installation or uninstallation at a time (two administrators, or two
  # tabs, at once): a lock file in the modules folder.

  def __enter__(self):
    try:
      cModulesPath.mkdir(parents=True, exist_ok=True)
      self.vFile = open(cModulesPath / ".install.lock", "a")
    except OSError as vError:
      raise CatalogError(f"install_failed: {vError}") from None
    try:
      fcntl.flock(self.vFile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      self.vFile.close()
      raise CatalogError("install_running") from None
    return self

  def __exit__(self, *pArguments):
    fcntl.flock(self.vFile, fcntl.LOCK_UN)
    self.vFile.close()


def fInstall(pRoot: Path, pName: str) -> dict:
  # Installs (or replaces) one module of an unpacked repository: its folder
  # mod-<name> becomes /opt/localsiem/modules/<name>. Returns its manifest,
  # with "previous": the version replaced, or None (first installation), and
  # "access_changed": whether its read_paths or its setup_option changed (a
  # first installation always changes them), so root has to run
  # setup-modules again.
  if not cNameRegex.match(pName):
    raise CatalogError("invalid_module_name")
  vSource = pRoot / (cFolderPrefix + pName)
  if vSource.is_symlink() or not (vSource / "module.json").is_file():
    raise CatalogError("module_not_found")
  try:
    fReadManifest(vSource, pName)
  except ManifestError as vError:
    raise CatalogError(f"invalid_module: {vError}") from None
  vTarget = cModulesPath / pName
  vPrevious = None
  # What the replaced copy let localsiem read; None when it is unknown.
  lPreviousAccess = None
  if (vTarget / "module.json").is_file():
    try:
      dPrevious = json.loads((vTarget / "module.json").read_text(encoding="utf-8"))
      vPrevious = str(dPrevious.get("version") or "")
      lPreviousAccess = [sorted(str(vPath) for vPath in dPrevious.get("read_paths") or []), str(dPrevious.get("setup_option") or "")]
    except (OSError, ValueError, AttributeError, TypeError):
      vPrevious = ""

  def fIgnore(pDirectory: str, lNames: list[str]) -> list[str]:
    # tests/ of the module and caches stay out; links are never copied.
    lIgnored = []
    for vName in lNames:
      if vName == "__pycache__" or vName.endswith(".pyc") or os.path.islink(os.path.join(pDirectory, vName)):
        lIgnored.append(vName)
      elif vName == "tests" and Path(pDirectory) == vSource:
        lIgnored.append(vName)
    return lIgnored

  # The staging folder is inside the modules folder, so the swap is a rename
  # on the same file system; it has no module.json, so it is not a module.
  # The copy in it already has the name of the installed folder (<name>).
  try:
    vStaging = Path(tempfile.mkdtemp(prefix=".staging-", dir=cModulesPath))
  except OSError as vError:
    raise CatalogError(f"install_failed: {vError}") from None
  try:
    shutil.copytree(vSource, vStaging / pName, ignore=fIgnore)
    try:
      fReadManifest(vStaging / pName)
    except ManifestError as vError:
      raise CatalogError(f"invalid_module: {vError}") from None
    if vTarget.exists():
      os.rename(vTarget, vStaging / ("old-" + pName))
    os.rename(vStaging / pName, vTarget)
  except OSError as vError:
    raise CatalogError(f"install_failed: {vError}") from None
  finally:
    shutil.rmtree(vStaging, ignore_errors=True)
  dManifest = fReadManifest(vTarget)
  dManifest["previous"] = vPrevious
  try:
    lAccess = [sorted(str(vPath) for vPath in dManifest["read_paths"] or []), str(dManifest["setup_option"] or "")]
  except TypeError:
    lAccess = None
  dManifest["access_changed"] = lPreviousAccess is None or lAccess is None or lAccess != lPreviousAccess
  return dManifest


def fRemove(pName: str) -> dict:
  # Uninstalls one installed module, also one that does not load: its folder
  # /opt/localsiem/modules/<name> goes into a staging folder with a rename (the
  # collector never sees half a module) and is deleted there. Only the modules
  # folder is touched. Returns {"id", "version"}.
  if not cNameRegex.match(pName):
    raise CatalogError("invalid_module_name")
  vTarget = cModulesPath / pName
  with InstallLock():
    if not (vTarget / "module.json").is_file():
      raise CatalogError("module_not_installed")
    try:
      vVersion = str(json.loads((vTarget / "module.json").read_text(encoding="utf-8")).get("version") or "")
    except (OSError, ValueError, AttributeError):
      vVersion = ""
    try:
      vStaging = Path(tempfile.mkdtemp(prefix=".staging-", dir=cModulesPath))
    except OSError as vError:
      raise CatalogError(f"uninstall_failed: {vError}") from None
    try:
      os.rename(vTarget, vStaging / ("old-" + pName))
    except OSError as vError:
      raise CatalogError(f"uninstall_failed: {vError}") from None
    finally:
      shutil.rmtree(vStaging, ignore_errors=True)
  return {"id": pName, "version": vVersion}


def fFetchCatalog(pSettings: dict) -> list[dict]:
  vUrl, vRef = fRepository(pSettings)
  cRunPath.mkdir(parents=True, exist_ok=True)
  with tempfile.TemporaryDirectory(prefix="catalog.", dir=cRunPath) as vFolder:
    return fCatalog(fDownload(fArchiveUrl(vUrl, fResolveRef(vUrl, vRef)), Path(vFolder)))


def fFetchAndInstall(pSettings: dict, pName: str) -> dict:
  vUrl, vRef = fRepository(pSettings)
  cRunPath.mkdir(parents=True, exist_ok=True)
  with InstallLock():
    with tempfile.TemporaryDirectory(prefix="catalog.", dir=cRunPath) as vFolder:
      return fInstall(fDownload(fArchiveUrl(vUrl, fResolveRef(vUrl, vRef)), Path(vFolder)), pName)


def fRootCommand() -> str:
  # What needs root once a module is installed from the web, or once
  # Reconfigure finds its requirements: manage.py setup-modules, of this same
  # localSIEM, lets localsiem read the folders of the installed modules
  # (read_paths, also the files of the next rotations), applies the setup
  # options added to it (the web suggests the one of the module,
  # --configure-apache) and restarts localSIEM. Idempotent.
  return shlex.join([sys.executable, str(cProjectPath / "backend" / "manage.py"), "setup-modules"])
