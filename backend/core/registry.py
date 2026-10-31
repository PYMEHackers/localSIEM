"""Registry of the modules: finds, checks and loads them.

The core imports no module by name and has no module of its own: every
module is installed by the web from the sibling project localSIEM-modules,
where its folder is mod-<name>/, into

  /opt/localsiem/modules/<name>/   (LOCALSIEM_MODULES_PATH in development
                                   copies), imported as the namespace package
                                   localsiem_modules.<name>: no __init__.py,
                                   its own files are imported relatively and
                                   the core as backend.core.

Each folder has a module.json:

  id               the folder name, without mod- in the repository:
                   [a-z][a-z0-9_]{1,31}
  version          version of the module
  core             lowest version of localSIEM it needs
  entry            "file:Class" of its Module subclass
  default_enabled  whether it runs until the administrator decides
  read_paths     folders localsiem is let read, as root (ACLs: manage.py
                   setup-modules and the installers)
  setup_option     option of manage.py setup-modules that applies its
                   requirements to its service
  settings         [{key, type, default, ...}] with type boolean, integer
                   (min, max), string (max_length), path (absolute), choice
                   (choices) or records (fields, max_items)

and locales/<language>.json with its name, its summary and the labels of its
settings, shown by the web.
"""

import copy
import importlib
import json
import re
import sys
import types
from pathlib import Path

from backend.core.config import cModulesPath, cVersion
from backend.core.timeutil import fNowStorage

cPackage = "localsiem_modules"
cNameRegex = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
cEntryRegex = re.compile(r"^([a-z][a-z0-9_]{0,63}):([A-Za-z_][A-Za-z0-9_]{0,63})$")
lLanguages = ["en-GB", "en-US", "es-AR", "es-ES"]
lSettingTypes = ["boolean", "integer", "string", "path", "choice", "records"]
cMaxString = 500
cMaxPath = 1024


class ManifestError(ValueError):
  pass


def fVersionTuple(pText: str) -> tuple:
  try:
    return tuple(int(vPart) for vPart in str(pText or "0").split("."))
  except ValueError:
    return (0,)


def fCheckSetting(pSetting: dict, pInRecords: bool = False) -> None:
  if not isinstance(pSetting, dict) or not cNameRegex.match(str(pSetting.get("key", ""))):
    raise ManifestError("invalid setting key")
  vType = pSetting.get("type")
  if vType not in lSettingTypes or (pInRecords and vType == "records"):
    raise ManifestError(f"invalid type of setting {pSetting['key']}")
  if vType == "choice" and (not isinstance(pSetting.get("choices"), list) or not pSetting["choices"]):
    raise ManifestError(f"setting {pSetting['key']} needs choices")
  if vType == "records":
    if not isinstance(pSetting.get("fields"), list) or not pSetting["fields"]:
      raise ManifestError(f"setting {pSetting['key']} needs fields")
    for dField in pSetting["fields"]:
      fCheckSetting(dField, True)


def fReadTexts(pFolder: Path) -> dict:
  # {language: texts}; a missing or broken file only loses its language.
  dTexts = {}
  for vLanguage in lLanguages:
    try:
      dLoaded = json.loads((pFolder / "locales" / (vLanguage + ".json")).read_text(encoding="utf-8"))
      if isinstance(dLoaded, dict):
        dTexts[vLanguage] = dLoaded
    except (OSError, ValueError):
      continue
  return dTexts


def fReadManifest(pFolder: Path, pId: str = "") -> dict:
  # pId: the id the module must have; by default the folder name (the
  # catalog gives it for the folders mod-<id> of the repository).
  try:
    dManifest = json.loads((pFolder / "module.json").read_text(encoding="utf-8"))
  except OSError as vError:
    raise ManifestError(f"module.json cannot be read: {vError.strerror or vError}") from None
  except ValueError as vError:
    raise ManifestError(f"module.json is not valid JSON: {vError}") from None
  if not isinstance(dManifest, dict):
    raise ManifestError("module.json must be an object")
  if dManifest.get("id") != (pId or pFolder.name):
    raise ManifestError("the id of module.json must be the folder name" + (" without mod-" if pId else ""))
  if not cEntryRegex.match(str(dManifest.get("entry", ""))):
    raise ManifestError("invalid entry (file:Class)")
  if not isinstance(dManifest.get("settings", []), list):
    raise ManifestError("settings must be a list")
  for dSetting in dManifest.get("settings", []):
    fCheckSetting(dSetting)
  if fVersionTuple(dManifest.get("core", "0")) > fVersionTuple(cVersion):
    raise ManifestError(f"it needs localSIEM {dManifest.get('core')} or newer (this is {cVersion})")
  dManifest.setdefault("version", "0")
  dManifest.setdefault("default_enabled", True)
  dManifest.setdefault("read_paths", [])
  dManifest.setdefault("setup_option", "")
  dManifest.setdefault("settings", [])
  dManifest["path"] = str(pFolder)
  dManifest["texts"] = fReadTexts(pFolder)
  return dManifest


def fListManifests() -> tuple[list[dict], list[dict]]:
  # (manifests, errors): the installed modules by name. A folder without
  # module.json is not a module and is ignored.
  ldManifests = []
  ldErrors = []
  try:
    lFolders = sorted(vEntry for vEntry in Path(cModulesPath).iterdir() if vEntry.is_dir() and (vEntry / "module.json").is_file())
  except OSError:
    return ldManifests, ldErrors
  for vFolder in lFolders:
    if not cNameRegex.match(vFolder.name):
      ldErrors.append({"id": vFolder.name[:64], "path": str(vFolder), "error": "invalid module folder name"})
      continue
    try:
      ldManifests.append(fReadManifest(vFolder))
    except ManifestError as vError:
      ldErrors.append({"id": vFolder.name, "path": str(vFolder), "error": str(vError)})
  return ldManifests, ldErrors


def fRegisterPackage() -> None:
  # localsiem_modules is a namespace package over the modules folder.
  vPackage = sys.modules.get(cPackage)
  if vPackage is None:
    vPackage = types.ModuleType(cPackage)
    vPackage.__path__ = []
    vPackage.__package__ = cPackage
    sys.modules[cPackage] = vPackage
  if str(cModulesPath) not in vPackage.__path__:
    vPackage.__path__.append(str(cModulesPath))


def fLoadClass(pManifest: dict):
  from backend.core.module import Module
  vFile, vClassName = pManifest["entry"].split(":")
  fRegisterPackage()
  vImport = f"{cPackage}.{pManifest['id']}.{vFile}"
  vClass = getattr(importlib.import_module(vImport), vClassName, None)
  if not isinstance(vClass, type) or not issubclass(vClass, Module):
    raise ManifestError(f"{pManifest['entry']} is not a localSIEM module class")
  if vClass.vName != pManifest["id"]:
    raise ManifestError(f"{pManifest['entry']} has the name {vClass.vName!r}, not {pManifest['id']!r}")
  return vClass


def fCreateModule(pManifest: dict, pSettings: dict, pMasker, pStorage):
  return fLoadClass(pManifest)(pSettings, pMasker, pStorage, pManifest)


def fCheckRequirements(pModule) -> dict:
  # mRequirements() of a module: {"time", "checks", "met"}, kept by the
  # collector (state <name>.requirements) and by the web. They are met when
  # no check is an error; a module that fails while checking them does not
  # meet them.
  try:
    ldChecks = [dict(dCheck) for dCheck in pModule.mRequirements() or [] if isinstance(dCheck, dict)]
  except Exception as vError:
    ldChecks = [{
      "id": "requirements", "status": "error", "title": "The requirements of the module could not be checked",
      "detail": f"{type(vError).__name__}: {vError}"[:500]
    }]
  return {"time": fNowStorage(), "checks": ldChecks, "met": not any(dCheck.get("status") == "error" for dCheck in ldChecks)}


def fCreateModules(pSettings: dict, pMasker, pStorage) -> tuple[dict, list[dict], list[dict]]:
  # ({name: module}, manifests, errors). A module that fails to load never
  # stops the others.
  dModules = {}
  ldManifests, ldErrors = fListManifests()
  for dManifest in ldManifests:
    try:
      dModules[dManifest["id"]] = fCreateModule(dManifest, pSettings, pMasker, pStorage)
    except Exception as vError:
      ldErrors.append({"id": dManifest["id"], "path": dManifest["path"], "error": f"{type(vError).__name__}: {vError}"[:500]})
  return dModules, ldManifests, ldErrors


def fModuleDefaults(pManifest: dict) -> dict:
  dDefaults = {"enabled": bool(pManifest.get("default_enabled", True))}
  for dSetting in pManifest.get("settings", []):
    if "default" in dSetting:
      dDefaults[dSetting["key"]] = copy.deepcopy(dSetting["default"])
  return dDefaults


def fModuleSettings(pManifest: dict, pSettings: dict) -> dict:
  # The defaults of module.json under what the administrator saved.
  dValues = fModuleDefaults(pManifest)
  dStored = (pSettings.get("modules") or {}).get(pManifest["id"]) or {}
  if isinstance(dStored, dict):
    dValues.update(copy.deepcopy(dStored))
  return dValues


# Validation of what the administrator saves


def fCleanValue(pSetting: dict, pValue):
  vType = pSetting["type"]
  vKey = pSetting["key"]
  if vType == "boolean":
    if not isinstance(pValue, bool):
      raise ValueError("invalid_setting:" + vKey)
    return pValue
  if vType == "integer":
    if isinstance(pValue, bool):
      raise ValueError("invalid_setting:" + vKey)
    try:
      vNumber = int(pValue)
    except (TypeError, ValueError):
      raise ValueError("invalid_setting:" + vKey) from None
    if vNumber != pValue and str(vNumber) != str(pValue).strip():
      raise ValueError("invalid_setting:" + vKey)
    if ("min" in pSetting and vNumber < pSetting["min"]) or ("max" in pSetting and vNumber > pSetting["max"]):
      raise ValueError("invalid_setting:" + vKey)
    return vNumber
  vText = "" if pValue is None else pValue
  if not isinstance(vText, str) or any(ord(vChar) < 32 for vChar in vText):
    raise ValueError("invalid_setting:" + vKey)
  vText = vText.strip()
  if vType == "string":
    if len(vText) > int(pSetting.get("max_length", cMaxString)):
      raise ValueError("invalid_setting:" + vKey)
    return vText
  if vType == "path":
    if len(vText) > cMaxPath or (vText and not vText.startswith("/")):
      raise ValueError("invalid_setting:" + vKey)
    return vText
  # choice
  if vText and vText not in pSetting["choices"]:
    raise ValueError("invalid_setting:" + vKey)
  return vText


def fCleanRecords(pSetting: dict, pValue) -> list[dict]:
  if not isinstance(pValue, list) or len(pValue) > int(pSetting.get("max_items", 50)):
    raise ValueError("invalid_setting:" + pSetting["key"])
  ldClean = []
  for dItem in pValue:
    if not isinstance(dItem, dict):
      raise ValueError("invalid_setting:" + pSetting["key"])
    dRecord = {}
    for dField in pSetting["fields"]:
      vValue = fCleanValue(dField, dItem.get(dField["key"]))
      if dField.get("required") and vValue in ("", None):
        raise ValueError("invalid_setting:" + pSetting["key"] + "." + dField["key"])
      if vValue not in ("", None):
        dRecord[dField["key"]] = vValue
    ldClean.append(dRecord)
  return ldClean


def fValidateSettings(pManifest: dict, pValues: dict) -> dict:
  # Only the settings of module.json are kept; ValueError("invalid_setting:
  # <key>") on the first wrong one.
  if not isinstance(pValues, dict):
    raise ValueError("invalid_settings")
  dClean = {}
  for dSetting in pManifest.get("settings", []):
    vKey = dSetting["key"]
    if vKey not in pValues:
      continue
    if dSetting["type"] == "records":
      dClean[vKey] = fCleanRecords(dSetting, pValues[vKey])
    else:
      dClean[vKey] = fCleanValue(dSetting, pValues[vKey])
  return dClean
