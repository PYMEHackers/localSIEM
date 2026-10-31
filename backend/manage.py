#!/usr/bin/env -S PYTHONDONTWRITEBYTECODE=1 python3

"""localSIEM administration from the command line (run by root or the installer).

  manage.py ensure-admin [--credentials FILE]   create the first administrator
  manage.py create-user USERNAME [--role admin|analyst] [--credentials FILE]
  manage.py reset-password USERNAME [--credentials FILE]
  manage.py reset-mfa USERNAME
  manage.py list-users
  manage.py doctor [--json]                    requirements of every enabled module, and of the ones off that have requirements
  manage.py modules                            installed modules, version, state and the requirements they lack
  manage.py read-paths                         folders the modules read
  manage.py soc-test                           send a heartbeat to the SOC
  manage.py configure-apache                   print the snippet of --configure-apache

Modules are installed only from the web (Modules › Installable). What
needs root after that, the command the web shows:

  manage.py setup-modules [OPTION...] [--no-restart]
                                               read access for localsiem to the folders of the installed modules
                                               (ACLs; adm group on Debian), the setup options given
                                               (--configure-apache) and a restart of localSIEM
  manage.py apply-setup -- OPTION              apply only the setup option of an installed module (--configure-apache)

Generated passwords are printed and, with --credentials, appended to that
file (mode 600).
"""

import sys

if sys.version_info < (3, 13):
  raise SystemExit("Python 3.13 or newer is required.")

# Run as root, too: no __pycache__ owned by root in the code of localSIEM or
# in the modules, which localsiem replaces when it updates them.
sys.dont_write_bytecode = True

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.config import cWebDatabaseFile, fLoadSettings, fReadSocToken
from backend.core.timeutil import fNowStorage


def fAccounts():
  from backend.core.config import fGetSecret
  from backend.web.auth import Accounts
  from backend.web.webdb import WebDatabase
  vDatabase = WebDatabase(cWebDatabaseFile)
  vDatabase.mInitialize()
  return Accounts(vDatabase, fLoadSettings(), fGetSecret("LOCALSIEM_SECRET_KEY") or "x" * 32)


def fWriteCredentials(pPath: str, pLines: list[str]) -> None:
  if not pPath:
    return
  vDescriptor = os.open(pPath, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
  with os.fdopen(vDescriptor, "a", encoding="utf-8") as vFile:
    os.fchmod(vFile.fileno(), 0o600)
    vFile.write("\n" + "\n".join(pLines) + "\n")


def fCreateUser(pUsername: str, pRole: str, pCredentials: str) -> None:
  from backend.web.auth import fGeneratePassword
  vAccounts = fAccounts()
  vPassword = fGeneratePassword()
  vAccounts.mCreateUser(pUsername, pRole, vPassword)
  print(f"Account {pUsername} ({pRole}) created. Password: {vPassword}")
  fWriteCredentials(pCredentials, [
    f"localSIEM web account — {fNowStorage()}",
    f"Username: {pUsername}",
    f"Role: {pRole}",
    f"Password: {vPassword}",
    "Two-step verification: set up at the first sign-in (authenticator app: «PYMEHackers localSIEM»)." if vAccounts.dSettings.get("mfa_enabled", False) else "Two-step verification: off (an administrator can turn it on in Administration › Settings)."
  ])


def fModules() -> tuple[dict, list[dict], list[dict], dict]:
  from backend.core.masking import fCreateMasker
  from backend.core.registry import fCreateModules
  dSettings = fLoadSettings()
  dModules, ldManifests, ldErrors = fCreateModules(dSettings, fCreateMasker(dSettings), None)
  return dModules, ldManifests, ldErrors, dSettings


def fReadPaths() -> list[str]:
  # Folders the installed modules read (read_paths of each module.json).
  from backend.core.registry import fListManifests
  sPaths = set()
  for dManifest in fListManifests()[0]:
    for vPath in dManifest.get("read_paths", []) or []:
      vText = str(vPath)
      if vText.startswith("/") and "\n" not in vText and ".." not in vText:
        sPaths.add(vText)
  return sorted(sPaths)


def fRunCommand(pCommand: list[str]) -> None:
  # A command of the system, as root; if it fails, manage.py stops.
  vResult = subprocess.run(pCommand, stdin=subprocess.DEVNULL)
  if vResult.returncode != 0:
    raise ValueError(f"{shlex.join(pCommand)} failed (exit status {vResult.returncode}).")


def fGrantReadAccess() -> None:
  # localsiem reads the logs of the folders its installed modules declare
  # (read_paths; /var/log/apache2 for the apache2 module). On Debian through
  # the adm group (Debian creates them root:adm 640) and, for files created
  # with another group, through ACLs; on Alpine (root:wheel, in a folder only
  # wheel can enter) through ACLs only. The ACLs also cover the files of the
  # next rotations (default ACL). Without modules there is nothing to do. The
  # installers do it at every update (fGrantLogAccess), so the modules keep
  # their access.
  lFolders = fReadPaths()
  if not lFolders:
    print("No installed module declares folders to read.")
    return
  vAlpine = Path("/etc/alpine-release").exists()
  if not vAlpine:
    fRunCommand(["usermod", "-aG", "adm", "localsiem"])
  for vFolder in lFolders:
    if not os.path.isdir(vFolder):
      print(f"{vFolder} does not exist (yet): nothing to do there.")
      continue
    try:
      vAcl = subprocess.run(["setfacl", "-m", "g:localsiem:rx", vFolder], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
      vAcl = False
    if not vAcl:
      if vAlpine:
        print(f"Warning: the file system of {vFolder} does not support ACLs; give localsiem read access to the logs of {vFolder} by hand.")
      else:
        print(f"Warning: the file system of {vFolder} does not support ACLs; localsiem reads through the adm group only.")
      continue
    fRunCommand(["setfacl", "-d", "-m", "g:localsiem:r", vFolder])
    for vFile in sorted(Path(vFolder).iterdir()):
      if vFile.is_file() and not vFile.name.startswith("."):
        fRunCommand(["setfacl", "-m", "g:localsiem:r", str(vFile)])
    print(f"localsiem can read {vFolder}.")


def fApplySetup(pOption: str) -> None:
  # The setup option of an installed module (--configure-apache of the
  # apache2 module), as root: the module applies its requirements to its
  # service (mApplySetup).
  _, ldManifests, _, dSettings = fModules()
  dManifest = next((dItem for dItem in ldManifests if dItem.get("setup_option") == pOption), None)
  if dManifest is None:
    raise ValueError(f"No installed module has the setup option {pOption}.")
  from backend.core.masking import fCreateMasker
  from backend.core.registry import fCreateModule
  fCreateModule(dManifest, dSettings, fCreateMasker(dSettings), None).mApplySetup()


def fRestartServices() -> None:
  # Both services, as the installers do: the collector reads with the new
  # permissions (the groups of a running process do not change).
  if Path("/etc/alpine-release").exists():
    fRunCommand(["rc-service", "localsiem", "restart"])
    fRunCommand(["rc-service", "localsiem-web", "restart"])
  else:
    fRunCommand(["systemctl", "restart", "localsiem.service"])
    fRunCommand(["systemctl", "restart", "localsiem-web.service"])


def fDoctorAsLocalsiem() -> None:
  # The doctor as the localsiem user: what it can read now.
  lCommand = [sys.executable, str(Path(__file__).resolve()), "doctor"]
  if Path("/etc/alpine-release").exists():
    # Alpine has no runuser: su with a shell, since localsiem has none.
    lCommand = ["su", "-s", "/bin/sh", "localsiem", "-c", shlex.join(lCommand)]
  else:
    lCommand = ["runuser", "-u", "localsiem", "--"] + lCommand
  subprocess.run(lCommand, stdin=subprocess.DEVNULL)


def fMain(pArguments: list[str]) -> None:
  vParser = argparse.ArgumentParser(description="localSIEM administration.")
  vSubparsers = vParser.add_subparsers(dest="vCommand", required=True)
  vSub = vSubparsers.add_parser("ensure-admin")
  vSub.add_argument("--credentials", default="")
  vSub = vSubparsers.add_parser("create-user")
  vSub.add_argument("username")
  vSub.add_argument("--role", default="analyst", choices=["admin", "analyst"])
  vSub.add_argument("--credentials", default="")
  vSub = vSubparsers.add_parser("reset-password")
  vSub.add_argument("username")
  vSub.add_argument("--credentials", default="")
  vSub = vSubparsers.add_parser("reset-mfa")
  vSub.add_argument("username")
  vSubparsers.add_parser("list-users")
  vSub = vSubparsers.add_parser("doctor")
  vSub.add_argument("--json", action="store_true")
  vSubparsers.add_parser("modules")
  vSubparsers.add_parser("read-paths")
  vSubparsers.add_parser("soc-test")
  vSubparsers.add_parser("configure-apache")
  # The setup options of the modules (--configure-apache) are not known
  # here: setup-modules takes them as they come.
  vSub = vSubparsers.add_parser("setup-modules")
  vSub.add_argument("--no-restart", action="store_true")
  vSub = vSubparsers.add_parser("apply-setup")
  vSub.add_argument("option")
  vArguments, lExtra = vParser.parse_known_args(pArguments)
  if lExtra and vArguments.vCommand != "setup-modules":
    vParser.error("unrecognized arguments: " + " ".join(lExtra))

  if vArguments.vCommand == "ensure-admin":
    vAccounts = fAccounts()
    if vAccounts.mUserCount() == 0:
      fCreateUser("admin", "admin", vArguments.credentials)
    else:
      print("Accounts already exist; nothing created.")
    return
  if vArguments.vCommand == "create-user":
    fCreateUser(vArguments.username, vArguments.role, vArguments.credentials)
    return
  if vArguments.vCommand == "reset-password":
    from backend.web.auth import fGeneratePassword
    vAccounts = fAccounts()
    dUser = vAccounts.mGetUserByName(vArguments.username)
    if dUser is None:
      raise ValueError(f"Unknown account: {vArguments.username}")
    vPassword = fGeneratePassword()
    vAccounts.mSetPassword(dUser["id"], vPassword, True)
    print(f"New password of {dUser['username']}: {vPassword}")
    fWriteCredentials(vArguments.credentials, [f"localSIEM password reset — {fNowStorage()}", f"Username: {dUser['username']}", f"Password: {vPassword}"])
    return
  if vArguments.vCommand == "reset-mfa":
    vAccounts = fAccounts()
    dUser = vAccounts.mGetUserByName(vArguments.username)
    if dUser is None:
      raise ValueError(f"Unknown account: {vArguments.username}")
    vAccounts.mResetTotp(dUser["id"])
    print(f"Two-step verification of {dUser['username']} reset: it is set up again at the next sign-in.")
    return
  if vArguments.vCommand == "list-users":
    vMfaEnabled = bool(fLoadSettings().get("mfa_enabled", False))
    for dUser in fAccounts().mListUsers():
      print(f"{dUser['username']:<24} {dUser['role']:<8} {'active' if dUser['is_active'] else 'disabled':<9} 2FA {('on' if dUser['totp_enabled_at'] else 'pending') if vMfaEnabled else 'off'}")
    return
  if vArguments.vCommand == "doctor":
    from backend.core.registry import fCheckRequirements
    dModules, _, ldErrors, _ = fModules()
    dReport = {}
    for vName, vModule in dModules.items():
      if not vModule.mEnabled():
        # A module that is off has no doctor; its requirements say whether it
        # can be turned on (installing it never installs what it watches).
        ldRequirements = fCheckRequirements(vModule)["checks"]
        if ldRequirements:
          dReport[vName] = {"enabled": False, "requirements": ldRequirements}
        continue
      ldSources = vModule.mDiscover()
      dReport[vName] = {"enabled": True, "sources": ldSources, "skipped": vModule.mSkipped(), "checks": vModule.mDoctor()}
    if vArguments.json:
      print(json.dumps({"modules": dReport, "errors": ldErrors}, indent=2, ensure_ascii=False))
      return
    dMarks = {"ok": "[ OK ]", "warning": "[WARN]", "error": "[FAIL]", "info": "[INFO]"}

    def fPrintChecks(ldChecks: list[dict]) -> None:
      for dCheck in ldChecks:
        print(f"{dMarks.get(dCheck.get('status'), '[    ]')} {dCheck.get('title', '')}")
        if dCheck.get("detail"):
          print(f"       {dCheck['detail']}")
        if dCheck.get("fix") and dCheck.get("status") != "ok":
          for vLine in dCheck["fix"].splitlines():
            print(f"         {vLine}")

    for dError in ldErrors:
      print(f"[FAIL] Module {dError['id']} not loaded: {dError['error']}")
    if not dModules:
      print("No modules installed in /opt/localsiem/modules: localSIEM reads no logs yet. Install them from the web (Modules › Installable).")
    for vName, dModuleReport in dReport.items():
      if not dModuleReport["enabled"]:
        print(f"localSIEM doctor — module {vName} (off): what it needs before it can be turned on")
        fPrintChecks(dModuleReport["requirements"])
        continue
      print(f"localSIEM doctor — module {vName}")
      fPrintChecks(dModuleReport["checks"])
      if dModuleReport["sources"]:
        print("Sources:")
      for dSource in dModuleReport["sources"]:
        print(f"  {dSource['kind']:<7} {dSource['path']}" + (f"  (vhost {dSource['vhost']})" if dSource.get("vhost") else ""))
    return
  if vArguments.vCommand == "modules":
    from backend.core.registry import fCheckRequirements
    dModules, ldManifests, ldErrors, _ = fModules()
    for dManifest in ldManifests:
      vModule = dModules.get(dManifest["id"])
      vState = "not loaded" if vModule is None else ("enabled" if vModule.mEnabled() else "disabled")
      print(f"{dManifest['id']:<16} {dManifest.get('version', ''):<10} {vState:<10} {dManifest['path']}")
      # What the server lacks for it: off, it cannot be turned on until then.
      if vModule is not None:
        ldMissing = [dCheck for dCheck in fCheckRequirements(vModule)["checks"] if dCheck.get("status") == "error"]
        if ldMissing:
          print(f"{'':<16} requirements missing: " + "; ".join(str(dCheck.get("title") or dCheck.get("id") or "") for dCheck in ldMissing))
    for dError in ldErrors:
      print(f"{dError['id']:<16} {'':<10} {'':<10} {'error':<10} {dError['error']}")
    return
  if vArguments.vCommand == "read-paths":
    for vPath in fReadPaths():
      print(vPath)
    return
  if vArguments.vCommand == "soc-test":
    from backend.core.soc import SocClient, SocError
    dSettings = fLoadSettings()
    vToken = fReadSocToken()
    if not vToken:
      raise ValueError("No SOC token configured (/opt/localsiem/config/soc-token).")
    try:
      SocClient(dSettings["soc_url"], vToken, dSettings.get("soc_ca_file", "")).mHeartbeat()
      print(f"The SOC ({dSettings['soc_url']}) accepted the heartbeat.")
    except SocError as vError:
      raise ValueError(f"The SOC answered HTTP {vError.vStatus} {vError.vCode}") from None
    return
  if vArguments.vCommand == "configure-apache":
    # The installed module that applies --configure-apache: apache2.
    dModules, ldManifests, _, _ = fModules()
    dManifest = next((dItem for dItem in ldManifests if dItem.get("setup_option") == "--configure-apache"), None)
    vModule = dModules.get(dManifest["id"] if dManifest is not None else "apache2")
    if vModule is None:
      raise ValueError("No installed module applies --configure-apache: install the apache2 module from the web (Modules › Installable).")
    print(vModule.mSetupSnippet())
    return
  if vArguments.vCommand == "setup-modules":
    # What the web asks root to run after installing a module, and after
    # Reconfigure finds its requirements; the installers run it with
    # --no-restart. Idempotent.
    if os.geteuid() != 0:
      raise ValueError("setup-modules changes the permissions of the logs of other services and restarts localSIEM: run it as root.")
    lOptions = [vOption for vOption in lExtra if vOption != "--"]
    _, ldManifests, _, _ = fModules()
    sOptions = {dManifest["setup_option"] for dManifest in ldManifests if dManifest.get("setup_option")}
    for vOption in lOptions:
      if vOption not in sOptions:
        raise ValueError(f"No installed module has the setup option {vOption} (the installed ones have: {', '.join(sorted(sOptions)) or 'none'}).")
    # The setup options first: they may create logs (--configure-apache
    # creates localsiem_access.log and modsec_audit.log) that the read
    # access then covers.
    for vOption in lOptions:
      fApplySetup(vOption)
    fGrantReadAccess()
    if vArguments.no_restart:
      return
    fRestartServices()
    print("localSIEM restarted (services localsiem and localsiem-web).")
    print("\nlocalSIEM doctor (as the localsiem user):")
    fDoctorAsLocalsiem()
    return
  if vArguments.vCommand == "apply-setup":
    if os.geteuid() != 0:
      raise ValueError("apply-setup changes the configuration of other services: run it as root.")
    fApplySetup(vArguments.option)
    return


if __name__ == "__main__":
  try:
    fMain(sys.argv[1:])
  except (OSError, ValueError) as vError:
    print(f"Error: {vError}", file=sys.stderr)
    raise SystemExit(1) from vError
