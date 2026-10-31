#!/usr/bin/env -S PYTHONDONTWRITEBYTECODE=1 python3

import sys

if sys.version_info < (3, 13):
  raise SystemExit("Python 3.13 or newer is required.")

import argparse
import ipaddress
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

cProjectPath = Path(__file__).resolve().parent.parent
cConfigPath = Path("/opt/localsiem/config")
cEnvironmentPath = cConfigPath / "localsiem.env"
cInstallEnvironmentPath = cConfigPath / "install.env"
cCertificatePath = Path("/opt/localsiem/certificates")
cCredentialsPath = Path("/root/webapp-credentials.txt")
cLetsEncryptHook = Path("/etc/letsencrypt/renewal-hooks/deploy/localsiem.sh")
sys.path.insert(0, str(cProjectPath))

from backend.core.config import cWebPort, fRemoveSettings, fSaveSettings, fSaveSocToken
from backend.core.timeutil import fNowStorage

# Values remembered between runs, so an update without options keeps them.
# Two-step verification is not one of them: it is turned on and off in the
# web (settings.json keeps it), and the installer only changes it when it is
# given --enable-mfa or --disable-mfa.
lRemembered = [
  "port", "allow_from", "soc_url", "soc_ca_file", "domain",
  "retention_days", "max_disk"
]
# Options of the remote HTTP input, removed: localSIEM only reads the logs of
# its own server.
lRemovedOptions = ["--enable-http-input", "--disable-http-input", "--mode"]
# What older versions kept for it in localsiem.env and settings.json.
lRemovedEnvironment = ["LOCALSIEM_USERNAME", "LOCALSIEM_PASSWORD_HASH", "LOCALSIEM_MODE"]
lRemovedSettings = ["http_input"]


def fReadKeyValueFile(pPath: Path, pPrefix: str) -> dict[str, str]:
  dValues = {}
  if pPath.exists():
    for vLine in pPath.read_text(encoding="utf-8").splitlines():
      if vLine and not vLine.startswith("#"):
        vName, vSeparator, vValue = vLine.partition("=")
        if not vSeparator or not vName.startswith(pPrefix):
          raise ValueError(f"Invalid line in {pPath}")
        dValues[vName] = vValue
  return dValues


def fReadEnvironment() -> dict[str, str]:
  return fReadKeyValueFile(cEnvironmentPath, "LOCALSIEM_")


def fReadInstallEnvironment() -> dict[str, str]:
  return {vName[len("LOCALSIEM_INSTALL_"):].lower(): vValue for vName, vValue in fReadKeyValueFile(cInstallEnvironmentPath, "LOCALSIEM_INSTALL_").items()}


def fParseSize(pValue: str) -> int:
  # 0 or auto (lesser of 15 % of the disk and 10 GB), bytes, or 500M / 10G.
  vValue = str(pValue or "").strip().lower()
  if vValue in ("", "0", "auto"):
    return 0
  vMatch = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]?)b?", vValue)
  if not vMatch:
    raise ValueError("Invalid --max-disk (examples: 2G, 500M, auto).")
  vNumber = float(vMatch.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}[vMatch.group(2)]
  if vNumber < 100 * 1024 ** 2:
    raise ValueError("--max-disk must be at least 100M.")
  return int(vNumber)


def fGetArguments():
  vParser = argparse.ArgumentParser(description="Configure a localSIEM deployment. Values given once are remembered in /opt/localsiem/config/install.env; existing credentials are kept.")
  vParser.add_argument("--allow-from", dest="vAllowFrom")
  vParser.add_argument("--soc-url", dest="vSocUrl")
  vParser.add_argument("--soc-token", dest="vSocToken")
  vParser.add_argument("--soc-ca-file", dest="vSocCaFile")
  vParser.add_argument("--domain", dest="vDomain")
  vParser.add_argument("--certificate", dest="vCertificate", type=Path)
  vParser.add_argument("--private-key", dest="vPrivateKey", type=Path)
  # Read by the shell installer, which downloads localSIEM; nothing to do here.
  vParser.add_argument("--ref", dest="vRef")
  vParser.add_argument("--source-url", dest="vSourceUrl")
  # Where the web installs the modules from (settings modules_repository).
  vParser.add_argument("--modules-repository", dest="vModulesRepository")
  vParser.add_argument("--modules-ref", dest="vModulesRef")
  vParser.add_argument("--retention-days", dest="vRetentionDays", type=int)
  vParser.add_argument("--max-disk", dest="vMaxDisk")
  vParser.add_argument("--disable-mfa", dest="vDisableMfa", action="store_true")
  vParser.add_argument("--enable-mfa", dest="vEnableMfa", action="store_true")
  vParser.add_argument("--rotate-credentials", dest="vRotateCredentials", action="store_true")
  vParser.add_argument("--check-arguments", dest="vCheckArguments", action="store_true", help=argparse.SUPPRESS)
  for vArgument in sys.argv[1:]:
    if vArgument.split("=", 1)[0] in lRemovedOptions:
      raise ValueError(vArgument.split("=", 1)[0] + " no longer exists: localSIEM has no remote HTTP input, it only reads the logs of its own server.")
  vArguments = vParser.parse_args()
  if vArguments.vModulesRepository is not None and not re.fullmatch(r"(https|http|file)://[^\s]{1,2000}", vArguments.vModulesRepository):
    raise ValueError("--modules-repository must be a URL (https://; http:// or file:// for a local mirror) of a repository or of a .tar.gz archive.")
  if vArguments.vModulesRef is not None and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}", vArguments.vModulesRef) or ".." in vArguments.vModulesRef):
    raise ValueError("Invalid --modules-ref (a branch or a tag).")
  dRemembered = fReadInstallEnvironment() if os.geteuid() == 0 else {}
  # The web always listens on 10443 (a port given to older versions is not used).
  vArguments.vPort = cWebPort
  if vArguments.vAllowFrom is None:
    vArguments.vAllowFrom = dRemembered.get("allow_from", "")
  lAllowed = []
  for vEntry in vArguments.vAllowFrom.replace(" ", ",").split(","):
    if vEntry.strip():
      try:
        lAllowed.append(str(ipaddress.ip_network(vEntry.strip(), strict=False)) if "/" in vEntry else str(ipaddress.ip_address(vEntry.strip())))
      except ValueError:
        raise ValueError(f"Invalid IP or CIDR in --allow-from: {vEntry.strip()}") from None
  vArguments.lAllowFrom = lAllowed
  vArguments.vSocUrl = (vArguments.vSocUrl or dRemembered.get("soc_url") or "https://soc.pymehackers.com").rstrip("/")
  if not vArguments.vSocUrl.startswith("https://"):
    raise ValueError("--soc-url must start with https://")
  if vArguments.vSocCaFile is None:
    vArguments.vSocCaFile = dRemembered.get("soc_ca_file", "")
  if vArguments.vSocCaFile and not Path(vArguments.vSocCaFile).is_file():
    raise ValueError("--soc-ca-file does not exist.")
  if vArguments.vSocToken is not None and (len(vArguments.vSocToken.strip()) < 16 or any(vChar.isspace() for vChar in vArguments.vSocToken.strip())):
    raise ValueError("Invalid --soc-token.")
  vArguments.vDomain = vArguments.vDomain or dRemembered.get("domain") or socket.getfqdn() or socket.gethostname()
  if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", vArguments.vDomain):
    raise ValueError("Provide --domain with a DNS hostname or an IPv4 address.")
  if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", vLabel) for vLabel in vArguments.vDomain.split(".")):
    raise ValueError("Invalid domain label")
  if bool(vArguments.vCertificate) != bool(vArguments.vPrivateKey):
    raise ValueError("Provide --certificate and --private-key together.")
  for vPath in [vArguments.vCertificate, vArguments.vPrivateKey]:
    if vPath is not None and not vPath.is_file():
      raise ValueError("Certificate or private key file does not exist.")
  vArguments.vRetentionDays = vArguments.vRetentionDays or int(dRemembered.get("retention_days") or 90)
  if not 1 <= vArguments.vRetentionDays <= 3650:
    raise ValueError("Invalid --retention-days.")
  vArguments.vMaxDisk = vArguments.vMaxDisk if vArguments.vMaxDisk is not None else dRemembered.get("max_disk", "auto")
  vArguments.vMaxDiskBytes = fParseSize(vArguments.vMaxDisk)
  if vArguments.vDisableMfa and vArguments.vEnableMfa:
    raise ValueError("Do not combine --disable-mfa and --enable-mfa.")
  if vArguments.vDisableMfa:
    vArguments.vMfa = False
  elif vArguments.vEnableMfa:
    vArguments.vMfa = True
  else:
    # Neither of them: the setting of the web is kept (off on a new
    # installation).
    vArguments.vMfa = None
  return vArguments


def fGetTimestamp() -> str:
  # The credentials file is a record: storage format, in UTC.
  return fNowStorage()


def fWritePrivateFile(pPath: Path, pText: str) -> None:
  vDescriptor = os.open(pPath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
  with os.fdopen(vDescriptor, "w", encoding="utf-8") as vFile:
    os.fchmod(vFile.fileno(), 0o600)
    vFile.write(pText)


def fAppendCredentials(pLines: list[str]) -> None:
  vDescriptor = os.open(cCredentialsPath, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
  with os.fdopen(vDescriptor, "a", encoding="utf-8") as vFile:
    os.fchmod(vFile.fileno(), 0o600)
    vFile.write("\n" + "\n".join(pLines) + "\n")


def fCheckPort(pPort: int) -> None:
  # localsiem-web is stopped by the installer before this check: anything still
  # listening there belongs to another service of the server.
  for vFamily, vAddress in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    try:
      with socket.socket(vFamily, socket.SOCK_STREAM) as vSocket:
        vSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if vFamily == socket.AF_INET6:
          vSocket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        vSocket.bind((vAddress, pPort))
    except OSError as vError:
      if vFamily == socket.AF_INET6 and vError.errno in (97, 99):
        continue
      raise ValueError(f"Port {pPort} is already in use by another service: the localSIEM web always listens on it. Free it and run the installer again.") from None


def fRememberArguments(pArguments, pTemporaryPath: Path) -> None:
  dValues = {
    "port": str(pArguments.vPort),
    "allow_from": ",".join(pArguments.lAllowFrom),
    "soc_url": pArguments.vSocUrl,
    "soc_ca_file": pArguments.vSocCaFile or "",
    "domain": pArguments.vDomain,
    "retention_days": str(pArguments.vRetentionDays),
    "max_disk": str(pArguments.vMaxDisk or "auto")
  }
  vText = "# Options of the last localSIEM installation; an update without options keeps them.\n"
  vText += "\n".join("LOCALSIEM_INSTALL_" + vName.upper() + "=" + dValues[vName] for vName in lRemembered) + "\n"
  fWritePrivateFile(pTemporaryPath / "install.env", vText)
  os.replace(pTemporaryPath / "install.env", cInstallEnvironmentPath)


def fConfigureSettings(pArguments) -> None:
  fSaveSettings({
    "port": pArguments.vPort,
    "listen": "0.0.0.0",
    "allow_from": pArguments.lAllowFrom,
    "soc_url": pArguments.vSocUrl,
    "soc_ca_file": pArguments.vSocCaFile or "",
    "retention_days": pArguments.vRetentionDays,
    "max_disk_bytes": pArguments.vMaxDiskBytes
  })
  # The remote HTTP input (removed) that older versions kept there.
  fRemoveSettings(lRemovedSettings)
  if pArguments.vMfa is not None:
    fSaveSettings({"mfa_enabled": pArguments.vMfa})
  # Given once, kept by the next updates (settings.json keeps it).
  dRepository = {}
  if pArguments.vModulesRepository:
    dRepository["url"] = pArguments.vModulesRepository.rstrip("/")
  if pArguments.vModulesRef:
    dRepository["ref"] = pArguments.vModulesRef
  if dRepository:
    fSaveSettings({"modules_repository": dRepository})
  if pArguments.vSocToken:
    # The token never goes to the installation log.
    fSaveSocToken(pArguments.vSocToken.strip())


def fConfigureCredentials(pArguments, pEnvironment: dict[str, str], pTemporaryPath: Path) -> list[list[str]]:
  # Returns the blocks for /root/webapp-credentials.txt instead of writing
  # them: fMain writes them after the block of the administrator, so the file
  # lists the admin account first.
  if pEnvironment and not pEnvironment.get("LOCALSIEM_SECRET_KEY") and not pArguments.vRotateCredentials:
    raise ValueError("Incomplete existing credentials. Use --rotate-credentials to replace them explicitly.")
  lBlocks = []
  vNewSecret = not pEnvironment or pArguments.vRotateCredentials
  if vNewSecret:
    pEnvironment["LOCALSIEM_SECRET_KEY"] = secrets.token_hex(32)
  # The account and the mode of the remote HTTP input (removed) that older
  # versions kept here.
  for vName in lRemovedEnvironment:
    pEnvironment.pop(vName, None)
  pEnvironment["LOCALSIEM_DOMAIN"] = pArguments.vDomain
  if vNewSecret:
    lBlocks.append([
      "localSIEM credentials — " + fGetTimestamp(),
      "System user: localsiem (locked; no system password)",
      "JWT signing secret: " + pEnvironment["LOCALSIEM_SECRET_KEY"]
    ])
  fWritePrivateFile(
    pTemporaryPath / "localsiem.env",
    "\n".join(vName + "=" + vValue for vName, vValue in pEnvironment.items()) + "\n"
  )
  os.replace(pTemporaryPath / "localsiem.env", cEnvironmentPath)
  os.environ["LOCALSIEM_SECRET_KEY"] = pEnvironment["LOCALSIEM_SECRET_KEY"]
  return lBlocks


def fConfigureCertificates(pArguments, pTemporaryPath: Path) -> str:
  # Returns where the certificate came from.
  vCertificate = pTemporaryPath / "fullchain.pem"
  vPrivateKey = pTemporaryPath / "privkey.pem"
  vLetsEncryptPath = Path("/etc/letsencrypt/live") / pArguments.vDomain
  vSource = "existing"
  try:
    ipaddress.ip_address(pArguments.vDomain)
    vSubjectAlternativeName = "IP:" + pArguments.vDomain
    vCheckOption = "-checkip"
  except ValueError:
    vSubjectAlternativeName = "DNS:" + pArguments.vDomain
    vCheckOption = "-checkhost"
  if pArguments.vCertificate:
    shutil.copyfile(pArguments.vCertificate, vCertificate)
    shutil.copyfile(pArguments.vPrivateKey, vPrivateKey)
    vSource = "provided"
  elif (vLetsEncryptPath / "fullchain.pem").is_file() and (vLetsEncryptPath / "privkey.pem").is_file():
    # The certificate of the client's own web, renewed by certbot: copied
    # now and again by a deploy hook at every renewal.
    shutil.copyfile(vLetsEncryptPath / "fullchain.pem", vCertificate)
    shutil.copyfile(vLetsEncryptPath / "privkey.pem", vPrivateKey)
    fInstallLetsEncryptHook(pArguments.vDomain)
    vSource = "letsencrypt"
  elif (cCertificatePath / "fullchain.pem").is_file() and (cCertificatePath / "privkey.pem").is_file():
    shutil.copyfile(cCertificatePath / "fullchain.pem", vCertificate)
    shutil.copyfile(cCertificatePath / "privkey.pem", vPrivateKey)
    vCheck = subprocess.run(["openssl", "x509", "-in", str(vCertificate), "-noout", vCheckOption, pArguments.vDomain], capture_output=True, text=True)
    if "does NOT match" in vCheck.stdout or vCheck.returncode != 0:
      vSource = "self-signed"
  elif (cCertificatePath / "fullchain.pem").exists() or (cCertificatePath / "privkey.pem").exists():
    raise ValueError("Incomplete certificate pair. Supply both certificate files.")
  else:
    vSource = "self-signed"
  if vSource == "self-signed":
    subprocess.run([
      "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "825",
      "-subj", "/CN=" + pArguments.vDomain, "-addext", "subjectAltName=" + vSubjectAlternativeName,
      "-keyout", str(vPrivateKey), "-out", str(vCertificate)
    ], check=True, capture_output=True)
  vCheck = subprocess.run(["openssl", "x509", "-in", str(vCertificate), "-noout", vCheckOption, pArguments.vDomain], capture_output=True, text=True)
  if "does NOT match" in vCheck.stdout:
    print(f"Warning: the certificate does not name {pArguments.vDomain}; browsers will warn.")
  subprocess.run(["openssl", "x509", "-in", str(vCertificate), "-noout", "-checkend", "0"], check=True, capture_output=True)
  vCertificateKey = subprocess.run(["openssl", "x509", "-in", str(vCertificate), "-pubkey", "-noout"], capture_output=True, check=True).stdout
  vPrivatePublicKey = subprocess.run(["openssl", "pkey", "-in", str(vPrivateKey), "-passin", "pass:", "-pubout"], capture_output=True, check=True).stdout
  if vCertificateKey != vPrivatePublicKey:
    raise ValueError("The certificate and private key do not match.")
  for vPath in [vCertificate, vPrivateKey]:
    vPath.chmod(0o600)
    os.replace(vPath, cCertificatePath / vPath.name)
  return vSource


def fInstallLetsEncryptHook(pDomain: str) -> None:
  vTemplate = (cProjectPath / "deploy" / "letsencrypt-deploy-hook.sh").read_text(encoding="utf-8")
  cLetsEncryptHook.parent.mkdir(parents=True, exist_ok=True)
  vTemporary = cLetsEncryptHook.with_name(".localsiem.sh.tmp")
  vTemporary.write_text(vTemplate.replace("@DOMAIN@", pDomain), encoding="utf-8")
  vTemporary.chmod(0o755)
  os.replace(vTemporary, cLetsEncryptHook)


def fEnsureAdmin() -> None:
  from backend.core.config import cWebDatabaseFile, fGetSecret, fLoadSettings
  from backend.web.auth import Accounts, fGeneratePassword
  from backend.web.webdb import WebDatabase
  vDatabase = WebDatabase(cWebDatabaseFile)
  vDatabase.mInitialize()
  dSettings = fLoadSettings()
  vAccounts = Accounts(vDatabase, dSettings, fGetSecret("LOCALSIEM_SECRET_KEY"))
  if vAccounts.mUserCount():
    return
  vPassword = fGeneratePassword()
  vAccounts.mCreateUser("admin", "admin", vPassword)
  fAppendCredentials([
    "localSIEM web account — " + fGetTimestamp(),
    "Username: admin",
    "Role: administrator",
    "Password: " + vPassword + " (it must be changed at the first sign-in)",
    "Two-step verification: set up at the first sign-in (authenticator app: «PYMEHackers localSIEM»)." if dSettings.get("mfa_enabled", False) else "Two-step verification: off (an administrator can turn it on in Administration › Settings)."
  ])
  print("Web account admin created (password in /root/webapp-credentials.txt).")


def fMain() -> None:
  if os.geteuid() != 0:
    raise ValueError("Run deployment configuration as root.")
  os.umask(0o077)
  vArguments = fGetArguments()
  if vArguments.vCheckArguments:
    return
  dEnvironment = fReadEnvironment()
  cConfigPath.mkdir(parents=True, exist_ok=True)
  cCertificatePath.mkdir(parents=True, exist_ok=True)
  fCheckPort(vArguments.vPort)
  vTemporaryRoot = cProjectPath / "_" / "temp"
  vTemporaryRoot.mkdir(parents=True, exist_ok=True)
  lCredentialBlocks = []
  try:
    with tempfile.TemporaryDirectory(prefix="configure.", dir=vTemporaryRoot) as vTemporaryDirectory:
      vTemporaryPath = Path(vTemporaryDirectory)
      vSource = fConfigureCertificates(vArguments, vTemporaryPath)
      lCredentialBlocks = fConfigureCredentials(vArguments, dEnvironment, vTemporaryPath)
      fConfigureSettings(vArguments)
      fRememberArguments(vArguments, vTemporaryPath)
    fEnsureAdmin()
  finally:
    # After the block of the administrator, so the file lists it first. Also
    # written when a later step fails: localsiem.env already has their
    # hashes, and the generated passwords would be lost otherwise.
    for lBlock in lCredentialBlocks:
      fAppendCredentials(lBlock)
  print(f"Certificate: {vSource}.")
  print(f"SIEM address for the SOC: https://{vArguments.vDomain}:{vArguments.vPort}")
  if not vArguments.lAllowFrom:
    print("WARNING: no --allow-from was given: the localSIEM web is open to any address of the Internet that reaches port " + str(vArguments.vPort) + ". Give the IPs of the SOC and of your administrators with --allow-from, and close the port in the firewall for everybody else.")
  if vArguments.vMfa is True:
    print("Two-step verification turned on (--enable-mfa): every account sets it up at its next sign-in.")
  elif vArguments.vMfa is False:
    print("Two-step verification turned off (--disable-mfa). An administrator can turn it on in Administration › Settings.")
  print("Deployment configured. Existing credentials are preserved unless rotation was requested.")


if __name__ == "__main__":
  try:
    fMain()
  except (OSError, ValueError, subprocess.CalledProcessError) as vError:
    print(f"Configuration failed: {vError}", file=sys.stderr)
    raise SystemExit(1) from vError
