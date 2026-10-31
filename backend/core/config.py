"""Paths and settings shared by the collector, the web and the tools.

Settings come from three layers, each one over the previous:

  1. dDefaults, below.
  2. /opt/localsiem/config/settings.json, written by the installer and by the
     administrator panel (the web). The collector reloads it when it changes.
  3. A few environment variables (LOCALSIEM_HOME, for development copies).

Secrets never live in settings.json: the SOC token is in config/soc-token,
the token of the Telegram bot in config/telegram-bot-token and the signing
secrets in config/localsiem.env, all with mode 600.
"""

import copy
import json
import os
import socket
import tempfile
from pathlib import Path

cHome = Path(os.getenv("LOCALSIEM_HOME", "/opt/localsiem"))
cProjectPath = Path(__file__).resolve().parent.parent.parent
cConfigPath = cHome / "config"
cDatabasePath = cHome / "db"
cRunPath = cHome / "run"
cLogPath = cHome / "log"
cCertificatePath = cHome / "certificates"
cSettingsFile = cConfigPath / "settings.json"
cEnvironmentFile = cConfigPath / "localsiem.env"
cSocTokenFile = cConfigPath / "soc-token"
cTelegramTokenFile = cConfigPath / "telegram-bot-token"
cEventsDatabaseFile = cDatabasePath / "localsiem.db"
cWebDatabaseFile = cDatabasePath / "localsiem-web.db"
# Installed modules (one folder each, <name>/, with its module.json). The web
# installs them from the repository localSIEM-modules, where the folder of
# each one is mod-<name>/ (backend/core/catalog.py).
cModulesPath = Path(os.getenv("LOCALSIEM_MODULES_PATH") or (cHome / "modules")).resolve()
# LOCALSIEM_COLLECTOR_SOCKET=@name uses a Linux abstract socket (development
# copies on file systems without Unix sockets).
cCollectorSocket = os.getenv("LOCALSIEM_COLLECTOR_SOCKET") or (cRunPath / "collector.sock")
cVersion = "2.2.0"
# The web always listens on this HTTPS port (self-signed certificate when
# there is no other one).
cWebPort = 10443

dDefaults = {
  # Name of this server in the events and in the alerts (external_id).
  "host": "",
  "port": cWebPort,
  "listen": "0.0.0.0",
  # IPs and CIDR allowed to reach the web. Empty: open (the installer warns).
  "allow_from": [],
  "retention_days": 90,
  "alert_retention_days": 365,
  # 0: the lesser of 15 % of the disk and 10 GB.
  "max_disk_bytes": 0,
  "max_disk_percent": 15,
  "max_disk_cap_bytes": 10 * 1024 ** 3,
  # Free space below which the bulky detail (audit bodies) is no longer stored.
  "low_disk_free_percent": 10,
  "low_disk_free_bytes": 2 * 1024 ** 3,
  # Free space below which only events that take part in an alert are stored.
  "critical_disk_free_percent": 3,
  "critical_disk_free_bytes": 512 * 1024 ** 2,
  # Severity of CRS matches below the blocking threshold (usually false
  # positives of the application itself).
  "below_threshold_severity": "low",
  "correlation_window_seconds": 5,
  "weak_correlation_seconds": 2,
  "group_window_seconds": 600,
  "group_buffer_seconds": 60,
  "soc_url": "https://soc.pymehackers.com",
  # Extra CA bundle for a SOC with a private certificate (test servers).
  "soc_ca_file": "",
  "soc_enabled": True,
  "heartbeat_seconds": 300,
  "soc_max_backoff_seconds": 300,
  "soc_exhausted_retry_seconds": 3600,
  # Channels through which localSIEM sends messages to its administrators
  # (backend/core/channels.py): enabled turns all of them on or off; the
  # alerts of min_severity or above are sent, in language. Each channel has
  # its own block; the token of the Telegram bot is in
  # config/telegram-bot-token, never here.
  "channels": {
    "enabled": True,
    "min_severity": "high",
    "language": "en-US",
    "telegram": {
      "enabled": False,
      "chat_id": ""
    }
  },
  "search_timeout_seconds": 5,
  "search_page_size": 100,
  "export_max_rows": 10000,
  "mfa_enabled": False,
  "session_hours": 8,
  "login_max_failures": 5,
  "login_window_seconds": 900,
  "masking": {
    "parameters": ["password", "pass", "pwd", "passwd", "token", "secret", "api_key", "apikey", "auth", "session"],
    "headers": ["Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Proxy-Authorization"]
  },
  "health": {
    "unparsed_percent": 5,
    "unparsed_minimum_lines": 100,
    "silent_hours": 24,
    "single_ip_percent": 90,
    "single_ip_minimum_requests": 100,
    "missing_grace_seconds": 60
  },
  # Settings of each module, by its name: {"enabled": bool, ...}. The defaults
  # of each one come from its module.json, not from here.
  "modules": {},
  # Where the web finds the modules it can install (backend/core/catalog.py),
  # the only way to install them: a repository and its branch or tag, or the
  # URL of a .tar.gz archive.
  "modules_repository": {
    "url": "https://github.com/PYMEHackers/localSIEM-modules",
    "ref": "main"
  }
}


def fDeepMerge(pBase: dict, pOverride: dict) -> dict:
  dResult = copy.deepcopy(pBase)
  for vKey, vValue in pOverride.items():
    if isinstance(vValue, dict) and isinstance(dResult.get(vKey), dict):
      dResult[vKey] = fDeepMerge(dResult[vKey], vValue)
    else:
      dResult[vKey] = copy.deepcopy(vValue)
  return dResult


def fReadSettingsFile() -> dict:
  try:
    with cSettingsFile.open("r", encoding="utf-8") as vFile:
      dStored = json.load(vFile)
    return dStored if isinstance(dStored, dict) else {}
  except FileNotFoundError:
    return {}
  except (OSError, ValueError):
    return {}


def fLoadSettings() -> dict:
  dSettings = fDeepMerge(dDefaults, fReadSettingsFile())
  if not dSettings.get("host"):
    dSettings["host"] = socket.gethostname().split(".")[0] or "localhost"
  return dSettings


def fSettingsMtime() -> float:
  try:
    return cSettingsFile.stat().st_mtime
  except OSError:
    return 0.0


def fWritePrivateFile(pPath: Path, pText: str) -> None:
  # Written next to the target and renamed, so readers never see half a file.
  pPath.parent.mkdir(parents=True, exist_ok=True)
  vDescriptor, vTemporary = tempfile.mkstemp(prefix="." + pPath.name + ".", dir=pPath.parent)
  try:
    with os.fdopen(vDescriptor, "w", encoding="utf-8") as vFile:
      os.fchmod(vFile.fileno(), 0o600)
      vFile.write(pText)
    os.replace(vTemporary, pPath)
  except BaseException:
    try:
      os.unlink(vTemporary)
    except OSError:
      pass
    raise


def fSaveSettings(pChanges: dict) -> dict:
  # Only the stored overrides are written, not the defaults: a later version
  # with better defaults still applies them.
  dStored = fDeepMerge(fReadSettingsFile(), pChanges)
  fWritePrivateFile(cSettingsFile, json.dumps(dStored, indent=2, ensure_ascii=False) + "\n")
  return fLoadSettings()


def fRemoveSettings(pKeys: list[str]) -> None:
  # Stored settings of features that no longer exist (the installer, at every
  # update). The file is only written when one of them is there.
  dStored = fReadSettingsFile()
  if any(vKey in dStored for vKey in pKeys):
    for vKey in pKeys:
      dStored.pop(vKey, None)
    fWritePrivateFile(cSettingsFile, json.dumps(dStored, indent=2, ensure_ascii=False) + "\n")


def fReadSocToken() -> str:
  try:
    return cSocTokenFile.read_text(encoding="utf-8").strip()
  except OSError:
    return ""


def fSaveSocToken(pToken: str) -> None:
  fWritePrivateFile(cSocTokenFile, pToken.strip() + "\n")


def fReadTelegramToken() -> str:
  try:
    return cTelegramTokenFile.read_text(encoding="utf-8").strip()
  except OSError:
    return ""


def fSaveTelegramToken(pToken: str) -> None:
  fWritePrivateFile(cTelegramTokenFile, pToken.strip() + "\n")


def fDeleteTelegramToken() -> None:
  try:
    cTelegramTokenFile.unlink()
  except FileNotFoundError:
    pass


def fMaskSecret(pValue: str) -> str:
  # Never shown whole: the first and the last four characters.
  if not pValue:
    return ""
  if len(pValue) <= 10:
    return "***"
  return pValue[:4] + "…" + pValue[-4:]


def fReadEnvironmentFile() -> dict:
  dEnvironment = {}
  try:
    for vLine in cEnvironmentFile.read_text(encoding="utf-8").splitlines():
      if vLine and not vLine.startswith("#"):
        vName, vSeparator, vValue = vLine.partition("=")
        if vSeparator and vName.startswith("LOCALSIEM_"):
          dEnvironment[vName] = vValue
  except OSError:
    pass
  return dEnvironment


def fGetSecret(pName: str) -> str:
  # The services get localsiem.env as their environment; the tools read the file.
  return os.getenv(pName) or fReadEnvironmentFile().get(pName, "")
