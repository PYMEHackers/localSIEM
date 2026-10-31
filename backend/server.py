#!/usr/bin/env -S PYTHONDONTWRITEBYTECODE=1 python3

import sys

if sys.version_info < (3, 13):
  raise SystemExit("Python 3.13 or newer is required.")

import fcntl
import os
import signal
import time
from pathlib import Path

cRootPath = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(cRootPath))

from backend.core.config import cCertificatePath, cRunPath, cWebPort, fLoadSettings

def fShowHelp() -> None:
  print("Usage: ./backend/server.py")
  print("The web always listens with HTTPS on port 10443, with /opt/localsiem/certificates/fullchain.pem and privkey.pem.")


def fCheckArguments(pArguments: list[str]) -> None:
  # The web takes no options: only the help.
  for vArgument in pArguments:
    if vArgument in ["-h", "--help"]:
      fShowHelp()
      raise SystemExit(0)
    raise ValueError(f"Unsupported option: {vArgument}")


def fListeningInodes(pPort: int) -> set[str]:
  sInodes = set()
  for vTable in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
      lLines = Path(vTable).read_text(encoding="ascii").splitlines()[1:]
    except OSError:
      continue
    for vLine in lLines:
      aParts = vLine.split()
      if len(aParts) < 10 or aParts[3] != "0A":
        continue
      if int(aParts[1].rsplit(":", 1)[1], 16) == pPort:
        sInodes.add(aParts[9])
  return sInodes


def fFreePort(pPort: int) -> None:
  # Before listening, any socket still open on the port by a previous run of
  # localSIEM (same user) is closed. Sockets of other users are never touched:
  # if one holds the port, the start fails and says so.
  sInodes = fListeningInodes(pPort)
  if not sInodes:
    return
  for vEntry in Path("/proc").iterdir():
    if not vEntry.name.isdigit() or int(vEntry.name) == os.getpid():
      continue
    try:
      if vEntry.stat().st_uid != os.getuid():
        continue
      for vDescriptor in (vEntry / "fd").iterdir():
        vTarget = os.readlink(vDescriptor)
        if vTarget.startswith("socket:[") and vTarget[8:-1] in sInodes:
          os.kill(int(vEntry.name), signal.SIGTERM)
          break
    except (OSError, ValueError):
      continue
  for _ in range(30):
    if not fListeningInodes(pPort):
      return
    time.sleep(0.2)


def fMain(pArguments: list[str] | None = None) -> None:
  if pArguments is None:
    pArguments = sys.argv[1:]
  fCheckArguments(pArguments)
  dSettings = fLoadSettings()
  vPort = cWebPort
  vListen = str(dSettings.get("listen", "0.0.0.0"))
  vCertificate = cCertificatePath / "fullchain.pem"
  vPrivateKey = cCertificatePath / "privkey.pem"
  if not vCertificate.is_file() or not vPrivateKey.is_file():
    raise ValueError(f"Missing certificate: {vCertificate} and {vPrivateKey}")
  from backend.web.app import fCreateApp
  import uvicorn

  vApp, _, _ = fCreateApp()
  os.umask(0o077)
  cRunPath.mkdir(parents=True, exist_ok=True)
  with (cRunPath / "web.lock").open("w") as vLock:
    fcntl.flock(vLock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
      fFreePort(vPort)
      print(f"Starting localSIEM web on https://{vListen}:{vPort}/", flush=True)
      uvicorn.run(
        vApp, host=vListen, port=vPort, ssl_certfile=str(vCertificate), ssl_keyfile=str(vPrivateKey),
        workers=1, proxy_headers=False, server_header=False, date_header=True,
        ws_max_size=65536, ws_ping_interval=20, ws_ping_timeout=20, log_level="warning", access_log=False
      )
    finally:
      fcntl.flock(vLock, fcntl.LOCK_UN)


if __name__ == "__main__":
  try:
    fMain()
  except (OSError, ValueError) as vError:
    print(f"Startup failed: {vError}", file=sys.stderr)
    raise SystemExit(1) from vError
