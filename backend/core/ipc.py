"""Local socket between localsiem-web and the collector.

One JSON object per line, one request and one answer per connection, over the
Unix socket /opt/localsiem/run/collector.sock (mode 600, user localsiem). The web
uses it for a few commands (reload the settings, retry the SOC queue, run the
doctor, restart after a module is installed); the collector stays the only
writer of the database.
"""

import json
import os
import socket
import stat
import threading
from pathlib import Path

cMaxMessageBytes = 8 * 1024 * 1024


def fAddress(pPath) -> str:
  # "@name" is a Linux abstract socket: it has no file.
  vPath = str(pPath)
  return "\0" + vPath[1:] if vPath.startswith("@") else vPath


def fRequest(pPath: Path, pMessage: dict, pTimeout: float = 10.0) -> dict:
  vData = (json.dumps(pMessage, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
  if len(vData) > cMaxMessageBytes:
    raise ValueError("Message too large")
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as vSocket:
    vSocket.settimeout(pTimeout)
    vSocket.connect(fAddress(pPath))
    vSocket.sendall(vData)
    vSocket.shutdown(socket.SHUT_WR)
    lChunks = []
    vSize = 0
    while True:
      vChunk = vSocket.recv(65536)
      if not vChunk:
        break
      lChunks.append(vChunk)
      vSize += len(vChunk)
      if vSize > cMaxMessageBytes:
        raise ValueError("Answer too large")
  vText = b"".join(lChunks).decode("utf-8").strip()
  return json.loads(vText) if vText else {}


class IpcServer(threading.Thread):

  def __init__(self, pPath: Path, pHandler):
    super().__init__(name="ipc", daemon=True)
    self.vAbstract = str(pPath).startswith("@")
    self.vPath = Path(pPath) if not self.vAbstract else None
    self.vName = str(pPath)
    self.fHandler = pHandler
    self.vSocket = None
    self.vStop = threading.Event()

  def mBind(self) -> None:
    if self.vAbstract:
      vSocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      vSocket.bind(fAddress(self.vName))
      vSocket.listen(32)
      vSocket.settimeout(1.0)
      self.vSocket = vSocket
      return
    self.vPath.parent.mkdir(parents=True, exist_ok=True)
    if self.vPath.exists() or self.vPath.is_symlink():
      if not stat.S_ISSOCK(self.vPath.lstat().st_mode):
        raise ValueError(f"{self.vPath} exists and is not a socket")
      # A socket left by a previous run of the collector.
      self.vPath.unlink()
    vSocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    vOldUmask = os.umask(0o177)
    try:
      vSocket.bind(str(self.vPath))
    finally:
      os.umask(vOldUmask)
    os.chmod(self.vPath, 0o600)
    vSocket.listen(32)
    vSocket.settimeout(1.0)
    self.vSocket = vSocket

  def run(self) -> None:
    while not self.vStop.is_set():
      try:
        vConnection, _ = self.vSocket.accept()
      except TimeoutError:
        continue
      except OSError:
        if self.vStop.is_set():
          break
        continue
      threading.Thread(target=self.mServe, args=(vConnection,), daemon=True).start()

  def mServe(self, pConnection: socket.socket) -> None:
    try:
      pConnection.settimeout(30)
      lChunks = []
      vSize = 0
      while True:
        vChunk = pConnection.recv(65536)
        if not vChunk:
          break
        lChunks.append(vChunk)
        vSize += len(vChunk)
        if b"\n" in vChunk or vSize > cMaxMessageBytes:
          break
      vText = b"".join(lChunks).decode("utf-8", errors="replace").split("\n", 1)[0]
      try:
        dMessage = json.loads(vText)
        dAnswer = self.fHandler(dMessage) if isinstance(dMessage, dict) else {"ok": False, "error": "invalid_message"}
      except ValueError:
        dAnswer = {"ok": False, "error": "invalid_json"}
      except Exception as vError:
        dAnswer = {"ok": False, "error": type(vError).__name__ + ": " + str(vError)[:300]}
      pConnection.sendall((json.dumps(dAnswer, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
    except OSError:
      pass
    finally:
      try:
        pConnection.close()
      except OSError:
        pass

  def mStop(self) -> None:
    self.vStop.set()
    try:
      if self.vSocket is not None:
        self.vSocket.close()
    except OSError:
      pass
    try:
      if self.vPath is not None and self.vPath.exists() and stat.S_ISSOCK(self.vPath.lstat().st_mode):
        self.vPath.unlink()
    except OSError:
      pass
