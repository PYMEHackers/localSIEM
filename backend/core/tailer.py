"""Reading of log files: positions, rotation, truncation and deletion.

Each followed file keeps its device, inode and offset in the database, so
the collector continues where it stopped after a restart without losing or
repeating lines. The files are polled (a stat per second), with no extra
dependencies.

  rotation      the inode of the path changes (logrotate with "create"), or
                the file becomes shorter and a fresh sibling holds the copy
                (logrotate with "copytruncate"). The old file is read to its
                end through the descriptor still open, then the new one from
                the start.
  truncation    the file becomes shorter and no rotated copy explains it.
  disappearance the path is missing for longer than the grace period.
  replacement   the inode changes, the old file is gone and the new one is
                already large (an edited copy put in its place).

The last three are reported as notices: the collector turns them into
anti-forensics alerts.
"""

import os
import time
from pathlib import Path

cReadChunk = 1024 * 1024
cMaxLineBytes = 4 * 1024 * 1024


class FileTailer:

  def __init__(self, pSourceKey: str, pPath: str, pPosition: dict | None, pStartAtEnd: bool, pGraceSeconds: int = 60):
    self.vSourceKey = pSourceKey
    self.vPath = str(pPath)
    self.dPosition = pPosition
    self.vStartAtEnd = pStartAtEnd
    self.vGraceSeconds = pGraceSeconds
    self.vFile = None
    self.vDevice = 0
    self.vInode = 0
    self.vOffset = 0
    self.vBuffer = b""
    self.lDrain = []
    self.vMissingSince = None
    self.vMissingReported = False
    self.vUnreadableReported = False
    self.vLastData = 0.0
    self.vEverOpened = False
    # True from each opening until the collector saves a position of this
    # file, also when nothing is read from it (Collector.mReadSources).
    self.vOpenedUnsaved = False
    # True when the last poll stopped at its byte budget: there is more to read.
    self.vBacklog = False

  # Helpers

  def mFindInode(self, pDevice: int, pInode: int) -> str | None:
    # A rotated file keeps its inode in the same directory (access.log.1).
    vDirectory = os.path.dirname(self.vPath) or "."
    try:
      with os.scandir(vDirectory) as vEntries:
        for vEntry in vEntries:
          try:
            # stat() and not DirEntry.inode(): some file systems (FUSE,
            # network mounts) do not fill the inode of directory entries.
            vEntryStat = vEntry.stat(follow_symlinks=False)
            if vEntryStat.st_ino == pInode and vEntryStat.st_dev == pDevice and vEntry.is_file(follow_symlinks=False):
              return vEntry.path
          except OSError:
            continue
    except OSError:
      return None
    return None

  def mFindCopy(self, pMinimumSize: int) -> str | None:
    # copytruncate: a sibling (access.log.1, access.log-20261027) written
    # in the last two minutes and at least as long as what was read.
    vDirectory = os.path.dirname(self.vPath) or "."
    vName = os.path.basename(self.vPath)
    vNow = time.time()
    vBest = None
    try:
      with os.scandir(vDirectory) as vEntries:
        for vEntry in vEntries:
          if vEntry.name == vName or not vEntry.name.startswith(vName) or vEntry.name.endswith((".gz", ".bz2", ".xz", ".zst")):
            continue
          try:
            vStat = vEntry.stat(follow_symlinks=False)
          except OSError:
            continue
          if vNow - vStat.st_mtime <= 120 and vStat.st_size >= pMinimumSize:
            if vBest is None or vStat.st_mtime > vBest[1]:
              vBest = (vEntry.path, vStat.st_mtime)
    except OSError:
      return None
    return vBest[0] if vBest else None

  def mOpen(self, pPath: str):
    vDescriptor = os.open(pPath, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    return os.fdopen(vDescriptor, "rb", buffering=0)

  def mClose(self) -> None:
    for dDrain in self.lDrain:
      try:
        dDrain["file"].close()
      except OSError:
        pass
    self.lDrain = []
    if self.vFile is not None:
      try:
        self.vFile.close()
      except OSError:
        pass
    self.vFile = None

  def mPosition(self, pCommit: tuple | None) -> dict:
    # pCommit: (device, inode, offset) of the last unit fully stored.
    if pCommit is None:
      vDevice, vInode, vOffset = self.vDevice, self.vInode, self.vOffset
    else:
      vDevice, vInode, vOffset = pCommit
    try:
      vSize = os.stat(self.vPath).st_size
    except OSError:
      vSize = 0
    from backend.core.timeutil import fNowStorage
    return {"path": self.vPath, "device": vDevice, "inode": vInode, "offset": vOffset, "size": vSize, "updated": fNowStorage()}

  # Opening

  def mStart(self, lNotices: list) -> bool:
    try:
      vFile = self.mOpen(self.vPath)
    except FileNotFoundError:
      return False
    except PermissionError:
      if not self.vUnreadableReported:
        lNotices.append({"kind": "unreadable", "path": self.vPath})
        self.vUnreadableReported = True
      return False
    except OSError as vError:
      if not self.vUnreadableReported:
        lNotices.append({"kind": "unreadable", "path": self.vPath, "error": str(vError)})
        self.vUnreadableReported = True
      return False
    if self.vUnreadableReported:
      lNotices.append({"kind": "readable", "path": self.vPath})
    self.vUnreadableReported = False
    vStat = os.fstat(vFile.fileno())
    self.vFile = vFile
    self.vDevice = vStat.st_dev
    self.vInode = vStat.st_ino
    self.vOffset = 0
    self.vBuffer = b""
    dPosition = self.dPosition
    self.dPosition = None
    if dPosition is not None:
      if dPosition["device"] == vStat.st_dev and dPosition["inode"] == vStat.st_ino:
        if vStat.st_size >= dPosition["offset"]:
          self.vOffset = dPosition["offset"]
        else:
          vCopy = self.mFindCopy(dPosition["offset"])
          if vCopy:
            self.mAddDrain(vCopy, dPosition["offset"], lNotices)
            lNotices.append({"kind": "rotated", "path": self.vPath, "method": "copytruncate"})
          else:
            lNotices.append({"kind": "truncated", "path": self.vPath, "previous": dPosition["offset"], "size": vStat.st_size})
      else:
        vOld = self.mFindInode(dPosition["device"], dPosition["inode"])
        if vOld:
          self.mAddDrain(vOld, dPosition["offset"], lNotices)
          lNotices.append({"kind": "rotated", "path": self.vPath, "method": "while_stopped", "old": vOld})
        else:
          lNotices.append({"kind": "rotated_lost", "path": self.vPath})
    elif self.vStartAtEnd:
      self.vOffset = vStat.st_size
    vFile.seek(self.vOffset)
    # Only the very first opening may start at the end: a file that appears
    # later (rotation, deletion and creation) is read from its start.
    self.vStartAtEnd = False
    self.vEverOpened = True
    self.vOpenedUnsaved = True
    self.vMissingSince = None
    return True

  def mAddDrain(self, pPath: str, pOffset: int, lNotices: list) -> None:
    try:
      vFile = self.mOpen(pPath)
    except OSError as vError:
      lNotices.append({"kind": "unreadable", "path": pPath, "error": str(vError)})
      return
    vStat = os.fstat(vFile.fileno())
    vFile.seek(min(pOffset, vStat.st_size))
    self.lDrain.append({"file": vFile, "device": vStat.st_dev, "inode": vStat.st_ino, "offset": min(pOffset, vStat.st_size), "buffer": b""})

  # Reading

  def mReadFrom(self, pFile, pDevice: int, pInode: int, pOffset: int, pBuffer: bytes, pMaxBytes: int, lLines: list, pFinal: bool) -> tuple[int, bytes, int]:
    # Returns the new offset of the last complete line, the remainder and
    # the bytes read.
    vRead = 0
    vOffset = pOffset
    vBuffer = pBuffer
    while vRead < pMaxBytes:
      try:
        vChunk = pFile.read(min(cReadChunk, pMaxBytes - vRead))
      except BlockingIOError:
        vChunk = b""
      if not vChunk:
        break
      vRead += len(vChunk)
      vBuffer += vChunk
      vStart = 0
      while True:
        vEnd = vBuffer.find(b"\n", vStart)
        if vEnd < 0:
          break
        vLine = vBuffer[vStart:vEnd]
        vOffset += vEnd + 1 - vStart
        if vLine.endswith(b"\r"):
          vLine = vLine[:-1]
        if len(vLine) > cMaxLineBytes:
          vLine = vLine[:cMaxLineBytes]
        lLines.append((vLine.decode("utf-8", errors="backslashreplace"), pDevice, pInode, vOffset))
        vStart = vEnd + 1
      vBuffer = vBuffer[vStart:]
      if len(vBuffer) > cMaxLineBytes:
        # A line without end that keeps growing: cut it here.
        vOffset += len(vBuffer)
        lLines.append((vBuffer[:cMaxLineBytes].decode("utf-8", errors="backslashreplace"), pDevice, pInode, vOffset))
        vBuffer = b""
    if pFinal and vBuffer:
      vOffset += len(vBuffer)
      lLines.append((vBuffer.decode("utf-8", errors="backslashreplace"), pDevice, pInode, vOffset))
      vBuffer = b""
    return vOffset, vBuffer, vRead

  def mPoll(self, pMaxBytes: int = 8 * 1024 * 1024) -> tuple[list, list]:
    lLines = []
    lNotices = []
    self.vBacklog = False
    if self.vFile is None:
      if not self.mStart(lNotices):
        self.mCheckMissing(lNotices)
        return lLines, lNotices
    # Rotated files first, to their end.
    while self.lDrain:
      dDrain = self.lDrain[0]
      vOffset, vBuffer, vRead = self.mReadFrom(dDrain["file"], dDrain["device"], dDrain["inode"], dDrain["offset"], dDrain["buffer"], pMaxBytes, lLines, False)
      dDrain["offset"], dDrain["buffer"] = vOffset, vBuffer
      if vRead >= pMaxBytes:
        self.vBacklog = True
        return lLines, lNotices
      vOffset, _, _ = self.mReadFrom(dDrain["file"], dDrain["device"], dDrain["inode"], dDrain["offset"], dDrain["buffer"], 0, lLines, True)
      try:
        dDrain["file"].close()
      except OSError:
        pass
      self.lDrain.pop(0)
    try:
      vStat = os.stat(self.vPath)
    except FileNotFoundError:
      vStat = None
    except PermissionError:
      vStat = None
      if not self.vUnreadableReported:
        lNotices.append({"kind": "unreadable", "path": self.vPath})
        self.vUnreadableReported = True
    if vStat is None:
      # Read what is left through the open descriptor.
      self.vOffset, self.vBuffer, vRead = self.mReadFrom(self.vFile, self.vDevice, self.vInode, self.vOffset, self.vBuffer, pMaxBytes, lLines, False)
      if vRead:
        self.vLastData = time.time()
      self.mCheckMissing(lNotices)
      return lLines, lNotices
    if self.vMissingSince is not None and self.vMissingReported:
      lNotices.append({"kind": "reappeared", "path": self.vPath})
    self.vMissingSince = None
    self.vMissingReported = False
    if vStat.st_ino != self.vInode or vStat.st_dev != self.vDevice:
      # Rotation: the rest of the old file, then the new one from the start.
      self.vOffset, self.vBuffer, vRead = self.mReadFrom(self.vFile, self.vDevice, self.vInode, self.vOffset, self.vBuffer, pMaxBytes, lLines, False)
      if vRead >= pMaxBytes:
        self.vBacklog = True
        return lLines, lNotices
      self.vOffset, self.vBuffer, _ = self.mReadFrom(self.vFile, self.vDevice, self.vInode, self.vOffset, self.vBuffer, 0, lLines, True)
      vOldDevice, vOldInode, vOldOffset = self.vDevice, self.vInode, self.vOffset
      vOldStillThere = self.mFindInode(vOldDevice, vOldInode) is not None
      try:
        self.vFile.close()
      except OSError:
        pass
      self.vFile = None
      if not self.mStart(lNotices):
        return lLines, lNotices
      if not vOldStillThere and vStat.st_size >= max(64 * 1024, vOldOffset // 2):
        lNotices.append({"kind": "replaced", "path": self.vPath, "previous": vOldOffset, "size": vStat.st_size})
        self.vOffset = vStat.st_size
        self.vFile.seek(self.vOffset)
      else:
        lNotices.append({"kind": "rotated", "path": self.vPath, "method": "create"})
      return lLines, lNotices
    if vStat.st_size < self.vOffset:
      vCopy = self.mFindCopy(self.vOffset)
      if vCopy:
        self.mAddDrain(vCopy, self.vOffset, lNotices)
        lNotices.append({"kind": "rotated", "path": self.vPath, "method": "copytruncate"})
      else:
        lNotices.append({"kind": "truncated", "path": self.vPath, "previous": self.vOffset, "size": vStat.st_size})
      self.vOffset = 0
      self.vBuffer = b""
      self.vFile.seek(0)
      return lLines, lNotices
    self.vOffset, self.vBuffer, vRead = self.mReadFrom(self.vFile, self.vDevice, self.vInode, self.vOffset, self.vBuffer, pMaxBytes, lLines, False)
    if vRead:
      self.vLastData = time.time()
    self.vBacklog = vRead >= pMaxBytes
    return lLines, lNotices

  def mCheckMissing(self, lNotices: list) -> None:
    if not self.vEverOpened:
      return
    if self.vMissingSince is None:
      self.vMissingSince = time.time()
    elif not self.vMissingReported and time.time() - self.vMissingSince >= self.vGraceSeconds:
      lNotices.append({"kind": "missing", "path": self.vPath})
      self.vMissingReported = True

  def mExists(self) -> bool:
    return Path(self.vPath).exists()
