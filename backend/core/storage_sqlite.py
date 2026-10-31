"""SQLite implementation of the storage interface (see storage.py).

  - WAL mode and a busy timeout; auto_vacuum = INCREMENTAL, so retention can
    give space back to the disk in small steps.
  - Typed, indexed columns for the usual fields and a contentless FTS5 table
    (contentless_delete=1) over the masked original text. The indexed text
    is URL-decoded, so "union select" also finds id=1%27%20UNION%20SELECT;
    the text itself is stored once, in records.raw.
  - Every query takes parameters; the search tree is compiled here into SQL
    with placeholders, never by concatenating user text.
  - The collector is the only process that writes. Inside the collector,
    several threads write through one lock.
"""

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import unquote_plus

from backend.core.query import QueryError
from backend.core.storage import Storage

cSchemaVersion = 1
lSchema = [
  """CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )""",
  """CREATE TABLE IF NOT EXISTS positions (
    source_key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    device INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    updated TEXT NOT NULL
  )""",
  """CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    time TEXT NOT NULL,
    received TEXT NOT NULL,
    module TEXT NOT NULL,
    source TEXT NOT NULL,
    source_key TEXT NOT NULL,
    correlation TEXT,
    parse_status TEXT NOT NULL,
    fields TEXT NOT NULL,
    raw TEXT NOT NULL
  )""",
  "CREATE INDEX IF NOT EXISTS records_event ON records(event_id)",
  "CREATE INDEX IF NOT EXISTS records_pending ON records(id) WHERE event_id IS NULL",
  "CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(text, content='', contentless_delete=1)",
  """CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    time TEXT NOT NULL,
    received TEXT NOT NULL,
    host TEXT NOT NULL,
    module TEXT NOT NULL,
    sources TEXT NOT NULL,
    ip TEXT,
    vhost TEXT,
    method TEXT,
    uri TEXT,
    path TEXT,
    query TEXT,
    status INTEGER,
    bytes INTEGER,
    duration INTEGER,
    ua TEXT,
    referer TEXT,
    uid TEXT,
    rules TEXT,
    category TEXT,
    phase INTEGER,
    score INTEGER,
    threshold INTEGER,
    engine TEXT,
    severity TEXT,
    action TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    correlation TEXT,
    fields TEXT NOT NULL
  )""",
  "CREATE INDEX IF NOT EXISTS events_time ON events(time)",
  "CREATE INDEX IF NOT EXISTS events_ip_time ON events(ip, time)",
  "CREATE INDEX IF NOT EXISTS events_vhost_time ON events(vhost, time)",
  "CREATE INDEX IF NOT EXISTS events_uid ON events(uid COLLATE NOCASE)",
  "CREATE INDEX IF NOT EXISTS events_status_time ON events(status, time)",
  "CREATE INDEX IF NOT EXISTS events_action_time ON events(action, time)",
  "CREATE INDEX IF NOT EXISTS events_category_time ON events(category, time)",
  "CREATE INDEX IF NOT EXISTS events_severity_time ON events(severity, time)",
  """CREATE TABLE IF NOT EXISTS event_rules (
    event_id INTEGER NOT NULL,
    rule TEXT NOT NULL,
    category TEXT,
    time TEXT NOT NULL,
    PRIMARY KEY (event_id, rule)
  ) WITHOUT ROWID""",
  "CREATE INDEX IF NOT EXISTS event_rules_rule ON event_rules(rule, time)",
  "CREATE INDEX IF NOT EXISTS event_rules_category ON event_rules(category, time)",
  """CREATE TABLE IF NOT EXISTS alert_groups (
    id INTEGER PRIMARY KEY,
    group_key TEXT NOT NULL,
    module TEXT NOT NULL,
    vhost TEXT NOT NULL,
    ip TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    rule TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    send_at TEXT NOT NULL,
    status TEXT NOT NULL,
    external_id TEXT NOT NULL UNIQUE,
    soc_code TEXT,
    details TEXT NOT NULL,
    search TEXT NOT NULL,
    sample_uids TEXT NOT NULL,
    created TEXT NOT NULL,
    sent_at TEXT,
    last_error TEXT
  )""",
  "CREATE INDEX IF NOT EXISTS alert_groups_open ON alert_groups(group_key, window_end)",
  "CREATE INDEX IF NOT EXISTS alert_groups_status ON alert_groups(status, send_at)",
  "CREATE INDEX IF NOT EXISTS alert_groups_soc ON alert_groups(soc_code COLLATE NOCASE)",
  "CREATE INDEX IF NOT EXISTS alert_groups_last ON alert_groups(last_seen)",
  """CREATE TABLE IF NOT EXISTS event_alerts (
    event_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    time TEXT NOT NULL,
    PRIMARY KEY (event_id, group_id)
  ) WITHOUT ROWID""",
  "CREATE INDEX IF NOT EXISTS event_alerts_group ON event_alerts(group_id)",
  """CREATE TABLE IF NOT EXISTS soc_queue (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL,
    payload TEXT NOT NULL,
    size INTEGER NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt TEXT NOT NULL,
    created TEXT NOT NULL,
    sent_at TEXT,
    last_error TEXT
  )""",
  "CREATE INDEX IF NOT EXISTS soc_queue_status ON soc_queue(status, next_attempt)",
  "CREATE INDEX IF NOT EXISTS soc_queue_group ON soc_queue(group_id)",
  """CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated TEXT NOT NULL
  )""",
  """CREATE TABLE IF NOT EXISTS seen_paths (
    vhost TEXT NOT NULL,
    path TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (vhost, path)
  ) WITHOUT ROWID"""
]

lEventColumns = [
  "time", "received", "host", "module", "sources", "ip", "vhost", "method", "uri", "path", "query",
  "status", "bytes", "duration", "ua", "referer", "uid", "rules", "category", "phase", "score",
  "threshold", "engine", "severity", "action", "parse_status", "correlation", "fields"
]
lListColumns = [
  "id", "time", "host", "module", "sources", "ip", "vhost", "method", "uri", "status", "uid",
  "rules", "category", "severity", "action", "parse_status", "engine", "phase", "score"
]
lGroupColumns = [
  "id", "module", "vhost", "ip", "category", "severity", "rule", "type", "window_start", "window_end",
  "first_seen", "last_seen", "count", "send_at", "status", "external_id", "soc_code", "search",
  "created", "sent_at", "last_error"
]
dTextColumns = {
  "ip": "e.ip", "vhost": "e.vhost", "host": "e.host", "method": "e.method", "uri": "e.uri",
  "path": "e.path", "query": "e.query", "ua": "e.ua", "referer": "e.referer", "uid": "e.uid",
  "module": "e.module", "engine": "e.engine", "severity": "e.severity", "action": "e.action",
  "parse": "e.parse_status"
}
dNumberColumns = {
  "status": "e.status", "bytes": "e.bytes", "duration": "e.duration", "phase": "e.phase", "score": "e.score"
}
# Columns stored in lower case, so equality uses their index.
sLowerColumns = {"ip", "vhost", "host", "module", "engine", "severity", "action", "parse"}
dEngineAliases = {"on": "on", "enabled": "on", "detection-only": "detection-only", "detectiononly": "detection-only", "detection_only": "detection-only", "off": "off"}
sYes = {"yes", "true", "1", "si", "sí", "y"}
sNo = {"no", "false", "0", "n"}


def fLikePattern(pValue: str) -> str:
  vEscaped = pValue.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
  return vEscaped.replace("*", "%")


def fFtsExpression(pNode: dict) -> str:
  # Every user term becomes a quoted FTS5 string: operators and special
  # characters inside it have no meaning.
  vValue = "\"" + str(pNode["value"]).replace("\"", "\"\"") + "\""
  return vValue + "*" if pNode.get("prefix") else vValue


def fCompileNode(pNode: dict, pParameters: list) -> str:
  vOp = pNode["op"]
  if vOp in ("and", "or"):
    return "(" + (" AND " if vOp == "and" else " OR ").join(fCompileNode(dItem, pParameters) for dItem in pNode["items"]) + ")"
  if vOp == "not":
    return "(NOT COALESCE(" + fCompileNode(pNode["item"], pParameters) + ", 0))"
  if vOp == "text":
    pParameters.append(fFtsExpression(pNode))
    return "(e.id IN (SELECT r.event_id FROM records r WHERE r.id IN (SELECT rowid FROM records_fts WHERE records_fts MATCH ?) AND r.event_id IS NOT NULL))"
  return fCompileField(pNode, pParameters)


def fCompileField(pNode: dict, pParameters: list) -> str:
  vField = pNode["field"]
  vKind = pNode["kind"]
  if vField in dNumberColumns:
    vColumn = dNumberColumns[vField]
    if vKind == "range":
      pParameters.extend([pNode["low"], pNode["high"]])
      return f"({vColumn} BETWEEN ? AND ?)"
    if vKind == "compare":
      pParameters.append(pNode["value"])
      return f"({vColumn} {pNode['operator']} ?)"
    pParameters.append(pNode["value"])
    return f"({vColumn} = ?)"
  vValue = str(pNode["value"])
  if vField == "engine":
    vValue = dEngineAliases.get(vValue.lower(), vValue.lower())
  if vField == "sent":
    vAnswer = vValue.lower()
    if vAnswer not in sYes | sNo:
      raise QueryError("query_invalid_value", 0, vValue)
    vExists = "EXISTS (SELECT 1 FROM event_alerts ea JOIN alert_groups g ON g.id = ea.group_id WHERE ea.event_id = e.id AND g.status = 'sent')"
    return f"({vExists})" if vAnswer in sYes else f"(NOT {vExists})"
  if vField == "source":
    if vKind == "like":
      pParameters.append("%," + fLikePattern(vValue.lower()) + ",%")
    else:
      pParameters.append("%," + fLikePattern(vValue.lower()) + ",%")
    return "((',' || e.sources || ',') LIKE ? ESCAPE '\\')"
  if vField == "rule":
    if vKind == "like":
      pParameters.append(fLikePattern(vValue))
      return "(e.id IN (SELECT er.event_id FROM event_rules er WHERE er.rule LIKE ? ESCAPE '\\'))"
    pParameters.append(vValue)
    return "(e.id IN (SELECT er.event_id FROM event_rules er WHERE er.rule = ? COLLATE NOCASE))"
  if vField == "category":
    if vKind == "like":
      pParameters.append(fLikePattern(vValue.lower()))
      return "(e.id IN (SELECT er.event_id FROM event_rules er WHERE er.category LIKE ? ESCAPE '\\'))"
    pParameters.append(vValue.lower())
    return "(e.id IN (SELECT er.event_id FROM event_rules er WHERE er.category = ?))"
  if vField == "alert":
    if vKind == "like":
      pParameters.append(fLikePattern(vValue))
      return "(e.id IN (SELECT ea.event_id FROM event_alerts ea JOIN alert_groups g ON g.id = ea.group_id WHERE g.soc_code LIKE ? ESCAPE '\\'))"
    pParameters.append(vValue)
    return "(e.id IN (SELECT ea.event_id FROM event_alerts ea JOIN alert_groups g ON g.id = ea.group_id WHERE g.soc_code = ? COLLATE NOCASE))"
  vColumn = dTextColumns[vField]
  if vKind == "like":
    pParameters.append(fLikePattern(vValue))
    return f"({vColumn} LIKE ? ESCAPE '\\')"
  if vField in sLowerColumns:
    pParameters.append(vValue.lower())
    return f"({vColumn} = ?)"
  pParameters.append(vValue)
  return f"({vColumn} = ? COLLATE NOCASE)"


def fCompileQuery(pQuery: dict | None, pFrom: str, pTo: str) -> tuple[str, list]:
  lParameters = [pFrom, pTo]
  vWhere = "e.time >= ? AND e.time < ?"
  if pQuery is not None:
    vWhere += " AND " + fCompileNode(pQuery, lParameters)
  return vWhere, lParameters


def fSearchText(pRaw: str) -> str:
  # Text given to the full-text index: the masked line, URL-decoded too.
  vRaw = str(pRaw or "")
  try:
    vDecoded = unquote_plus(vRaw)
  except (ValueError, TypeError):
    vDecoded = vRaw
  return vRaw if vDecoded == vRaw else vRaw + "\n" + vDecoded


class SearchTimeout(Exception):
  pass


class SqliteStorage(Storage):

  def __init__(self, pPath: Path, pReadOnly: bool = False):
    self.vPath = Path(pPath)
    self.vReadOnly = pReadOnly
    self.vLocal = threading.local()
    self.vWriteLock = threading.RLock()
    self.lConnections = []
    self.vConnectionsLock = threading.Lock()

  # Connections

  def mConnection(self) -> sqlite3.Connection:
    vConnection = getattr(self.vLocal, "vConnection", None)
    if vConnection is None:
      if self.vReadOnly:
        vConnection = sqlite3.connect(f"file:{self.vPath}?mode=ro", uri=True, isolation_level=None, check_same_thread=False, timeout=10)
      else:
        vConnection = sqlite3.connect(str(self.vPath), isolation_level=None, check_same_thread=False, timeout=10)
      vConnection.row_factory = sqlite3.Row
      vConnection.execute("PRAGMA busy_timeout = 10000")
      if not self.vReadOnly:
        vConnection.execute("PRAGMA synchronous = NORMAL")
      vConnection.execute("PRAGMA temp_store = MEMORY")
      vConnection.execute("PRAGMA cache_size = -8000")
      self.vLocal.vConnection = vConnection
      with self.vConnectionsLock:
        self.lConnections.append(vConnection)
    return vConnection

  def mWrite(self, pFunction, *pArguments):
    # One write transaction at a time in this process; BEGIN IMMEDIATE takes
    # the database lock at once, so a transaction never fails half way.
    with self.vWriteLock:
      vConnection = self.mConnection()
      vConnection.execute("BEGIN IMMEDIATE")
      try:
        vResult = pFunction(vConnection, *pArguments)
        vConnection.execute("COMMIT")
        return vResult
      except BaseException:
        vConnection.execute("ROLLBACK")
        raise

  def mInitialize(self) -> None:
    self.vPath.parent.mkdir(parents=True, exist_ok=True)
    vNew = not self.vPath.exists()
    vOldUmask = os.umask(0o077)
    try:
      vConnection = self.mConnection()
    finally:
      os.umask(vOldUmask)
    if vNew:
      # Only effective before the first table exists.
      vConnection.execute("PRAGMA auto_vacuum = INCREMENTAL")
    vConnection.execute("PRAGMA journal_mode = WAL")
    with self.vWriteLock:
      vConnection.execute("BEGIN IMMEDIATE")
      try:
        for vStatement in lSchema:
          vConnection.execute(vStatement)
        vConnection.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)", (str(cSchemaVersion),))
        vConnection.execute("COMMIT")
      except BaseException:
        vConnection.execute("ROLLBACK")
        raise
    try:
      os.chmod(self.vPath, 0o600)
    except OSError:
      pass

  def mClose(self) -> None:
    with self.vConnectionsLock:
      for vConnection in self.lConnections:
        try:
          vConnection.close()
        except sqlite3.Error:
          pass
      self.lConnections = []
    self.vLocal = threading.local()

  # Sources and records

  def mGetPositions(self) -> dict:
    dPositions = {}
    for vRow in self.mConnection().execute("SELECT * FROM positions"):
      dPositions[vRow["source_key"]] = dict(vRow)
    return dPositions

  def mSaveRecords(self, pRecords: list[dict], pPositions: dict) -> list[int]:
    # Records and the positions of their files in one transaction: after a
    # crash both are there, or neither.
    def fWrite(pConnection):
      lIds = []
      for dRecord in pRecords:
        vCursor = pConnection.execute(
          "INSERT INTO records (event_id, time, received, module, source, source_key, correlation, parse_status, fields, raw) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          (
            dRecord["time"], dRecord["received"], dRecord["module"], dRecord["source"], dRecord["source_key"],
            dRecord.get("correlation"), dRecord["parse_status"], json.dumps(dRecord.get("fields", {}), ensure_ascii=False, separators=(",", ":")),
            dRecord["raw"]
          )
        )
        vId = vCursor.lastrowid
        pConnection.execute("INSERT INTO records_fts (rowid, text) VALUES (?, ?)", (vId, fSearchText(dRecord.get("search") or dRecord["raw"])))
        dRecord["id"] = vId
        lIds.append(vId)
      self.mWritePositions(pConnection, pPositions)
      return lIds
    return self.mWrite(fWrite)

  def mWritePositions(self, pConnection: sqlite3.Connection, pPositions: dict) -> None:
    for vKey, dPosition in pPositions.items():
      pConnection.execute(
        "INSERT INTO positions (source_key, path, device, inode, offset, size, updated) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(source_key) DO UPDATE SET path = excluded.path, device = excluded.device, inode = excluded.inode, offset = excluded.offset, size = excluded.size, updated = excluded.updated",
        (vKey, dPosition["path"], dPosition["device"], dPosition["inode"], dPosition["offset"], dPosition["size"], dPosition["updated"])
      )

  def mSavePositions(self, pPositions: dict) -> None:
    if pPositions:
      self.mWrite(self.mWritePositions, pPositions)

  def mLoadPendingRecords(self) -> list[dict]:
    ldRecords = []
    for vRow in self.mConnection().execute("SELECT * FROM records WHERE event_id IS NULL ORDER BY id"):
      dRecord = dict(vRow)
      dRecord["fields"] = json.loads(dRecord["fields"] or "{}")
      ldRecords.append(dRecord)
    return ldRecords

  def mDeleteRecords(self, pRecordIds: list[int]) -> None:
    def fWrite(pConnection):
      for vId in pRecordIds:
        pConnection.execute("DELETE FROM records_fts WHERE rowid = ?", (vId,))
        pConnection.execute("DELETE FROM records WHERE id = ?", (vId,))
    if pRecordIds:
      self.mWrite(fWrite)

  # Events

  def mInsertEvent(self, pConnection: sqlite3.Connection, pEvent: dict) -> int:
    lValues = []
    for vColumn in lEventColumns:
      vValue = pEvent.get(vColumn)
      if vColumn == "fields":
        vValue = json.dumps(vValue or {}, ensure_ascii=False, separators=(",", ":"))
      elif vColumn == "sources":
        vValue = ",".join(vValue) if isinstance(vValue, (list, tuple)) else (vValue or "")
      elif vColumn == "rules":
        vValue = ",".join(vValue) if isinstance(vValue, (list, tuple)) else vValue
      lValues.append(vValue)
    vCursor = pConnection.execute(
      "INSERT INTO events (" + ", ".join(lEventColumns) + ") VALUES (" + ", ".join("?" for _ in lEventColumns) + ")",
      lValues
    )
    vEventId = vCursor.lastrowid
    for dHit in pEvent.get("rule_hits", []):
      pConnection.execute(
        "INSERT OR IGNORE INTO event_rules (event_id, rule, category, time) VALUES (?, ?, ?, ?)",
        (vEventId, str(dHit["rule"]), (dHit.get("category") or "").lower() or None, pEvent["time"])
      )
    lRecordIds = pEvent.get("record_ids", [])
    for vRecordId in lRecordIds:
      pConnection.execute("UPDATE records SET event_id = ? WHERE id = ?", (vEventId, vRecordId))
    return vEventId

  def mSaveEvent(self, pEvent: dict) -> int:
    return self.mWrite(self.mInsertEvent, pEvent)

  def mSaveEvents(self, pEvents: list[dict]) -> list[int]:
    def fWrite(pConnection):
      return [self.mInsertEvent(pConnection, dEvent) for dEvent in pEvents]
    return self.mWrite(fWrite) if pEvents else []

  def mAddRuleHits(self, pEventId: int, pTime: str, pHits: list[dict]) -> None:
    def fWrite(pConnection):
      for dHit in pHits:
        pConnection.execute(
          "INSERT OR IGNORE INTO event_rules (event_id, rule, category, time) VALUES (?, ?, ?, ?)",
          (pEventId, str(dHit["rule"]), (dHit.get("category") or "").lower() or None, pTime)
        )
      vRow = pConnection.execute("SELECT rules, category FROM events WHERE id = ?", (pEventId,)).fetchone()
      if vRow is not None:
        lRules = [vRule for vRule in (vRow["rules"] or "").split(",") if vRule]
        for dHit in pHits:
          if str(dHit["rule"]) not in lRules:
            lRules.append(str(dHit["rule"]))
        vCategory = vRow["category"] or (pHits[0].get("category") if pHits else None)
        pConnection.execute("UPDATE events SET rules = ?, category = ? WHERE id = ?", (",".join(lRules), vCategory, pEventId))
    if pHits:
      self.mWrite(fWrite)

  def mSetEventSeverity(self, pEventId: int, pSeverity: str) -> None:
    dRank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    def fWrite(pConnection):
      vRow = pConnection.execute("SELECT severity FROM events WHERE id = ?", (pEventId,)).fetchone()
      if vRow is not None and dRank.get(pSeverity, 0) > dRank.get(vRow["severity"] or "", 0):
        pConnection.execute("UPDATE events SET severity = ? WHERE id = ?", (pSeverity, pEventId))
    self.mWrite(fWrite)

  def mGetIpContext(self, pIp: str, pSince: str) -> dict:
    vConnection = self.mConnection()
    vRow = vConnection.execute(
      "SELECT COUNT(*) AS total, SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked FROM events WHERE ip = ? AND time >= ?",
      (pIp, pSince)
    ).fetchone()
    lRules = [
      vItem["rule"] for vItem in vConnection.execute(
        "SELECT er.rule, COUNT(*) AS n FROM event_rules er JOIN events e ON e.id = er.event_id "
        "WHERE e.ip = ? AND e.time >= ? AND e.action = 'blocked' AND er.category IS NOT NULL AND er.rule NOT LIKE 'localsiem:%' GROUP BY er.rule ORDER BY n DESC LIMIT 10",
        (pIp, pSince)
      )
    ]
    vFirst = vConnection.execute("SELECT MIN(time) AS first FROM events WHERE ip = ?", (pIp,)).fetchone()
    return {
      "requests": vRow["total"] or 0,
      "blocked": vRow["blocked"] or 0,
      "blocked_rules": lRules,
      "first_seen": vFirst["first"] if vFirst else None
    }

  def mPathFirstSeen(self, pVhost: str, pPath: str, pTime: str) -> str:
    # When the path was first seen; it is recorded now if it was unknown.
    def fWrite(pConnection):
      pConnection.execute(
        "INSERT OR IGNORE INTO seen_paths (vhost, path, first_seen) VALUES (?, ?, ?)",
        (pVhost or "", pPath, pTime)
      )
      vRow = pConnection.execute("SELECT first_seen FROM seen_paths WHERE vhost = ? AND path = ?", (pVhost or "", pPath)).fetchone()
      return vRow["first_seen"] if vRow else pTime
    return self.mWrite(fWrite)

  def mSeenPathCount(self) -> int:
    return self.mConnection().execute("SELECT COUNT(*) AS n FROM seen_paths").fetchone()["n"]

  def mCountRecentEvents(self, pSince: str, pModule: str) -> dict:
    vConnection = self.mConnection()
    vRow = vConnection.execute(
      "SELECT COUNT(*) AS total FROM events WHERE time >= ? AND module = ? AND ip IS NOT NULL", (pSince, pModule)
    ).fetchone()
    vTop = vConnection.execute(
      "SELECT ip, COUNT(*) AS n FROM events WHERE time >= ? AND module = ? AND ip IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT 1",
      (pSince, pModule)
    ).fetchone()
    return {"total": vRow["total"] or 0, "top_ip": vTop["ip"] if vTop else None, "top_count": vTop["n"] if vTop else 0}

  # Alert groups

  def mFindOpenGroup(self, pGroupKey: str, pTime: str) -> dict | None:
    vRow = self.mConnection().execute(
      "SELECT * FROM alert_groups WHERE group_key = ? AND window_start <= ? AND window_end > ? ORDER BY id DESC LIMIT 1",
      (pGroupKey, pTime, pTime)
    ).fetchone()
    return dict(vRow) if vRow else None

  def mCreateGroup(self, pGroup: dict) -> int:
    def fWrite(pConnection):
      vRow = pConnection.execute("SELECT id FROM alert_groups WHERE external_id = ?", (pGroup["external_id"],)).fetchone()
      if vRow is not None:
        return vRow["id"]
      vCursor = pConnection.execute(
        "INSERT INTO alert_groups (group_key, module, vhost, ip, category, severity, rule, type, description, window_start, window_end, "
        "first_seen, last_seen, count, send_at, status, external_id, soc_code, details, search, sample_uids, created) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
        (
          pGroup["group_key"], pGroup["module"], pGroup["vhost"], pGroup["ip"], pGroup["category"], pGroup["severity"],
          pGroup["rule"], pGroup["type"], pGroup["description"], pGroup["window_start"], pGroup["window_end"],
          pGroup["first_seen"], pGroup["last_seen"], pGroup.get("count", 1), pGroup["send_at"], "buffer",
          pGroup["external_id"], json.dumps(pGroup.get("details", {}), ensure_ascii=False), pGroup["search"],
          json.dumps(pGroup.get("sample_uids", []), ensure_ascii=False), pGroup["created"]
        )
      )
      vGroupId = vCursor.lastrowid
      if pGroup.get("event_id"):
        pConnection.execute(
          "INSERT OR IGNORE INTO event_alerts (event_id, group_id, time) VALUES (?, ?, ?)",
          (pGroup["event_id"], vGroupId, pGroup["first_seen"])
        )
      return vGroupId
    return self.mWrite(fWrite)

  def mAddToGroup(self, pGroupId: int, pEventId: int | None, pTime: str, pUid: str) -> None:
    def fWrite(pConnection):
      vRow = pConnection.execute("SELECT sample_uids, first_seen, last_seen FROM alert_groups WHERE id = ?", (pGroupId,)).fetchone()
      if vRow is None:
        return
      lSamples = json.loads(vRow["sample_uids"] or "[]")
      if pUid and pUid not in lSamples and len(lSamples) < 5:
        lSamples.append(pUid)
      pConnection.execute(
        "UPDATE alert_groups SET count = count + 1, first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?), sample_uids = ? WHERE id = ?",
        (pTime, pTime, json.dumps(lSamples), pGroupId)
      )
      if pEventId:
        pConnection.execute(
          "INSERT OR IGNORE INTO event_alerts (event_id, group_id, time) VALUES (?, ?, ?)",
          (pEventId, pGroupId, pTime)
        )
    self.mWrite(fWrite)

  def mGetDueGroups(self, pNow: str) -> list[dict]:
    ldGroups = []
    for vRow in self.mConnection().execute(
      "SELECT * FROM alert_groups WHERE status = 'buffer' AND send_at <= ? ORDER BY send_at, id LIMIT 500", (pNow,)
    ):
      dGroup = dict(vRow)
      dGroup["details"] = json.loads(dGroup["details"] or "{}")
      dGroup["sample_uids"] = json.loads(dGroup["sample_uids"] or "[]")
      ldGroups.append(dGroup)
    return ldGroups

  def mQueueGroup(self, pGroupId: int, pPayload: str, pNow: str) -> None:
    def fWrite(pConnection):
      pConnection.execute(
        "INSERT INTO soc_queue (group_id, payload, size, status, attempts, next_attempt, created) VALUES (?, ?, ?, 'pending', 0, ?, ?)",
        (pGroupId, pPayload, len(pPayload.encode("utf-8")), pNow, pNow)
      )
      pConnection.execute("UPDATE alert_groups SET status = 'queued' WHERE id = ?", (pGroupId,))
    self.mWrite(fWrite)

  def mSkipGroup(self, pGroupId: int, pReason: str) -> None:
    # A group that is not sent (SOC not configured): kept for the panel.
    self.mWrite(lambda pConnection: pConnection.execute(
      "UPDATE alert_groups SET status = 'local', last_error = ? WHERE id = ?", (pReason, pGroupId)
    ))

  def mSkipPending(self, pReason: str) -> int:
    # The SOC is no longer configured: what waited for it in the queue stays
    # as not sent and is never sent later. The write lock is only taken when
    # something is pending (the SOC sender asks every 2 s).
    if self.mConnection().execute("SELECT 1 FROM soc_queue WHERE status = 'pending' LIMIT 1").fetchone() is None:
      return 0

    def fWrite(pConnection):
      lGroupIds = [vRow["group_id"] for vRow in pConnection.execute("SELECT group_id FROM soc_queue WHERE status = 'pending'")]
      for vGroupId in lGroupIds:
        pConnection.execute("UPDATE alert_groups SET status = 'local', last_error = ? WHERE id = ?", (pReason, vGroupId))
      pConnection.execute("DELETE FROM soc_queue WHERE status = 'pending'")
      return len(lGroupIds)
    return self.mWrite(fWrite)

  def mGetQueueBatch(self, pNow: str, pMaxAlerts: int, pMaxBytes: int) -> list[dict]:
    ldBatch = []
    vSize = 2
    for vRow in self.mConnection().execute(
      "SELECT id, group_id, payload, size, attempts FROM soc_queue WHERE status = 'pending' AND next_attempt <= ? ORDER BY id LIMIT ?",
      (pNow, pMaxAlerts)
    ):
      if ldBatch and vSize + vRow["size"] + 1 > pMaxBytes:
        break
      ldBatch.append(dict(vRow))
      vSize += vRow["size"] + 1
    return ldBatch

  def mMarkQueueSent(self, pResults: list[tuple], pNow: str) -> None:
    # pResults: (queue id, SOC alert code or None)
    def fWrite(pConnection):
      for vQueueId, vCode in pResults:
        pConnection.execute("UPDATE soc_queue SET status = 'sent', sent_at = ?, last_error = NULL WHERE id = ?", (pNow, vQueueId))
        pConnection.execute(
          "UPDATE alert_groups SET status = 'sent', sent_at = ?, soc_code = COALESCE(?, soc_code), last_error = NULL WHERE id = (SELECT group_id FROM soc_queue WHERE id = ?)",
          (pNow, vCode, vQueueId)
        )
    self.mWrite(fWrite)

  def mMarkQueueRejected(self, pQueueId: int, pError: str, pNow: str) -> None:
    def fWrite(pConnection):
      pConnection.execute("UPDATE soc_queue SET status = 'rejected', last_error = ?, sent_at = ? WHERE id = ?", (pError[:500], pNow, pQueueId))
      pConnection.execute(
        "UPDATE alert_groups SET status = 'rejected', last_error = ? WHERE id = (SELECT group_id FROM soc_queue WHERE id = ?)",
        (pError[:500], pQueueId)
      )
    self.mWrite(fWrite)

  def mDeferQueue(self, pQueueIds: list[int], pNextAttempt: str, pError: str) -> None:
    def fWrite(pConnection):
      for vQueueId in pQueueIds:
        pConnection.execute(
          "UPDATE soc_queue SET attempts = attempts + 1, next_attempt = ?, last_error = ? WHERE id = ?",
          (pNextAttempt, pError[:500], vQueueId)
        )
        pConnection.execute(
          "UPDATE alert_groups SET last_error = ? WHERE id = (SELECT group_id FROM soc_queue WHERE id = ?)",
          (pError[:500], vQueueId)
        )
    if pQueueIds:
      self.mWrite(fWrite)

  def mRetryQueueNow(self, pNow: str) -> int:
    def fWrite(pConnection):
      return pConnection.execute("UPDATE soc_queue SET next_attempt = ? WHERE status = 'pending'", (pNow,)).rowcount
    return self.mWrite(fWrite)

  def mRequeueRejected(self, pNow: str) -> int:
    def fWrite(pConnection):
      vCount = pConnection.execute(
        "UPDATE soc_queue SET status = 'pending', next_attempt = ?, attempts = 0 WHERE status = 'rejected'", (pNow,)
      ).rowcount
      pConnection.execute(
        "UPDATE alert_groups SET status = 'queued' WHERE id IN (SELECT group_id FROM soc_queue WHERE status = 'pending')"
      )
      return vCount
    return self.mWrite(fWrite)

  def mModuleCounts(self, pSince: str, pTimeout: float) -> dict:
    # {module: {events, blocked, alerted, last}} since pSince (overview and
    # modules page).
    vSql = (
      "SELECT module, COUNT(*) AS n, SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked, "
      "SUM(CASE WHEN severity IS NOT NULL THEN 1 ELSE 0 END) AS alerted, MAX(time) AS last FROM events WHERE time >= ? GROUP BY module"
    )
    return self.mRunWithTimeout(pTimeout, lambda pConnection: {
      vRow["module"]: {"events": vRow["n"], "blocked": vRow["blocked"] or 0, "alerted": vRow["alerted"] or 0, "last": vRow["last"]}
      for vRow in pConnection.execute(vSql, (pSince,))
    })

  def mAlertCounts(self, pSince: str) -> dict:
    # Alerts created since pSince: by status and by severity.
    vConnection = self.mConnection()
    return {
      "status": {vRow["status"]: vRow["n"] for vRow in vConnection.execute("SELECT status, COUNT(*) AS n FROM alert_groups WHERE created >= ? GROUP BY status", (pSince,))},
      "severity": {vRow["severity"]: vRow["n"] for vRow in vConnection.execute("SELECT severity, COUNT(*) AS n FROM alert_groups WHERE created >= ? GROUP BY severity", (pSince,))}
    }

  def mQueueStatistics(self) -> dict:
    vConnection = self.mConnection()
    dQueue = {vRow["status"]: vRow["n"] for vRow in vConnection.execute("SELECT status, COUNT(*) AS n FROM soc_queue GROUP BY status")}
    dGroups = {vRow["status"]: vRow["n"] for vRow in vConnection.execute("SELECT status, COUNT(*) AS n FROM alert_groups GROUP BY status")}
    vOldest = vConnection.execute("SELECT MIN(created) AS oldest FROM soc_queue WHERE status = 'pending'").fetchone()
    vLastError = vConnection.execute(
      "SELECT last_error FROM soc_queue WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
      "queue": dQueue, "groups": dGroups,
      "oldest_pending": vOldest["oldest"] if vOldest else None,
      "last_error": vLastError["last_error"] if vLastError else None
    }

  # State

  def mSetState(self, pKey: str, pValue) -> None:
    from backend.core.timeutil import fNowStorage
    vText = json.dumps(pValue, ensure_ascii=False)
    self.mWrite(lambda pConnection: pConnection.execute(
      "INSERT INTO state (key, value, updated) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
      (pKey, vText, fNowStorage())
    ))

  def mGetState(self, pKey: str, pDefault=None):
    vRow = self.mConnection().execute("SELECT value FROM state WHERE key = ?", (pKey,)).fetchone()
    if vRow is None:
      return pDefault
    try:
      return json.loads(vRow["value"])
    except ValueError:
      return pDefault

  def mGetStates(self, pPrefix: str) -> dict:
    dStates = {}
    for vRow in self.mConnection().execute("SELECT key, value, updated FROM state WHERE key LIKE ? ESCAPE '\\'", (fLikePattern(pPrefix) + "%",)):
      try:
        dStates[vRow["key"]] = {"value": json.loads(vRow["value"]), "updated": vRow["updated"]}
      except ValueError:
        pass
    return dStates

  # Retention

  def mDeleteOldEvents(self, pBefore: str, pLimit: int) -> int:
    # Short batches, so the collector never holds the lock for long.
    def fWrite(pConnection):
      lEventIds = [vRow["id"] for vRow in pConnection.execute("SELECT id FROM events WHERE time < ? ORDER BY time LIMIT ?", (pBefore, pLimit))]
      for vEventId in lEventIds:
        for vRecord in pConnection.execute("SELECT id FROM records WHERE event_id = ?", (vEventId,)).fetchall():
          pConnection.execute("DELETE FROM records_fts WHERE rowid = ?", (vRecord["id"],))
        pConnection.execute("DELETE FROM records WHERE event_id = ?", (vEventId,))
        pConnection.execute("DELETE FROM event_rules WHERE event_id = ?", (vEventId,))
        pConnection.execute("DELETE FROM event_alerts WHERE event_id = ?", (vEventId,))
        pConnection.execute("DELETE FROM events WHERE id = ?", (vEventId,))
      return len(lEventIds)
    return self.mWrite(fWrite)

  def mOldestEventTime(self) -> str | None:
    vRow = self.mConnection().execute("SELECT MIN(time) AS oldest FROM events").fetchone()
    return vRow["oldest"] if vRow else None

  def mDeleteOldAlerts(self, pBefore: str, pLimit: int) -> int:
    def fWrite(pConnection):
      lGroupIds = [
        vRow["id"] for vRow in pConnection.execute(
          "SELECT id FROM alert_groups WHERE last_seen < ? AND status IN ('sent', 'rejected', 'local') ORDER BY last_seen LIMIT ?",
          (pBefore, pLimit)
        )
      ]
      for vGroupId in lGroupIds:
        pConnection.execute("DELETE FROM soc_queue WHERE group_id = ?", (vGroupId,))
        pConnection.execute("DELETE FROM event_alerts WHERE group_id = ?", (vGroupId,))
        pConnection.execute("DELETE FROM alert_groups WHERE id = ?", (vGroupId,))
      pConnection.execute("DELETE FROM seen_paths WHERE first_seen < ? AND path NOT LIKE '%.php'", (pBefore,))
      return len(lGroupIds)
    return self.mWrite(fWrite)

  def mGetUsedBytes(self) -> int:
    vConnection = self.mConnection()
    vPageSize = vConnection.execute("PRAGMA page_size").fetchone()[0]
    vPages = vConnection.execute("PRAGMA page_count").fetchone()[0]
    vFree = vConnection.execute("PRAGMA freelist_count").fetchone()[0]
    return (vPages - vFree) * vPageSize

  def mGetFileBytes(self) -> int:
    vTotal = 0
    for vSuffix in ("", "-wal", "-shm"):
      try:
        vTotal += os.stat(str(self.vPath) + vSuffix).st_size
      except OSError:
        pass
    return vTotal

  def mReleaseSpace(self) -> None:
    # Gives free pages back to the file system in steps of about 4 MB.
    vConnection = self.mConnection()
    for _ in range(64):
      with self.vWriteLock:
        vFree = vConnection.execute("PRAGMA freelist_count").fetchone()[0]
        if vFree <= 0:
          break
        vConnection.execute("PRAGMA incremental_vacuum(1000)")
    with self.vWriteLock:
      try:
        vConnection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
      except sqlite3.Error:
        pass

  def mOptimize(self) -> None:
    with self.vWriteLock:
      try:
        self.mConnection().execute("PRAGMA optimize")
      except sqlite3.Error:
        pass

  # Searches

  def mRunWithTimeout(self, pTimeout: float, pFunction):
    vConnection = self.mConnection()
    vDeadline = time.monotonic() + pTimeout
    vConnection.set_progress_handler(lambda: 1 if time.monotonic() > vDeadline else 0, 20000)
    try:
      return pFunction(vConnection)
    except sqlite3.OperationalError as vError:
      if "interrupted" in str(vError).lower():
        raise SearchTimeout() from vError
      if "fts5" in str(vError).lower() or "malformed match" in str(vError).lower():
        raise QueryError("query_invalid_text", 0, str(vError)) from vError
      raise
    finally:
      vConnection.set_progress_handler(None, 0)

  def mAttachAlerts(self, pConnection: sqlite3.Connection, pRows: list[dict]) -> None:
    dById = {dRow["id"]: dRow for dRow in pRows}
    for dRow in pRows:
      dRow["alerts"] = []
    lIds = list(dById)
    for vStart in range(0, len(lIds), 500):
      lChunk = lIds[vStart:vStart + 500]
      for vRow in pConnection.execute(
        "SELECT ea.event_id, g.id AS group_id, g.soc_code, g.status, g.severity, g.rule FROM event_alerts ea JOIN alert_groups g ON g.id = ea.group_id "
        "WHERE ea.event_id IN (" + ",".join("?" for _ in lChunk) + ")",
        lChunk
      ):
        dById[vRow["event_id"]]["alerts"].append({
          "group_id": vRow["group_id"], "code": vRow["soc_code"], "status": vRow["status"],
          "severity": vRow["severity"], "rule": vRow["rule"]
        })

  def mSearch(self, pQuery, pFrom: str, pTo: str, pLimit: int, pCursor: tuple | None, pTimeout: float) -> list[dict]:
    vWhere, lParameters = fCompileQuery(pQuery, pFrom, pTo)
    if pCursor is not None:
      vWhere += " AND (e.time < ? OR (e.time = ? AND e.id < ?))"
      lParameters.extend([pCursor[0], pCursor[0], int(pCursor[1])])
    vSql = "SELECT " + ", ".join("e." + vColumn for vColumn in lListColumns) + " FROM events e WHERE " + vWhere + " ORDER BY e.time DESC, e.id DESC LIMIT ?"
    lParameters.append(int(pLimit))
    def fRun(pConnection):
      ldRows = [dict(vRow) for vRow in pConnection.execute(vSql, lParameters)]
      self.mAttachAlerts(pConnection, ldRows)
      return ldRows
    return self.mRunWithTimeout(pTimeout, fRun)

  def mSearchExport(self, pQuery, pFrom: str, pTo: str, pLimit: int, pTimeout: float) -> list[dict]:
    vWhere, lParameters = fCompileQuery(pQuery, pFrom, pTo)
    vSql = "SELECT e.* FROM events e WHERE " + vWhere + " ORDER BY e.time DESC, e.id DESC LIMIT ?"
    lParameters.append(int(pLimit))
    def fRun(pConnection):
      ldRows = []
      for vRow in pConnection.execute(vSql, lParameters):
        dRow = dict(vRow)
        dRow.pop("fields", None)
        ldRows.append(dRow)
      self.mAttachAlerts(pConnection, ldRows)
      return ldRows
    return self.mRunWithTimeout(pTimeout, fRun)

  def mCount(self, pQuery, pFrom: str, pTo: str, pTimeout: float) -> int:
    vWhere, lParameters = fCompileQuery(pQuery, pFrom, pTo)
    return self.mRunWithTimeout(pTimeout, lambda pConnection: pConnection.execute(
      "SELECT COUNT(*) AS n FROM events e WHERE " + vWhere, lParameters
    ).fetchone()["n"])

  def mHistogram(self, pQuery, pFrom: str, pTo: str, pBucket: int, pTimeout: float) -> list[dict]:
    # pBucket: characters of the storage format kept (10 day, 13 hour,
    # 15 ten minutes, 16 minute).
    vWhere, lParameters = fCompileQuery(pQuery, pFrom, pTo)
    vSql = "SELECT substr(e.time, 1, ?) AS bucket, COUNT(*) AS n, SUM(CASE WHEN e.action = 'blocked' THEN 1 ELSE 0 END) AS blocked FROM events e WHERE " + vWhere + " GROUP BY bucket ORDER BY bucket"
    return self.mRunWithTimeout(pTimeout, lambda pConnection: [
      {"bucket": vRow["bucket"], "count": vRow["n"], "blocked": vRow["blocked"] or 0}
      for vRow in pConnection.execute(vSql, [int(pBucket)] + lParameters)
    ])

  def mSummaries(self, pQuery, pFrom: str, pTo: str, pTimeout: float) -> dict:
    vWhere, lParameters = fCompileQuery(pQuery, pFrom, pTo)
    def fRun(pConnection):
      dResult = {}
      dResult["ips"] = [
        {"value": vRow["ip"], "count": vRow["n"]} for vRow in pConnection.execute(
          "SELECT e.ip, COUNT(*) AS n FROM events e WHERE " + vWhere + " AND e.ip IS NOT NULL GROUP BY e.ip ORDER BY n DESC LIMIT 10", lParameters
        )
      ]
      dResult["paths"] = [
        {"value": vRow["path"], "count": vRow["n"]} for vRow in pConnection.execute(
          "SELECT e.path, COUNT(*) AS n FROM events e WHERE " + vWhere + " AND e.path IS NOT NULL GROUP BY e.path ORDER BY n DESC LIMIT 10", lParameters
        )
      ]
      dResult["statuses"] = [
        {"value": vRow["status"], "count": vRow["n"]} for vRow in pConnection.execute(
          "SELECT e.status, COUNT(*) AS n FROM events e WHERE " + vWhere + " AND e.status IS NOT NULL GROUP BY e.status ORDER BY n DESC LIMIT 20", lParameters
        )
      ]
      dResult["rules"] = [
        {"value": vRow["rule"], "count": vRow["n"], "category": vRow["category"]} for vRow in pConnection.execute(
          "SELECT er.rule, MAX(er.category) AS category, COUNT(*) AS n FROM event_rules er WHERE er.event_id IN (SELECT e.id FROM events e WHERE " + vWhere + ") GROUP BY er.rule ORDER BY n DESC LIMIT 10",
          lParameters
        )
      ]
      return dResult
    return self.mRunWithTimeout(pTimeout, fRun)

  def mGetEventDetail(self, pEventId: int) -> dict | None:
    vConnection = self.mConnection()
    vRow = vConnection.execute("SELECT * FROM events WHERE id = ?", (int(pEventId),)).fetchone()
    if vRow is None:
      return None
    dEvent = dict(vRow)
    dEvent["fields"] = json.loads(dEvent["fields"] or "{}")
    dEvent["records"] = []
    for vRecord in vConnection.execute(
      "SELECT id, time, module, source, source_key, parse_status, fields, raw FROM records WHERE event_id = ? ORDER BY time, id", (int(pEventId),)
    ):
      dRecord = dict(vRecord)
      dRecord["fields"] = json.loads(dRecord["fields"] or "{}")
      dEvent["records"].append(dRecord)
    dEvent["rule_hits"] = [dict(vItem) for vItem in vConnection.execute("SELECT rule, category FROM event_rules WHERE event_id = ? ORDER BY rule", (int(pEventId),))]
    self.mAttachAlerts(vConnection, [dEvent])
    return dEvent

  def mGetEventsAfter(self, pQuery, pAfterId: int, pLimit: int, pTimeout: float) -> list[dict]:
    lParameters = [int(pAfterId)]
    vWhere = "e.id > ?"
    if pQuery is not None:
      vWhere += " AND " + fCompileNode(pQuery, lParameters)
    vSql = "SELECT " + ", ".join("e." + vColumn for vColumn in lListColumns) + " FROM events e WHERE " + vWhere + " ORDER BY e.id LIMIT ?"
    lParameters.append(int(pLimit))
    def fRun(pConnection):
      ldRows = [dict(vRow) for vRow in pConnection.execute(vSql, lParameters)]
      self.mAttachAlerts(pConnection, ldRows)
      return ldRows
    return self.mRunWithTimeout(pTimeout, fRun)

  def mLastEventId(self) -> int:
    vRow = self.mConnection().execute("SELECT MAX(id) AS id FROM events").fetchone()
    return vRow["id"] or 0

  def mListGroups(self, pStatus: str, pLimit: int, pBefore: int | None) -> list[dict]:
    lParameters = []
    vWhere = "1 = 1"
    if pStatus:
      vWhere += " AND status = ?"
      lParameters.append(pStatus)
    if pBefore:
      vWhere += " AND id < ?"
      lParameters.append(int(pBefore))
    lParameters.append(int(pLimit))
    return [
      dict(vRow) for vRow in self.mConnection().execute(
        "SELECT " + ", ".join(lGroupColumns) + " FROM alert_groups WHERE " + vWhere + " ORDER BY id DESC LIMIT ?", lParameters
      )
    ]

  def mGetGroup(self, pGroupId: int) -> dict | None:
    vRow = self.mConnection().execute("SELECT * FROM alert_groups WHERE id = ?", (int(pGroupId),)).fetchone()
    if vRow is None:
      return None
    dGroup = dict(vRow)
    dGroup["details"] = json.loads(dGroup["details"] or "{}")
    dGroup["sample_uids"] = json.loads(dGroup["sample_uids"] or "[]")
    vQueue = self.mConnection().execute("SELECT payload FROM soc_queue WHERE group_id = ? ORDER BY id DESC LIMIT 1", (int(pGroupId),)).fetchone()
    dGroup["payload"] = json.loads(vQueue["payload"]) if vQueue else None
    return dGroup
