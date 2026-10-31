"""Database of the web: accounts, sessions, login attempts, the access tokens
of the direct sign-in, the record of every sign-in and the audit log of the
searches (/opt/localsiem/db/localsiem-web.db, mode 600).

It is a separate file from the events database so the collector stays the
only process that writes events; the web is the only one that writes here.
"""

import os
import sqlite3
import threading
from pathlib import Path

lSchema = [
  """CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    language TEXT NOT NULL DEFAULT 'en-US',
    totp_secret TEXT,
    totp_pending_secret TEXT,
    totp_enabled_at TEXT,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    password_changed_at TEXT
  )""",
  """CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
  )""",
  "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)",
  """CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,
    attempted_at TEXT NOT NULL
  )""",
  "CREATE INDEX IF NOT EXISTS login_attempts_lookup ON login_attempts(username, ip, attempted_at)",
  "CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts(ip, attempted_at)",
  """CREATE TABLE IF NOT EXISTS search_audit (
    id INTEGER PRIMARY KEY,
    time TEXT NOT NULL,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    kind TEXT NOT NULL,
    query TEXT NOT NULL,
    range_from TEXT NOT NULL,
    range_to TEXT NOT NULL,
    results INTEGER,
    took_ms INTEGER
  )""",
  "CREATE INDEX IF NOT EXISTS search_audit_time ON search_audit(time)",
  # Direct sign-in (/auth/login/auto?token=...): only the hash of the token is
  # kept; token_hint is its last 4 characters, to tell tokens apart.
  """CREATE TABLE IF NOT EXISTS access_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    last_used_ip TEXT,
    revoked_at TEXT
  )""",
  "CREATE INDEX IF NOT EXISTS access_tokens_user ON access_tokens(user_id)",
  # Every sign-in, with a password or with a token, and every failed attempt.
  """CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY,
    time TEXT NOT NULL,
    username TEXT NOT NULL,
    method TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    token_id INTEGER
  )""",
  "CREATE INDEX IF NOT EXISTS logins_time ON logins(time)"
]
# Columns added to tables of older versions: (table, column, definition).
lColumns = [
  ("sessions", "method", "TEXT NOT NULL DEFAULT 'password'")
]


class WebDatabase:

  def __init__(self, pPath: Path):
    self.vPath = Path(pPath)
    self.vLocal = threading.local()
    self.vLock = threading.RLock()

  def mConnection(self) -> sqlite3.Connection:
    vConnection = getattr(self.vLocal, "vConnection", None)
    if vConnection is None:
      vConnection = sqlite3.connect(str(self.vPath), isolation_level=None, check_same_thread=False, timeout=10)
      vConnection.row_factory = sqlite3.Row
      vConnection.execute("PRAGMA busy_timeout = 10000")
      vConnection.execute("PRAGMA foreign_keys = ON")
      self.vLocal.vConnection = vConnection
    return vConnection

  def mInitialize(self) -> None:
    self.vPath.parent.mkdir(parents=True, exist_ok=True)
    vOldUmask = os.umask(0o077)
    try:
      vConnection = self.mConnection()
    finally:
      os.umask(vOldUmask)
    vConnection.execute("PRAGMA journal_mode = WAL")
    self.mWrite(lambda pConnection: [pConnection.execute(vStatement) for vStatement in lSchema])

    def fAddColumns(pConnection):
      for vTable, vColumn, vDefinition in lColumns:
        if vColumn not in [vRow["name"] for vRow in pConnection.execute(f"PRAGMA table_info({vTable})")]:
          pConnection.execute(f"ALTER TABLE {vTable} ADD COLUMN {vColumn} {vDefinition}")
    self.mWrite(fAddColumns)
    try:
      os.chmod(self.vPath, 0o600)
    except OSError:
      pass

  def mWrite(self, pFunction, *pArguments):
    with self.vLock:
      vConnection = self.mConnection()
      vConnection.execute("BEGIN IMMEDIATE")
      try:
        vResult = pFunction(vConnection, *pArguments)
        vConnection.execute("COMMIT")
        return vResult
      except BaseException:
        vConnection.execute("ROLLBACK")
        raise

  def mOne(self, pSql: str, pParameters=()) -> dict | None:
    vRow = self.mConnection().execute(pSql, pParameters).fetchone()
    return dict(vRow) if vRow else None

  def mAll(self, pSql: str, pParameters=()) -> list[dict]:
    return [dict(vRow) for vRow in self.mConnection().execute(pSql, pParameters)]
