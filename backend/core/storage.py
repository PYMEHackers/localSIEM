"""Storage interface.

The collector, the modules and the web only talk to an object with these
methods, so a PostgreSQL implementation (central mode) can be added later
without touching the modules. Today the only implementation is SQLite
(storage_sqlite.SqliteStorage).

Vocabulary:

  record   one line or one audit entry as read from a source, already masked.
           It is stored as soon as it is read, together with the position of
           its file, so a restart never loses or repeats it.
  event    one request (or one standalone record): the records with the same
           correlation key (UNIQUE_ID in Apache) joined after the correlation
           window. Searches return events.
  group    one alert for the SOC: detections with the same module, vhost, IP,
           category and severity inside the grouping window.
"""


class Storage:

  # Lifecycle

  def mInitialize(self) -> None:
    raise NotImplementedError

  def mClose(self) -> None:
    raise NotImplementedError

  # Sources and records (collector)

  def mGetPositions(self) -> dict:
    raise NotImplementedError

  def mSaveRecords(self, pRecords: list[dict], pPositions: dict) -> list[int]:
    raise NotImplementedError

  def mSavePositions(self, pPositions: dict) -> None:
    raise NotImplementedError

  def mLoadPendingRecords(self) -> list[dict]:
    raise NotImplementedError

  # Events (collector)

  def mSaveEvent(self, pEvent: dict) -> int:
    raise NotImplementedError

  def mGetIpContext(self, pIp: str, pSince: str) -> dict:
    raise NotImplementedError

  def mPathFirstSeen(self, pVhost: str, pPath: str, pTime: str) -> str:
    raise NotImplementedError

  # Alert groups and the SOC queue (collector)

  def mFindOpenGroup(self, pGroupKey: str, pTime: str) -> dict | None:
    raise NotImplementedError

  def mCreateGroup(self, pGroup: dict) -> int:
    raise NotImplementedError

  def mAddToGroup(self, pGroupId: int, pEventId: int | None, pTime: str, pUid: str) -> None:
    raise NotImplementedError

  def mGetDueGroups(self, pNow: str) -> list[dict]:
    raise NotImplementedError

  def mQueueGroup(self, pGroupId: int, pPayload: str, pNow: str) -> None:
    raise NotImplementedError

  def mSkipGroup(self, pGroupId: int, pReason: str) -> None:
    raise NotImplementedError

  def mSkipPending(self, pReason: str) -> int:
    raise NotImplementedError

  def mGetQueueBatch(self, pNow: str, pMaxAlerts: int, pMaxBytes: int) -> list[dict]:
    raise NotImplementedError

  def mMarkQueueSent(self, pResults: list[tuple], pNow: str) -> None:
    raise NotImplementedError

  def mMarkQueueRejected(self, pQueueId: int, pError: str, pNow: str) -> None:
    raise NotImplementedError

  def mDeferQueue(self, pQueueIds: list[int], pNextAttempt: str, pError: str) -> None:
    raise NotImplementedError

  # State shared with the web (collector writes, web reads)

  def mSetState(self, pKey: str, pValue) -> None:
    raise NotImplementedError

  def mGetState(self, pKey: str, pDefault=None):
    raise NotImplementedError

  # Retention (collector)

  def mDeleteOldEvents(self, pBefore: str, pLimit: int) -> int:
    raise NotImplementedError

  def mDeleteOldAlerts(self, pBefore: str, pLimit: int) -> int:
    raise NotImplementedError

  def mGetUsedBytes(self) -> int:
    raise NotImplementedError

  def mReleaseSpace(self) -> None:
    raise NotImplementedError

  # Searches (web, read only)

  def mSearch(self, pQuery, pFrom: str, pTo: str, pLimit: int, pCursor: tuple | None, pTimeout: float) -> list[dict]:
    raise NotImplementedError

  def mHistogram(self, pQuery, pFrom: str, pTo: str, pBucket: int, pTimeout: float) -> list[dict]:
    raise NotImplementedError

  def mSummaries(self, pQuery, pFrom: str, pTo: str, pTimeout: float) -> dict:
    raise NotImplementedError

  def mGetEventDetail(self, pEventId: int) -> dict | None:
    raise NotImplementedError

  def mGetEventsAfter(self, pQuery, pAfterId: int, pLimit: int, pTimeout: float) -> list[dict]:
    raise NotImplementedError

  def mListGroups(self, pStatus: str, pLimit: int, pBefore: int | None) -> list[dict]:
    raise NotImplementedError

  def mQueueStatistics(self) -> dict:
    raise NotImplementedError

  def mModuleCounts(self, pSince: str, pTimeout: float) -> dict:
    raise NotImplementedError

  def mAlertCounts(self, pSince: str) -> dict:
    raise NotImplementedError
