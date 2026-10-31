"""Search, request card, alerts and the live view (/api/search, /api/events,
/api/alerts, /api/ws).

Every search is bounded by its time range, paginated by time (no large
OFFSET), stopped after search_timeout_seconds and recorded in the audit log
(who searched what and when: the logs hold personal data).
"""

import asyncio
import csv
import datetime
import io
import json
import time

from fastapi import HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from backend.core.config import cVersion
from backend.core.query import QueryError, fParseQuery
from backend.core.storage_sqlite import SearchTimeout
from backend.core.timeutil import fDisplayToStorage, fFormatDisplay, fNow, fParseAny, fStorageToDisplay
from backend.web.auth import cSessionCookie

lTimeColumns = ("time", "received", "first_seen", "last_seen", "window_start", "window_end", "send_at", "created", "sent_at")


def fDisplayRow(pRow: dict) -> dict:
  dRow = dict(pRow)
  for vName in lTimeColumns:
    if dRow.get(vName):
      dRow[vName] = fStorageToDisplay(dRow[vName])
  if isinstance(dRow.get("rules"), str):
    dRow["rules"] = [vRule for vRule in dRow["rules"].split(",") if vRule]
  if isinstance(dRow.get("sources"), str):
    dRow["sources"] = [vSource for vSource in dRow["sources"].split(",") if vSource]
  return dRow


def fRange(pFrom: str | None, pTo: str | None) -> tuple[str, str]:
  vNow = fNow()
  vTo = fParseAny(pTo) if pTo else vNow
  vFrom = fParseAny(pFrom) if pFrom else vTo - datetime.timedelta(hours=24)
  if (pFrom and fParseAny(pFrom) is None) or (pTo and fParseAny(pTo) is None):
    raise HTTPException(status_code=422, detail="invalid_time")
  if vFrom >= vTo:
    raise HTTPException(status_code=422, detail="invalid_range")
  return fDisplayToStorage(fFormatDisplay(vFrom)), fDisplayToStorage(fFormatDisplay(vTo))


def fParse(pQuery: str):
  try:
    return fParseQuery(pQuery or "")
  except QueryError as vError:
    raise HTTPException(status_code=400, detail={"error": "query_syntax", "code": vError.vCode, "position": vError.vPosition, "detail": vError.vDetail}) from None


def fBucketLength(pFrom: str, pTo: str) -> int:
  vSeconds = (fParseAny(pTo) - fParseAny(pFrom)).total_seconds()
  if vSeconds <= 2 * 3600:
    return 16
  if vSeconds <= 2 * 86400:
    return 15
  if vSeconds <= 14 * 86400:
    return 13
  return 10


def fRegisterSearch(pApp, pContext) -> None:

  def fTimeout() -> float:
    return float(pContext.dSettings.get("search_timeout_seconds", 5))

  async def fRun(pFunction, *pArguments):
    try:
      return await asyncio.to_thread(pFunction, *pArguments)
    except SearchTimeout:
      raise HTTPException(status_code=422, detail="search_timeout") from None
    except QueryError as vError:
      raise HTTPException(status_code=400, detail={"error": "query_syntax", "code": vError.vCode, "position": vError.vPosition, "detail": vError.vDetail}) from None

  @pApp.get("/api/search", tags=["search"], summary="Search the events")
  async def fSearch(
    pRequest: Request,
    q: str = Query("", max_length=2000, description="Query (see the manual): words, \"phrases\", field:value, wildcards, ranges, AND/OR/NOT, parentheses"),
    pFrom: str | None = Query(None, alias="from", description="Start, native format (2026/10/29@13:59:59.723)"),
    pTo: str | None = Query(None, alias="to", description="End, native format"),
    cursor: str | None = Query(None, description="next of the previous page"),
    limit: int = Query(100, ge=1, le=500)
  ):
    """Results newest first; next is the cursor of the following page (null at the end)."""
    dSession = await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dQuery = fParse(q)
    vFrom, vTo = fRange(pFrom, pTo)
    vCursor = None
    if cursor:
      vTime, vSeparator, vId = cursor.partition("|")
      vTime = fDisplayToStorage(vTime)
      if not vSeparator or not vId.isdigit() or not vTime:
        raise HTTPException(status_code=422, detail="invalid_cursor")
      vCursor = (vTime, int(vId))
    vStart = time.monotonic()
    ldRows = await fRun(pContext.mEvents().mSearch, dQuery, vFrom, vTo, limit, vCursor, fTimeout())
    vTook = int((time.monotonic() - vStart) * 1000)
    vNext = None
    if len(ldRows) == limit:
      vNext = fStorageToDisplay(ldRows[-1]["time"]) + "|" + str(ldRows[-1]["id"])
    if not cursor:
      await asyncio.to_thread(pContext.vAccounts.mAudit, dSession["username"], pContext.mClientIp(pRequest), "search", q, vFrom, vTo, len(ldRows), vTook)
    return {"results": [fDisplayRow(dRow) for dRow in ldRows], "next": vNext, "took_ms": vTook, "from": fStorageToDisplay(vFrom), "to": fStorageToDisplay(vTo)}

  @pApp.get("/api/search/histogram", tags=["search"], summary="Results over time")
  async def fHistogram(pRequest: Request, q: str = Query("", max_length=2000), pFrom: str | None = Query(None, alias="from"), pTo: str | None = Query(None, alias="to")):
    """Buckets of one minute, ten minutes, one hour or one day, by the length of the range."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dQuery = fParse(q)
    vFrom, vTo = fRange(pFrom, pTo)
    vLength = fBucketLength(vFrom, vTo)
    ldBuckets = await fRun(pContext.mEvents().mHistogram, dQuery, vFrom, vTo, vLength, fTimeout())
    dSizes = {16: 60, 15: 600, 13: 3600, 10: 86400}
    ldResult = []
    for dBucket in ldBuckets:
      vText = dBucket["bucket"]
      vStart = vText + {16: "-00.000", 15: "0-00.000", 13: "-00-00.000", 10: "@00-00-00.000"}[vLength]
      ldResult.append({"start": fStorageToDisplay(vStart), "count": dBucket["count"], "blocked": dBucket["blocked"]})
    return {"bucket_seconds": dSizes[vLength], "buckets": ldResult, "from": fStorageToDisplay(vFrom), "to": fStorageToDisplay(vTo)}

  @pApp.get("/api/search/summaries", tags=["search"], summary="Summaries of the current query")
  async def fSummaries(pRequest: Request, q: str = Query("", max_length=2000), pFrom: str | None = Query(None, alias="from"), pTo: str | None = Query(None, alias="to")):
    """IPs with most requests, most requested paths, HTTP status codes and most frequent rules."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dQuery = fParse(q)
    vFrom, vTo = fRange(pFrom, pTo)
    return await fRun(pContext.mEvents().mSummaries, dQuery, vFrom, vTo, fTimeout())

  @pApp.get("/api/search/export", tags=["search"], summary="Export the results (CSV or JSON)")
  async def fExport(pRequest: Request, q: str = Query("", max_length=2000), pFrom: str | None = Query(None, alias="from"), pTo: str | None = Query(None, alias="to"), format: str = Query("csv", pattern="^(csv|json)$")):
    """Masked data, up to export_max_rows rows (10 000 by default), newest first. Times in the storage format (2026-10-29@13-59-59.723, UTC)."""
    dSession = await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dQuery = fParse(q)
    vFrom, vTo = fRange(pFrom, pTo)
    vLimit = int(pContext.dSettings.get("export_max_rows", 10000))
    vStart = time.monotonic()
    ldRows = await fRun(pContext.mEvents().mSearchExport, dQuery, vFrom, vTo, vLimit, fTimeout() * 4)
    await asyncio.to_thread(pContext.vAccounts.mAudit, dSession["username"], pContext.mClientIp(pRequest), "export-" + format, q, vFrom, vTo, len(ldRows), int((time.monotonic() - vStart) * 1000))
    vStamp = fStorageToDisplay(vTo).replace("/", "-").replace(":", "-")
    lColumns = ["time", "received", "host", "module", "sources", "ip", "vhost", "method", "uri", "path", "query", "status", "bytes", "duration", "ua", "referer", "uid", "rules", "category", "phase", "score", "threshold", "engine", "severity", "action", "parse_status", "correlation", "alerts", "id"]
    ldOut = []
    for dRow in ldRows:
      dItem = fDisplayRow(dRow)
      # An exported file is a record: its times stay in the storage format.
      for vName in lTimeColumns:
        if dRow.get(vName):
          dItem[vName] = dRow[vName]
      dItem["alerts"] = [dAlert["code"] for dAlert in dRow.get("alerts", []) if dAlert.get("code")]
      ldOut.append({vName: dItem.get(vName) for vName in lColumns})
    if format == "json":
      return Response(json.dumps(ldOut, ensure_ascii=False, indent=1), media_type="application/json", headers={"content-disposition": f"attachment; filename=\"localsiem-{vStamp}.json\""})
    vBuffer = io.StringIO()
    vWriter = csv.writer(vBuffer)
    vWriter.writerow(lColumns)
    for dItem in ldOut:
      vWriter.writerow([
        ",".join(dItem[vName]) if isinstance(dItem.get(vName), list) else ("" if dItem.get(vName) is None else dItem[vName])
        for vName in lColumns
      ])
    return Response("﻿" + vBuffer.getvalue(), media_type="text/csv; charset=utf-8", headers={"content-disposition": f"attachment; filename=\"localsiem-{vStamp}.csv\""})

  @pApp.get("/api/events/{pEventId}", tags=["search"], summary="Request card: one event with all its records")
  async def fEvent(pEventId: int, pRequest: Request):
    """The access line, the error.log lines and the ModSecurity audit record (headers, masked body, rules and score) of the request, and the original lines."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dEvent = await asyncio.to_thread(pContext.mEvents().mGetEventDetail, pEventId)
    if dEvent is None:
      raise HTTPException(status_code=404, detail="not_found")
    dEvent = fDisplayRow(dEvent)
    dEvent["records"] = [fDisplayRow(dRecord) for dRecord in dEvent["records"]]
    for dRecord in dEvent["records"]:
      # Each module adds what it can show of its records (the Apache module:
      # headers and body of the stored, masked, audit record).
      vModule = await asyncio.to_thread(pContext.mModule, dRecord.get("module") or "")
      if vModule is not None:
        try:
          dRecord["fields"].update(vModule.mDisplayRecord(dRecord) or {})
        except Exception:
          pass
    return dEvent

  @pApp.get("/api/alerts", tags=["alerts"], summary="Alerts generated by localSIEM")
  async def fAlerts(pRequest: Request, status: str = Query("", pattern="^(|buffer|queued|sent|rejected|local)$"), before: int | None = Query(None), limit: int = Query(100, ge=1, le=500)):
    """Status buffer (gathering the burst), queued (waiting for the SOC), sent or rejected; with the SOC code, severity, rule, count, first and last time."""
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    ldGroups = await asyncio.to_thread(pContext.mEvents().mListGroups, status, limit, before)
    return {"alerts": [fDisplayRow(dGroup) for dGroup in ldGroups], "next": ldGroups[-1]["id"] if len(ldGroups) == limit else None}

  @pApp.get("/api/alerts/{pGroupId}", tags=["alerts"], summary="One alert, with what was sent to the SOC")
  async def fAlert(pGroupId: int, pRequest: Request):
    await asyncio.to_thread(pContext.mRequireSession, pRequest)
    dGroup = await asyncio.to_thread(pContext.mEvents().mGetGroup, pGroupId)
    if dGroup is None:
      raise HTTPException(status_code=404, detail="not_found")
    return fDisplayRow(dGroup)

  @pApp.get("/api/ws", tags=["live"], summary="Protocol of the live WebSocket")
  async def fWebSocketProtocol():
    return {
      "path": "/api/ws", "transport": "WebSocket",
      "authentication": "session cookie",
      "ready_frame": {"status": "ready"},
      "messages": {"type": "events", "events": "list of events (newest last)"},
      "client_frames": [{"query": "search query"}, {"paused": True}],
      "authentication_close_code": 4401, "forbidden_close_code": 4403
    }

  @pApp.websocket("/api/ws")
  async def fLive(pWebSocket: WebSocket):
    await pWebSocket.accept()
    # Only a signed-in session opens the live view.
    dSession = await asyncio.to_thread(pContext.vAccounts.mLoadSession, pWebSocket.cookies.get(cSessionCookie, ""))
    if dSession is None:
      await pWebSocket.close(code=4401)
      return
    await pWebSocket.send_json({"status": "ready", "version": cVersion})
    dState = {"query": None, "paused": False, "last": 0}
    try:
      vStorage = pContext.mEvents()
      dState["last"] = max(0, await asyncio.to_thread(vStorage.mLastEventId) - 50)
    except HTTPException:
      vStorage = None

    async def fReceive():
      while True:
        vText = await pWebSocket.receive_text()
        try:
          dMessage = json.loads(vText)
        except ValueError:
          continue
        if not isinstance(dMessage, dict):
          continue
        if "query" in dMessage:
          try:
            dState["query"] = fParseQuery(str(dMessage.get("query") or ""))
            await pWebSocket.send_json({"type": "query", "ok": True})
          except QueryError as vError:
            await pWebSocket.send_json({"type": "query", "ok": False, "code": vError.vCode, "position": vError.vPosition})
        if "paused" in dMessage:
          dState["paused"] = bool(dMessage["paused"])

    vReceiver = asyncio.create_task(fReceive())
    try:
      while not vReceiver.done():
        dCheck = await asyncio.to_thread(pContext.vAccounts.mLoadSession, pWebSocket.cookies.get(cSessionCookie, ""))
        if dCheck is None:
          await pWebSocket.close(code=4401)
          return
        if not dState["paused"]:
          if vStorage is None:
            try:
              vStorage = pContext.mEvents()
            except HTTPException:
              vStorage = None
          if vStorage is not None:
            try:
              ldRows = await asyncio.to_thread(vStorage.mGetEventsAfter, dState["query"], dState["last"], 200, 3.0)
            except (SearchTimeout, QueryError):
              ldRows = []
            if ldRows:
              dState["last"] = ldRows[-1]["id"]
              await pWebSocket.send_json({"type": "events", "events": [fDisplayRow(dRow) for dRow in ldRows]})
            elif dState["last"] == 0:
              dState["last"] = await asyncio.to_thread(vStorage.mLastEventId)
        else:
          # While paused the position follows the newest event, so resuming
          # does not flood the page with what happened meanwhile.
          if vStorage is not None:
            dState["last"] = await asyncio.to_thread(vStorage.mLastEventId)
        await asyncio.wait([vReceiver], timeout=1.0)
    except (WebSocketDisconnect, RuntimeError):
      pass
    finally:
      vReceiver.cancel()
