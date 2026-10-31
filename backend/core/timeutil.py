"""Dates and times in the native formats of the project.

Stored values are UTC in the storage format 2026-10-29@13-59-59.723: fixed
width, so they sort correctly as text. Values shown to people use the display
format 2026/10/29@13:59:59.723. Every other format is computed from these.
"""

import datetime
import re

cUtc = datetime.UTC
cStorageRegex = re.compile(r"^(\d{4})-(\d{2})-(\d{2})@(\d{2})-(\d{2})-(\d{2})\.(\d{3})(?:([+-])(\d{2})(\d{2}))?$")
cDisplayRegex = re.compile(r"^(\d{4})/(\d{2})/(\d{2})@(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(?:([+-])(\d{2}):?(\d{2}))?$")
dMonths = {
  "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
  "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
}
# [27/Oct/2026:10:14:03 +0100], with optional fractions of a second.
cApacheAccessRegex = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))? ([+-])(\d{2})(\d{2})$")
# Tue Oct 27 10:14:03.512345 2026 (local time of the server, no offset).
cApacheErrorRegex = re.compile(r"^[A-Za-z]{3} ([A-Za-z]{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))? (\d{4})$")


def fFormatStorage(pDateTime: datetime.datetime) -> str:
  if pDateTime.tzinfo is None:
    pDateTime = pDateTime.replace(tzinfo=cUtc)
  vUtc = pDateTime.astimezone(cUtc)
  return f"{vUtc.year:04d}-{vUtc.month:02d}-{vUtc.day:02d}@{vUtc.hour:02d}-{vUtc.minute:02d}-{vUtc.second:02d}.{vUtc.microsecond // 1000:03d}"


def fFormatDisplay(pDateTime: datetime.datetime) -> str:
  if pDateTime.tzinfo is None:
    pDateTime = pDateTime.replace(tzinfo=cUtc)
  vUtc = pDateTime.astimezone(cUtc)
  return f"{vUtc.year:04d}/{vUtc.month:02d}/{vUtc.day:02d}@{vUtc.hour:02d}:{vUtc.minute:02d}:{vUtc.second:02d}.{vUtc.microsecond // 1000:03d}"


def fNow() -> datetime.datetime:
  return datetime.datetime.now(cUtc)


def fNowStorage() -> str:
  return fFormatStorage(fNow())


def fStorageFromNow(pSeconds: float) -> str:
  # Now plus pSeconds (negative values are in the past), in the storage format.
  return fFormatStorage(fNow() + datetime.timedelta(seconds=pSeconds))


def fApplyOffset(pDateTime: datetime.datetime, pSign: str | None, pHours: str | None, pMinutes: str | None) -> datetime.datetime:
  # The digits are the local time of that offset: UTC is the time minus the offset.
  if not pSign:
    return pDateTime
  vOffset = datetime.timedelta(hours=int(pHours), minutes=int(pMinutes))
  return pDateTime - vOffset if pSign == "+" else pDateTime + vOffset


def fParseStorage(pValue: str) -> datetime.datetime | None:
  vMatch = cStorageRegex.match(str(pValue or "").strip())
  if not vMatch:
    return None
  aParts = vMatch.groups()
  try:
    vTime = datetime.datetime(
      int(aParts[0]), int(aParts[1]), int(aParts[2]), int(aParts[3]), int(aParts[4]), int(aParts[5]),
      int(aParts[6]) * 1000, tzinfo=cUtc
    )
  except ValueError:
    return None
  return fApplyOffset(vTime, aParts[7], aParts[8], aParts[9])


def fParseDisplay(pValue: str) -> datetime.datetime | None:
  vMatch = cDisplayRegex.match(str(pValue or "").strip())
  if not vMatch:
    return None
  aParts = vMatch.groups()
  try:
    vTime = datetime.datetime(
      int(aParts[0]), int(aParts[1]), int(aParts[2]), int(aParts[3]), int(aParts[4]), int(aParts[5]),
      int((aParts[6] or "0").ljust(3, "0")) * 1000, tzinfo=cUtc
    )
  except ValueError:
    return None
  return fApplyOffset(vTime, aParts[7], aParts[8], aParts[9])


def fParseAny(pValue: str) -> datetime.datetime | None:
  # Storage or display format, with or without an offset.
  return fParseStorage(pValue) or fParseDisplay(pValue)


def fStorageToDisplay(pValue: str | None) -> str:
  vTime = fParseStorage(pValue) if pValue else None
  return fFormatDisplay(vTime) if vTime else ""


def fDisplayToStorage(pValue: str | None) -> str:
  vTime = fParseAny(pValue) if pValue else None
  return fFormatStorage(vTime) if vTime else ""


def fStorageToEpoch(pValue: str) -> float:
  vTime = fParseStorage(pValue)
  return vTime.timestamp() if vTime else 0.0


def fEpochToStorage(pEpoch: float) -> str:
  return fFormatStorage(datetime.datetime.fromtimestamp(pEpoch, cUtc))


def fParseApacheAccessTime(pValue: str) -> datetime.datetime | None:
  # Access log and audit log time: local time with its offset.
  vMatch = cApacheAccessRegex.match(str(pValue or "").strip())
  if not vMatch:
    return None
  aParts = vMatch.groups()
  vMonth = dMonths.get(aParts[1].lower())
  if vMonth is None:
    return None
  try:
    vTime = datetime.datetime(
      int(aParts[2]), vMonth, int(aParts[0]), int(aParts[3]), int(aParts[4]), int(aParts[5]),
      int((aParts[6] or "0").ljust(6, "0")[:6]), tzinfo=cUtc
    )
  except ValueError:
    return None
  return fApplyOffset(vTime, aParts[7], aParts[8], aParts[9])


def fParseApacheErrorTime(pValue: str) -> datetime.datetime | None:
  # error.log writes the local time of the server without an offset: the
  # time zone of this process (the system one) converts it to UTC.
  vMatch = cApacheErrorRegex.match(str(pValue or "").strip())
  if not vMatch:
    return None
  aParts = vMatch.groups()
  vMonth = dMonths.get(aParts[0].lower())
  if vMonth is None:
    return None
  try:
    vLocal = datetime.datetime(
      int(aParts[6]), vMonth, int(aParts[1]), int(aParts[2]), int(aParts[3]), int(aParts[4]),
      int((aParts[5] or "0").ljust(6, "0")[:6])
    )
  except ValueError:
    return None
  return vLocal.astimezone(cUtc)
