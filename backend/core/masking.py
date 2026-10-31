"""Masking of sensitive values before anything is stored.

A parameter or JSON key is sensitive when one of the words of its name (split
on anything that is not a letter or a digit) is in the configured list:
user_password, new-pass and pwd are masked; author is not. Headers are matched
by their whole name. Masked values become ***.
"""

import json
import re
from urllib.parse import unquote_plus

cMask = "***"
cWordRegex = re.compile(r"[A-Za-z0-9]+")


class Masker:

  def __init__(self, pParameters: list[str], pHeaders: list[str]):
    self.sParameters = {vName.lower() for vName in pParameters}
    self.sHeaders = {vName.lower() for vName in pHeaders}
    # name=value inside URLs, forms and free text.
    self.vPairRegex = re.compile(r"(?i)((?:^|[?&;\s\"'])([A-Za-z0-9_.\[\]%-]*?)=)([^&;\s\"']*)")
    # ModSecurity variable references: ARGS:password: secret, ARGS:json.user.pwd: secret
    self.vModsecRegex = re.compile(r"(?i)((?:ARGS|ARGS_POST|ARGS_GET|REQUEST_COOKIES|REQUEST_HEADERS):([^:\s\]\"]+):\s?)(.*?)(?=$|\"\]|\] \[|\s\[)")
    self.vHeaderRegex = re.compile(
      r"(?im)^(\s*(" + "|".join(re.escape(vName) for vName in self.sHeaders) + r")\s*:\s*)(.*)$"
    ) if self.sHeaders else None
    # "password":"value" inside JSON text that could not be parsed.
    self.vJsonPairRegex = re.compile(r"(?i)(\"([A-Za-z0-9_.-]*)\"\s*:\s*)(\"(?:[^\"\\]|\\.)*\"|[^,}\s]+)")

  def mIsSensitiveName(self, pName: str) -> bool:
    vName = unquote_plus(str(pName or "")).lower()
    if vName in self.sParameters:
      return True
    return any(vWord in self.sParameters for vWord in cWordRegex.findall(vName))

  def mIsSensitiveHeader(self, pName: str) -> bool:
    return str(pName or "").strip().lower() in self.sHeaders

  def mMaskPairs(self, pText: str) -> str:
    def fReplace(pMatch):
      if self.mIsSensitiveName(pMatch.group(2)) and pMatch.group(3):
        return pMatch.group(1) + cMask
      return pMatch.group(0)
    return self.vPairRegex.sub(fReplace, pText)

  def mMaskUri(self, pUri: str) -> str:
    vUri = str(pUri or "")
    vPath, vSeparator, vQuery = vUri.partition("?")
    if not vSeparator:
      return vUri
    lParts = []
    for vPart in vQuery.split("&"):
      vName, vEquals, vValue = vPart.partition("=")
      if vEquals and vValue and self.mIsSensitiveName(vName):
        lParts.append(vName + "=" + cMask)
      else:
        lParts.append(vPart)
    return vPath + "?" + "&".join(lParts)

  def mMaskForm(self, pBody: str) -> str:
    lParts = []
    for vPart in str(pBody or "").split("&"):
      vName, vEquals, vValue = vPart.partition("=")
      if vEquals and vValue and self.mIsSensitiveName(vName):
        lParts.append(vName + "=" + cMask)
      else:
        lParts.append(vPart)
    return "&".join(lParts)

  def mMaskJsonValue(self, pValue):
    if isinstance(pValue, dict):
      dResult = {}
      for vKey, vItem in pValue.items():
        if self.mIsSensitiveName(vKey) and not isinstance(vItem, (dict, list)):
          dResult[vKey] = cMask
        else:
          dResult[vKey] = self.mMaskJsonValue(vItem)
      return dResult
    if isinstance(pValue, list):
      return [self.mMaskJsonValue(vItem) for vItem in pValue]
    return pValue

  def mMaskJsonText(self, pText: str) -> str:
    try:
      return json.dumps(self.mMaskJsonValue(json.loads(pText)), ensure_ascii=False)
    except (ValueError, TypeError):
      def fReplace(pMatch):
        if self.mIsSensitiveName(pMatch.group(2)):
          return pMatch.group(1) + "\"" + cMask + "\""
        return pMatch.group(0)
      return self.vJsonPairRegex.sub(fReplace, str(pText or ""))

  def mMaskBody(self, pBody: str, pContentType: str = "") -> str:
    vBody = str(pBody or "")
    vType = str(pContentType or "").lower()
    vStripped = vBody.lstrip()
    if "json" in vType or vStripped.startswith("{") or vStripped.startswith("["):
      return self.mMaskJsonText(vBody)
    if "multipart" in vType:
      return self.mMaskMultipart(vBody)
    return self.mMaskText(self.mMaskForm(vBody))

  def mMaskMultipart(self, pBody: str) -> str:
    # Content-Disposition: form-data; name="password" followed by the value.
    return re.sub(
      r"(?is)(name=\"([^\"]*)\"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)(.*?)(?=\r?\n--)",
      lambda pMatch: pMatch.group(1) + cMask if self.mIsSensitiveName(pMatch.group(2)) else pMatch.group(0),
      pBody
    )

  def mMaskHeaders(self, pHeaders: dict) -> dict:
    return {
      vName: (cMask if self.mIsSensitiveHeader(vName) else vValue)
      for vName, vValue in (pHeaders or {}).items()
    }

  def mMaskHeaderText(self, pText: str) -> str:
    if self.vHeaderRegex is None:
      return pText
    return self.vHeaderRegex.sub(lambda pMatch: pMatch.group(1) + cMask, pText)

  def mMaskModsec(self, pText: str) -> str:
    def fReplace(pMatch):
      vName = pMatch.group(2)
      vLast = re.split(r"[.:]", vName)[-1]
      if self.mIsSensitiveName(vName) or self.mIsSensitiveName(vLast) or self.mIsSensitiveHeader(vLast):
        return pMatch.group(1) + cMask
      return pMatch.group(0)
    return self.vModsecRegex.sub(fReplace, pText)

  def mMaskText(self, pText: str) -> str:
    # Free text: a log line, a ModSecurity message.
    vText = str(pText or "")
    vText = self.mMaskModsec(vText)
    vText = self.mMaskPairs(vText)
    vText = self.mMaskHeaderText(vText)
    return vText


def fCreateMasker(pSettings: dict) -> Masker:
  dMasking = pSettings.get("masking", {})
  return Masker(dMasking.get("parameters", []), dMasking.get("headers", []))


def fTrim(pText: str, pLength: int) -> str:
  vText = str(pText or "")
  return vText if len(vText) <= pLength else vText[:pLength] + "…"
