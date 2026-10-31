"""Search language: one text field, parsed into a tree.

  words            full-text search on the original (masked) text
  "exact phrase"
  field:value      case-insensitive on text fields; field:"value with spaces"
  field:*part*     wildcards
  status:>=500     comparisons on numeric fields: > >= < <=
  status:400..499  ranges
  AND (implicit), OR, NOT or a leading -, and parentheses

The tree never becomes SQL here: each storage compiles it with parameters
(storage_sqlite.fCompileQuery), so no user text is ever concatenated into SQL.
"""

import re

cMaxQueryLength = 2000
cMaxTerms = 60

dFields = {
  "ip": "text", "vhost": "text", "host": "text",
  "method": "text", "uri": "text", "path": "text", "query": "text",
  "status": "number", "bytes": "number", "duration": "number",
  "ua": "text", "referer": "text",
  "uid": "text", "module": "text", "source": "text",
  "rule": "text", "category": "text", "phase": "number", "score": "number", "engine": "text",
  "severity": "text", "action": "text", "alert": "text", "sent": "text",
  "parse": "text"
}
dFieldAliases = {"useragent": "ua", "user_agent": "ua", "unique_id": "uid", "code": "status"}
cNumberRegex = re.compile(r"^-?\d+$")
cRangeRegex = re.compile(r"^(-?\d+)\.\.(-?\d+)$")
cComparisonRegex = re.compile(r"^(>=|<=|>|<)(-?\d+)$")


class QueryError(ValueError):

  def __init__(self, pCode: str, pPosition: int, pDetail: str = ""):
    super().__init__(pCode)
    self.vCode = pCode
    self.vPosition = pPosition
    self.vDetail = pDetail


def fTokenize(pText: str) -> list[dict]:
  lTokens = []
  vIndex = 0
  vLength = len(pText)
  while vIndex < vLength:
    vChar = pText[vIndex]
    if vChar.isspace():
      vIndex += 1
      continue
    if vChar in "()":
      lTokens.append({"type": vChar, "value": vChar, "position": vIndex})
      vIndex += 1
      continue
    if vChar == "-" and vIndex + 1 < vLength and not pText[vIndex + 1].isspace() and pText[vIndex + 1] != ")":
      # A leading minus is NOT; a minus inside a word is part of the word.
      if not lTokens or lTokens[-1]["type"] in ("(", "op", "not") or (vIndex > 0 and pText[vIndex - 1].isspace()):
        lTokens.append({"type": "not", "value": "-", "position": vIndex})
        vIndex += 1
        continue
    if vChar == "\"":
      vValue, vEnd = fReadQuoted(pText, vIndex)
      lTokens.append({"type": "phrase", "value": vValue, "position": vIndex})
      vIndex = vEnd
      continue
    vStart = vIndex
    while vIndex < vLength and not pText[vIndex].isspace() and pText[vIndex] not in "()\"":
      vIndex += 1
    vWord = pText[vStart:vIndex]
    vName, vColon, vValue = vWord.partition(":")
    vField = dFieldAliases.get(vName.lower(), vName.lower())
    if vColon and vField in dFields:
      if vValue == "" and vIndex < vLength and pText[vIndex] == "\"":
        vValue, vIndex = fReadQuoted(pText, vIndex)
        lTokens.append({"type": "field", "field": vField, "value": vValue, "quoted": True, "position": vStart})
        continue
      if vValue == "":
        raise QueryError("query_empty_value", vStart, vName)
      lTokens.append({"type": "field", "field": vField, "value": vValue, "quoted": False, "position": vStart})
      continue
    if vWord in ("AND", "OR"):
      lTokens.append({"type": "op", "value": vWord, "position": vStart})
      continue
    if vWord == "NOT":
      lTokens.append({"type": "not", "value": vWord, "position": vStart})
      continue
    lTokens.append({"type": "word", "value": vWord, "position": vStart})
  return lTokens


def fReadQuoted(pText: str, pStart: int) -> tuple[str, int]:
  # pStart is the opening quote. \" inside the value is a literal quote.
  lChars = []
  vIndex = pStart + 1
  while vIndex < len(pText):
    vChar = pText[vIndex]
    if vChar == "\\" and vIndex + 1 < len(pText) and pText[vIndex + 1] == "\"":
      lChars.append("\"")
      vIndex += 2
      continue
    if vChar == "\"":
      return "".join(lChars), vIndex + 1
    lChars.append(vChar)
    vIndex += 1
  raise QueryError("query_unclosed_quote", pStart)


class Parser:

  def __init__(self, pTokens: list[dict], pLength: int):
    self.lTokens = pTokens
    self.vIndex = 0
    self.vLength = pLength
    self.vTerms = 0

  def mPeek(self) -> dict | None:
    return self.lTokens[self.vIndex] if self.vIndex < len(self.lTokens) else None

  def mNext(self) -> dict:
    vToken = self.lTokens[self.vIndex]
    self.vIndex += 1
    return vToken

  def mParse(self) -> dict | None:
    if not self.lTokens:
      return None
    dNode = self.mParseOr()
    vToken = self.mPeek()
    if vToken is not None:
      if vToken["type"] == ")":
        raise QueryError("query_unbalanced_parenthesis", vToken["position"])
      raise QueryError("query_unexpected", vToken["position"], vToken["value"])
    return dNode

  def mParseOr(self) -> dict:
    lItems = [self.mParseAnd()]
    while True:
      vToken = self.mPeek()
      if vToken is None or not (vToken["type"] == "op" and vToken["value"] == "OR"):
        break
      self.mNext()
      if self.mPeek() is None:
        raise QueryError("query_missing_term", self.vLength, "OR")
      lItems.append(self.mParseAnd())
    return lItems[0] if len(lItems) == 1 else {"op": "or", "items": lItems}

  def mParseAnd(self) -> dict:
    lItems = [self.mParseUnary()]
    while True:
      vToken = self.mPeek()
      if vToken is None or vToken["type"] == ")" or (vToken["type"] == "op" and vToken["value"] == "OR"):
        break
      if vToken["type"] == "op" and vToken["value"] == "AND":
        self.mNext()
        if self.mPeek() is None:
          raise QueryError("query_missing_term", self.vLength, "AND")
      lItems.append(self.mParseUnary())
    return lItems[0] if len(lItems) == 1 else {"op": "and", "items": lItems}

  def mParseUnary(self) -> dict:
    vToken = self.mPeek()
    if vToken is None:
      raise QueryError("query_missing_term", self.vLength)
    if vToken["type"] == "not":
      self.mNext()
      if self.mPeek() is None:
        raise QueryError("query_missing_term", self.vLength, "NOT")
      return {"op": "not", "item": self.mParseUnary()}
    return self.mParsePrimary()

  def mParsePrimary(self) -> dict:
    vToken = self.mNext()
    if vToken["type"] == "(":
      if self.mPeek() is None or self.mPeek()["type"] == ")":
        raise QueryError("query_empty_group", vToken["position"])
      dNode = self.mParseOr()
      vClosing = self.mPeek()
      if vClosing is None or vClosing["type"] != ")":
        raise QueryError("query_unbalanced_parenthesis", vToken["position"])
      self.mNext()
      return dNode
    if vToken["type"] == ")":
      raise QueryError("query_unbalanced_parenthesis", vToken["position"])
    if vToken["type"] == "op":
      raise QueryError("query_missing_term", vToken["position"], vToken["value"])
    self.vTerms += 1
    if self.vTerms > cMaxTerms:
      raise QueryError("query_too_many_terms", vToken["position"])
    if vToken["type"] == "phrase":
      if not vToken["value"].strip():
        raise QueryError("query_empty_value", vToken["position"])
      return {"op": "text", "value": vToken["value"], "phrase": True, "prefix": False}
    if vToken["type"] == "word":
      vValue = vToken["value"]
      vPrefix = vValue.endswith("*") and len(vValue.rstrip("*")) > 0
      vValue = vValue.rstrip("*") if vPrefix else vValue
      if not vValue.strip("*"):
        raise QueryError("query_empty_value", vToken["position"])
      return {"op": "text", "value": vValue, "phrase": False, "prefix": vPrefix}
    return fBuildFieldNode(vToken)


def fBuildFieldNode(pToken: dict) -> dict:
  vField = pToken["field"]
  vValue = pToken["value"]
  vPosition = pToken["position"]
  if dFields[vField] == "number":
    vMatch = cRangeRegex.match(vValue)
    if vMatch:
      vLow, vHigh = int(vMatch.group(1)), int(vMatch.group(2))
      if vLow > vHigh:
        raise QueryError("query_invalid_range", vPosition, vValue)
      return {"op": "field", "field": vField, "kind": "range", "low": vLow, "high": vHigh}
    vMatch = cComparisonRegex.match(vValue)
    if vMatch:
      return {"op": "field", "field": vField, "kind": "compare", "operator": vMatch.group(1), "value": int(vMatch.group(2))}
    if cNumberRegex.match(vValue):
      return {"op": "field", "field": vField, "kind": "equal", "value": int(vValue)}
    if vValue.endswith("xx") and cNumberRegex.match(vValue[:-2] or "x"):
      # status:4xx
      vBase = int(vValue[:-2]) * 100
      return {"op": "field", "field": vField, "kind": "range", "low": vBase, "high": vBase + 99}
    raise QueryError("query_invalid_number", vPosition, vValue)
  if "*" in vValue and not pToken.get("quoted"):
    return {"op": "field", "field": vField, "kind": "like", "value": vValue}
  return {"op": "field", "field": vField, "kind": "equal", "value": vValue}


def fParseQuery(pText: str) -> dict | None:
  vText = str(pText or "")
  if len(vText) > cMaxQueryLength:
    raise QueryError("query_too_long", cMaxQueryLength)
  vParser = Parser(fTokenize(vText), len(vText))
  return vParser.mParse()


def fFieldTerms(pNode: dict | None, pField: str) -> list[str]:
  # Values used for one field anywhere in the tree (for pivots and hints).
  if pNode is None:
    return []
  if pNode["op"] in ("and", "or"):
    lValues = []
    for dItem in pNode["items"]:
      lValues.extend(fFieldTerms(dItem, pField))
    return lValues
  if pNode["op"] == "not":
    return []
  if pNode["op"] == "field" and pNode["field"] == pField and "value" in pNode:
    return [str(pNode["value"])]
  return []


def fQuoteValue(pValue: str) -> str:
  # For building queries (pivots, alert descriptions): quoted when needed.
  vValue = str(pValue)
  if vValue and re.fullmatch(r"[^\s()\"]+", vValue):
    return vValue
  return "\"" + vValue.replace("\"", "\\\"") + "\""
