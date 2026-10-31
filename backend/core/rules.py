"""Rules engine: YAML rules evaluated on every event.

A rule file holds one rule:

  id: apache-enumeration            stable id; stored as rule localsiem:<id>
  name: "Apache: ..."               the alert rule name sent to the SOC
  category: enumeration
  type: web-attack                  SOC alert type
  severity: medium
  kind: match | threshold | sequence
  when: {conditions}                match and threshold
  first: {conditions}               sequence: what must happen first...
  first_threshold: 10               ...at least this many times...
  then: {conditions}                ...before this, inside the window
  by: [ip, vhost]                   grouping key of the counters
  window: 300                       seconds
  threshold: 30                     threshold kind
  lists: {name: [values]}           referenced by in_list / regex_list
  description: "..."                {field} placeholders are replaced
  search: "ip:{ip} ..."             query for the localSIEM search

Conditions (all must hold) map a field to:

  value                             equal (case-insensitive for text)
  {in: [...]}  {in_list: name}      one of
  {regex: "..."}  {regex_list: name}
  {prefix: "..."}  {suffix: "..."}  {contains: "..."}
  {gte: n}  {lte: n}  {range: [a, b]}
  {exists: true}
  {function: name}                  a named function of the module
  {not: {...}}

Fields are looked up in the event columns first and then in event["fields"].
Every rule produces events with no action taken, so its detections go to the
SOC. Counters live in memory: after a restart they start again.
"""

import collections
import re
import time
from pathlib import Path

import yaml

lRequiredKeys = ["id", "name", "category", "type", "severity", "kind"]
sKinds = {"match", "threshold", "sequence"}
sSeverities = {"low", "medium", "high", "critical"}


class RuleError(ValueError):
  pass


def fDescribeFolder(pModule: str, pFolder) -> tuple[list[dict], list[str]]:
  # The rules of a module as their files define them, before the overrides
  # of the settings: the web lists them, the disabled ones included.
  ldRules = []
  lErrors = []
  if pFolder is None or not Path(pFolder).is_dir():
    return ldRules, lErrors
  for vFile in sorted(Path(pFolder).glob("*.yaml")):
    try:
      with vFile.open("r", encoding="utf-8") as vHandle:
        dDefinition = yaml.safe_load(vHandle) or {}
      if not isinstance(dDefinition, dict) or any(vKey not in dDefinition for vKey in lRequiredKeys):
        raise RuleError("missing keys")
      vKind = str(dDefinition["kind"])
      ldRules.append({
        "id": str(dDefinition["id"]), "module": str(dDefinition.get("module", pModule)), "name": str(dDefinition["name"]),
        "category": str(dDefinition["category"]).lower(), "severity": str(dDefinition["severity"]), "kind": vKind,
        "window": float(dDefinition.get("window", 300)),
        "threshold": int(dDefinition.get("threshold", 1)) if vKind == "threshold" else int(dDefinition.get("first_threshold", 1)),
        "file_enabled": dDefinition.get("enabled") is not False
      })
    except (OSError, yaml.YAMLError, RuleError, TypeError, ValueError) as vError:
      lErrors.append(f"{vFile.name}: {vError}")
  return ldRules, lErrors


def fGetField(pEvent: dict, pName: str):
  if pName in pEvent and pEvent[pName] is not None:
    return pEvent[pName]
  dFields = pEvent.get("fields") or {}
  vValue = dFields
  for vPart in pName.split("."):
    if isinstance(vValue, dict) and vPart in vValue:
      vValue = vValue[vPart]
    else:
      return None
  return vValue


class Rule:

  def __init__(self, pDefinition: dict, pFunctions: dict, pModule: str, pFile: str):
    for vKey in lRequiredKeys:
      if vKey not in pDefinition:
        raise RuleError(f"{pFile}: missing key {vKey}")
    if pDefinition["kind"] not in sKinds:
      raise RuleError(f"{pFile}: unknown kind {pDefinition['kind']}")
    if pDefinition["severity"] not in sSeverities:
      raise RuleError(f"{pFile}: unknown severity {pDefinition['severity']}")
    self.dDefinition = pDefinition
    self.vId = str(pDefinition["id"])
    self.vModule = str(pDefinition.get("module", pModule))
    self.vName = str(pDefinition["name"])
    self.vCategory = str(pDefinition["category"]).lower()
    self.vType = str(pDefinition["type"])
    self.vSeverity = str(pDefinition["severity"])
    self.vKind = pDefinition["kind"]
    self.lBy = list(pDefinition.get("by", ["ip"]))
    self.vWindow = float(pDefinition.get("window", 300))
    self.vThreshold = int(pDefinition.get("threshold", 1))
    self.vFirstThreshold = int(pDefinition.get("first_threshold", 1))
    self.dLists = {vName: list(lValues or []) for vName, lValues in (pDefinition.get("lists") or {}).items()}
    self.dFunctions = pFunctions
    self.vDescription = str(pDefinition.get("description", ""))
    self.vSearch = str(pDefinition.get("search", "ip:{ip}"))
    self.dRegexCache = {}
    self.dWhen = self.mCompile(pDefinition.get("when") or {}, pFile)
    self.dFirst = self.mCompile(pDefinition.get("first") or {}, pFile)
    self.dThen = self.mCompile(pDefinition.get("then") or {}, pFile)
    if self.vKind == "sequence" and (not self.dFirst or not self.dThen):
      raise RuleError(f"{pFile}: a sequence needs first and then")
    # key -> deque of event times (epoch)
    self.dCounters = collections.defaultdict(collections.deque)
    self.dLastFired = {}

  def mCompile(self, pConditions: dict, pFile: str) -> dict:
    # Validates the conditions and compiles their regular expressions.
    for vField, vCondition in pConditions.items():
      self.mCheckCondition(vCondition, pFile)
    return pConditions

  def mCheckCondition(self, pCondition, pFile: str) -> None:
    if isinstance(pCondition, dict):
      for vOperator, vArgument in pCondition.items():
        if vOperator == "regex":
          self.mRegex(vArgument)
        elif vOperator == "regex_list":
          if vArgument not in self.dLists:
            raise RuleError(f"{pFile}: unknown list {vArgument}")
          for vPattern in self.dLists[vArgument]:
            self.mRegex(vPattern)
        elif vOperator == "in_list":
          if vArgument not in self.dLists:
            raise RuleError(f"{pFile}: unknown list {vArgument}")
        elif vOperator == "function":
          if vArgument not in self.dFunctions:
            raise RuleError(f"{pFile}: unknown function {vArgument}")
        elif vOperator == "not":
          self.mCheckCondition(vArgument, pFile)
        elif vOperator not in ("in", "prefix", "suffix", "contains", "gte", "lte", "range", "exists"):
          raise RuleError(f"{pFile}: unknown operator {vOperator}")

  def mRegex(self, pPattern: str):
    vCompiled = self.dRegexCache.get(pPattern)
    if vCompiled is None:
      try:
        vCompiled = re.compile(pPattern, re.IGNORECASE)
      except re.error as vError:
        raise RuleError(f"invalid regular expression {pPattern}: {vError}") from vError
      self.dRegexCache[pPattern] = vCompiled
    return vCompiled

  def mTest(self, pEvent: dict, pField: str, pCondition) -> bool:
    vValue = fGetField(pEvent, pField)
    if not isinstance(pCondition, dict):
      if vValue is None:
        return False
      if isinstance(pCondition, bool):
        return bool(vValue) == pCondition
      if isinstance(pCondition, (int, float)) and not isinstance(vValue, str):
        return vValue == pCondition
      return str(vValue).lower() == str(pCondition).lower()
    for vOperator, vArgument in pCondition.items():
      if vOperator == "not":
        if self.mTest(pEvent, pField, vArgument):
          return False
        continue
      if vOperator == "exists":
        if (vValue is not None and vValue != "") != bool(vArgument):
          return False
        continue
      if vOperator == "function":
        if not self.dFunctions[vArgument](pEvent, vValue):
          return False
        continue
      if vValue is None:
        return False
      vText = str(vValue)
      if vOperator == "in":
        if vText.lower() not in {str(vItem).lower() for vItem in vArgument}:
          return False
      elif vOperator == "in_list":
        if vText.lower() not in {str(vItem).lower() for vItem in self.dLists[vArgument]}:
          return False
      elif vOperator == "regex":
        if not self.mRegex(vArgument).search(vText):
          return False
      elif vOperator == "regex_list":
        if not any(self.mRegex(vPattern).search(vText) for vPattern in self.dLists[vArgument]):
          return False
      elif vOperator == "prefix":
        if not vText.lower().startswith(str(vArgument).lower()):
          return False
      elif vOperator == "suffix":
        if not vText.lower().endswith(str(vArgument).lower()):
          return False
      elif vOperator == "contains":
        if str(vArgument).lower() not in vText.lower():
          return False
      elif vOperator in ("gte", "lte", "range"):
        try:
          vNumber = float(vValue)
        except (TypeError, ValueError):
          return False
        if vOperator == "gte" and vNumber < float(vArgument):
          return False
        if vOperator == "lte" and vNumber > float(vArgument):
          return False
        if vOperator == "range" and not float(vArgument[0]) <= vNumber <= float(vArgument[1]):
          return False
    return True

  def mMatches(self, pEvent: dict, pConditions: dict) -> bool:
    return all(self.mTest(pEvent, vField, vCondition) for vField, vCondition in pConditions.items())

  def mKey(self, pEvent: dict) -> tuple:
    return tuple(str(fGetField(pEvent, vField) or "") for vField in self.lBy)

  def mPrune(self, pCounter: collections.deque, pNow: float) -> None:
    while pCounter and pCounter[0] < pNow - self.vWindow:
      pCounter.popleft()

  def mEvaluate(self, pEvent: dict, pEventTime: float) -> dict | None:
    if self.vModule and pEvent.get("module") != self.vModule:
      return None
    if self.vKind == "match":
      if self.mMatches(pEvent, self.dWhen):
        return self.mSignal(pEvent, 1)
      return None
    if self.vKind == "threshold":
      if not self.mMatches(pEvent, self.dWhen):
        return None
      vKey = self.mKey(pEvent)
      vCounter = self.dCounters[vKey]
      vCounter.append(pEventTime)
      self.mPrune(vCounter, pEventTime)
      while len(vCounter) > max(self.vThreshold * 4, 64):
        vCounter.popleft()
      if len(vCounter) >= self.vThreshold:
        vLast = self.dLastFired.get(vKey)
        if vLast is None or pEventTime - vLast >= self.vWindow:
          self.dLastFired[vKey] = pEventTime
          return self.mSignal(pEvent, len(vCounter))
      return None
    # sequence
    vKey = self.mKey(pEvent)
    if self.mMatches(pEvent, self.dThen):
      vCounter = self.dCounters.get(vKey)
      if vCounter:
        self.mPrune(vCounter, pEventTime)
        if len(vCounter) >= self.vFirstThreshold:
          vCount = len(vCounter)
          vCounter.clear()
          return self.mSignal(pEvent, vCount)
      return None
    if self.mMatches(pEvent, self.dFirst):
      vCounter = self.dCounters[vKey]
      vCounter.append(pEventTime)
      self.mPrune(vCounter, pEventTime)
      while len(vCounter) > max(self.vFirstThreshold * 4, 64):
        vCounter.popleft()
    return None

  def mSignal(self, pEvent: dict, pCount: int) -> dict:
    dValues = {
      "ip": pEvent.get("ip") or "", "vhost": pEvent.get("vhost") or "", "path": pEvent.get("path") or "",
      "uri": pEvent.get("uri") or "", "method": pEvent.get("method") or "", "status": pEvent.get("status") or "",
      "uid": pEvent.get("uid") or "", "count": pCount, "window": int(self.vWindow), "threshold": self.vThreshold
    }
    return {
      "rule_id": "localsiem:" + self.vId,
      "module": self.vModule or pEvent.get("module"),
      "name": self.vName,
      "category": self.vCategory,
      "type": self.vType,
      "severity": self.vSeverity,
      "description": fFormatTemplate(self.vDescription, dValues),
      "search": fFormatTemplate(self.vSearch, dValues),
      "count": pCount
    }

  def mCleanup(self, pNow: float) -> None:
    for vKey in list(self.dCounters):
      vCounter = self.dCounters[vKey]
      self.mPrune(vCounter, pNow)
      if not vCounter:
        del self.dCounters[vKey]
    for vKey in list(self.dLastFired):
      if pNow - self.dLastFired[vKey] > self.vWindow * 2:
        del self.dLastFired[vKey]


def fFormatTemplate(pTemplate: str, pValues: dict) -> str:
  from backend.core.query import fQuoteValue

  def fReplace(pMatch):
    vName = pMatch.group(1)
    if vName not in pValues:
      return pMatch.group(0)
    vValue = pValues[vName]
    # Inside a search, values with spaces or quotes must stay one term.
    return fQuoteValue(vValue) if pMatch.group(2) == "q" else str(vValue)
  return re.sub(r"\{([a-z_]+)(?::(q))?\}", fReplace, pTemplate)


class RulesEngine:

  def __init__(self):
    self.lRules = []
    self.lErrors = []

  def mLoad(self, pPaths: list[tuple], pOverrides: dict | None = None) -> None:
    # pPaths: [(module name, folder, functions)]. pOverrides: {rule id:
    # {threshold, window, severity, enabled, lists}} from the settings.
    lRules = []
    lErrors = []
    dOverrides = pOverrides or {}
    for vModule, vFolder, dFunctions in pPaths:
      if vFolder is None or not Path(vFolder).is_dir():
        continue
      for vFile in sorted(Path(vFolder).glob("*.yaml")):
        try:
          with vFile.open("r", encoding="utf-8") as vHandle:
            dDefinition = yaml.safe_load(vHandle) or {}
          dOverride = dOverrides.get(str(dDefinition.get("id")), {})
          if dOverride.get("enabled") is False or dDefinition.get("enabled") is False:
            continue
          for vKey in ("threshold", "window", "severity", "first_threshold"):
            if vKey in dOverride:
              dDefinition[vKey] = dOverride[vKey]
          if isinstance(dOverride.get("lists"), dict):
            dDefinition.setdefault("lists", {}).update(dOverride["lists"])
          lRules.append(Rule(dDefinition, dFunctions, vModule, vFile.name))
        except (OSError, yaml.YAMLError, RuleError, TypeError, ValueError) as vError:
          lErrors.append(f"{vFile}: {vError}")
    self.lRules = lRules
    self.lErrors = lErrors

  def mEvaluate(self, pEvent: dict, pEventTime: float) -> list[dict]:
    lSignals = []
    for vRule in self.lRules:
      try:
        dSignal = vRule.mEvaluate(pEvent, pEventTime)
      except Exception as vError:
        # A broken rule never stops the collector.
        self.lErrors.append(f"{vRule.vId}: {vError}")
        self.lErrors = self.lErrors[-50:]
        continue
      if dSignal is not None:
        lSignals.append(dSignal)
    return lSignals

  def mCleanup(self) -> None:
    vNow = time.time()
    for vRule in self.lRules:
      vRule.mCleanup(vNow)

  def mDescribe(self) -> list[dict]:
    return [
      {
        "id": vRule.vId, "module": vRule.vModule, "name": vRule.vName, "category": vRule.vCategory,
        "severity": vRule.vSeverity, "kind": vRule.vKind, "window": vRule.vWindow,
        "threshold": vRule.vThreshold if vRule.vKind == "threshold" else vRule.vFirstThreshold
      }
      for vRule in self.lRules
    ]
