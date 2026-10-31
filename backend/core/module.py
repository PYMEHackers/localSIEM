"""Interface of a localSIEM module.

The core knows nothing about Apache: storage, search, rules engine, grouping,
the SOC queue, the heartbeat and health are generic. Each service of the
server (Apache today; SSH, mail, databases... later) is a module, loaded by
backend/core/registry.py from its module.json, that provides:

  1. discovery        where its sources are (mDiscover), with manual sources
                      from the settings.
  2. inputs           how they are read: the log files of this server, through
                      the core tailer (localSIEM only reads local logs).
  3. framing/parsing  from lines to units (mCreateFramer) and from units to
                      records (mParse).
  4. correlation      how records of several sources become one event
                      (mCreateCorrelator).
  5. action taken     what counts as "already resolved" (inside mBuildEvent:
                      event["action"] is "blocked" or "none").
  6. rules            YAML files in the module folder (mRulesPath), plus named
                      functions they can call (mRuleFunctions).
  7. enrichment       context for alerts (mEnrich).
  8. health/doctor    requirement checks (mDoctor) and periodic health
                      signals (mHealth).
  9. requirements     what the server must have before the module can be
                      turned on (mRequirements): the software it watches,
                      which installing the module never installs.
  10. web/root        extra fields of a record for the request card
                      (mDisplayRecord) and the server requirements that
                      manage.py can apply as root (mSetupSnippet,
                      mApplySetup).

Its settings live in settings.json under modules.<name>, over the defaults
of its module.json (mModuleSettings); modules.<name>.enabled turns it on and
off without restarting anything.

Records are dicts with: time, received, module, source, source_key,
correlation, parse_status (ok/partial/unparsed), fields, raw (masked).

Events are dicts with the columns of the events table plus record_ids,
rule_hits ([{rule, category}]) and detections (what must go to the SOC).
"""

from pathlib import Path

from backend.core.registry import fModuleSettings


class LineFramer:
  # One line is one unit; nothing is ever held back.

  def mFeed(self, pText: str, pDevice: int, pInode: int, pOffset: int) -> list[tuple]:
    return [(pText, (pDevice, pInode, pOffset))]

  def mSafeCommit(self):
    # None: every line fed so far can be committed.
    return None


class Module:

  vName = ""

  def __init__(self, pSettings: dict, pMasker, pStorage, pManifest: dict | None = None):
    self.dSettings = pSettings
    self.vMasker = pMasker
    self.vStorage = pStorage
    self.dManifest = pManifest or {"id": self.vName, "settings": []}

  def mModuleSettings(self) -> dict:
    return fModuleSettings(self.dManifest, self.dSettings)

  def mReload(self, pSettings: dict, pMasker) -> None:
    self.dSettings = pSettings
    self.vMasker = pMasker

  def mEnabled(self) -> bool:
    return bool(self.mModuleSettings().get("enabled"))

  def mStart(self) -> None:
    # Called once by the collector, with the storage ready.
    return None

  def mDiscoveryInterval(self) -> float:
    return float(self.mModuleSettings().get("discovery_interval_seconds", 3600))

  def mDiscover(self) -> list[dict]:
    # [{"key", "path", "kind", "format", "vhost"}]; key is stable per source.
    return []

  def mCreateFramer(self, pSource: dict):
    return LineFramer()

  def mParse(self, pSource: dict, pUnit: str, pReceived: str) -> dict:
    raise NotImplementedError

  def mCreateCorrelator(self):
    raise NotImplementedError

  def mBuildEvent(self, pTransaction: dict) -> dict:
    raise NotImplementedError

  def mRulesPath(self) -> Path | None:
    return None

  def mRuleFunctions(self) -> dict:
    return {}

  def mEnrich(self, pDetection: dict) -> dict:
    return {}

  def mDoctor(self) -> list[dict]:
    return []

  def mRequirements(self) -> list[dict]:
    # What the server must have before the module can be turned on (usually
    # the software it watches, which installing the module never installs),
    # as checks like the ones of mDoctor: {"id", "status": "ok" or "error",
    # "title", "detail", "fix" (optional: the command that installs it)}.
    # They are met when no check is an error; [] (the default): nothing is
    # required. It is called without storage (the web and manage.py too) and
    # may read the configuration of the service every time, so the core calls
    # it only at the first installation, when the collector starts or
    # reloads, when the module is turned on and with Reconfigure, and keeps
    # the result (fCheckRequirements).
    return []

  def mHealth(self, pNow: float) -> list[dict]:
    return []

  def mSkipped(self) -> list[dict]:
    # Logs found but not read, with the reason: [{path, kind, reason}].
    return []

  def mSetLowDisk(self, pLowDisk: bool) -> None:
    return None

  # Web and root (manage.py configure-apache, apply-setup, setup-modules)

  def mDisplayRecord(self, pRecord: dict) -> dict:
    return {}

  def mSetupSnippet(self) -> str:
    return ""

  def mApplySetup(self) -> None:
    return None
