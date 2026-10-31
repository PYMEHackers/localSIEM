"use strict";

// Overview: the first tab of both dashboards. The last 24 hours (events,
// blocks, alerts and an hourly histogram), the state of every module, the
// last alerts and the state of the collector, the SOC and the disk.

window.LocalsiemViews = window.LocalsiemViews || {};

(function fOverviewView() {
  const P = window.Localsiem;
  const fEl = P.fEl;
  const fT = P.fT;

  function fStat(pIcon, pKey, pValue, pSub, pClass) {
    return fEl("div", { class: "stat-card" + (pClass ? " " + pClass : "") }, [
      fEl("div", { class: "stat-title" }, fEl("h3", {}, [P.fIcon(pIcon), P.fText(pKey)])),
      fEl("div", { class: "stat-value" }, String(pValue)),
      pSub ? fEl("div", { class: "muted small cell-break" }, pSub) : null
    ]);
  }

  function fSum(dCounts) {
    return Object.values(dCounts || {}).reduce(function fAdd(pTotal, pValue) { return pTotal + (Number(pValue) || 0); }, 0);
  }

  window.LocalsiemViews.overview = function fRenderOverview(pContainer, pContext) {
    const vStats = fEl("div", { class: "stat-grid overview-stats" });
    const vHistogram = fEl("div", { class: "histogram", role: "img", "aria-label": fT("overview.activity") });
    const vModules = fEl("div", { class: "module-strip" });
    const vAlerts = fEl("tbody");
    const vSystem = fEl("div");
    const vModulesLink = fEl("a", { class: "button button-secondary button-small", href: pContext.fBase() + "modules/" }, [P.fIcon("plug"), P.fText("overview.see_modules")]);
    const vAlertsLink = fEl("a", { class: "button button-secondary button-small", href: pContext.fBase() + "alerts/" }, [P.fIcon("bell"), P.fText("overview.see_alerts")]);
    for (const vLink of [vModulesLink, vAlertsLink]) {
      vLink.addEventListener("click", function fOnClick(pEvent) {
        if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
          return;
        }
        pEvent.preventDefault();
        pContext.fNavigate(vLink.getAttribute("href"));
      });
    }

    function fDrawHistogram(dAnswer) {
      P.fClear(vHistogram);
      const vSize = 3600 * 1000;
      const vEnd = P.fParseNativeTime(dAnswer.to);
      const vFrom = P.fParseNativeTime(dAnswer.from);
      if (!vEnd || !vFrom) {
        return;
      }
      const dCounts = {};
      for (const dBucket of dAnswer.histogram || []) {
        dCounts[P.fParseNativeTime(dBucket.start).getTime()] = dBucket;
      }
      const aBuckets = [];
      for (let vTime = Math.floor(vFrom.getTime() / vSize) * vSize; vTime < vEnd.getTime(); vTime += vSize) {
        aBuckets.push({ time: vTime, count: dCounts[vTime] ? dCounts[vTime].count : 0, blocked: dCounts[vTime] ? dCounts[vTime].blocked : 0 });
      }
      const vMax = Math.max(1, ...aBuckets.map(function fCount(dBucket) { return dBucket.count; }));
      for (const dBucket of aBuckets) {
        const vLabel = P.fFormatNativeTime(new Date(dBucket.time)) + " · " + P.fFormatNumber(dBucket.count) + " · " + fT("overview.blocked_short", { count: P.fFormatNumber(dBucket.blocked) });
        // Heights through the CSSOM: the Content-Security-Policy forbids
        // style attributes.
        const vBlocked = fEl("span", { class: "histogram-blocked" });
        vBlocked.style.height = (dBucket.count ? dBucket.blocked * 100 / dBucket.count : 0) + "%";
        const vFill = fEl("span", { class: "histogram-fill" }, vBlocked);
        vFill.style.height = (dBucket.count ? Math.max(3, dBucket.count * 100 / vMax) : 0) + "%";
        const vBar = fEl("div", { class: "histogram-bar", title: vLabel }, vFill);
        vBar.addEventListener("click", function fOpenHour() {
          window.LocalsiemSearch.fOpenSearch("", P.fFormatNativeTime(new Date(dBucket.time)), P.fFormatNativeTime(new Date(dBucket.time + vSize - 1)));
        });
        vHistogram.appendChild(vBar);
      }
    }

    function fModuleLine(dModule) {
      if (["disabled", "unknown", "pending"].includes(dModule.state) || !dModule.version) {
        return null;
      }
      return fEl("span", { class: "muted small" }, fT("modules.reading", { reading: dModule.sources_reading, total: dModule.sources, lines: P.fFormatNumber(dModule.lines_hour) }));
    }

    function fDrawModules(ldModules) {
      P.fClear(vModules);
      for (const dModule of ldModules) {
        vModules.appendChild(fEl("div", { class: "module-strip-item" }, [
          fEl("strong", { class: "cell-break" }, window.LocalsiemModules.fModuleText(dModule, "name", dModule.id)),
          window.LocalsiemModules.fStatePill(dModule.state),
          fModuleLine(dModule)
        ]));
      }
      if (!ldModules.length) {
        vModules.appendChild(fEl("div", { class: "empty-state", i18n: "modules.none" }));
      }
    }

    function fDrawAlerts(ldAlerts) {
      P.fClear(vAlerts);
      for (const dAlert of ldAlerts) {
        vAlerts.appendChild(fEl("tr", {}, [
          fEl("td", {}, P.fSeverityBadge(dAlert.severity)),
          fEl("td", { class: "cell-rule" }, dAlert.rule),
          fEl("td", { class: "mono cell-break" }, dAlert.ip || "—"),
          fEl("td", { class: "mono" }, P.fFormatNumber(dAlert.count)),
          fEl("td", {}, P.fStatusBadge("alert_status", dAlert.status)),
          fEl("td", { class: "mono" }, dAlert.last_seen || "—")
        ]));
      }
      if (!vAlerts.children.length) {
        vAlerts.appendChild(P.fEmptyRow(6, "overview.no_alerts"));
      }
      P.fLabelStackTables(vAlerts.closest("table").parentElement);
    }

    function fDrawSystem(dAnswer) {
      P.fClear(vSystem);
      const dCollector = dAnswer.collector || {};
      const dSoc = dAnswer.soc || {};
      const dHeartbeat = dAnswer.heartbeat || {};
      const dDisk = dAnswer.disk || {};
      const dDatabase = dAnswer.database || {};
      vSystem.appendChild(P.fDetailsList([
        [fT("overview.collector"), dCollector.running
          ? fEl("span", { class: "module-state module-state-ok" }, fT("overview.collector_running", { version: dCollector.version || "" }))
          : fEl("span", { class: "module-state module-state-error" }, fT("overview.collector_stopped"))],
        [fT("overview.since"), dCollector.started || ""],
        [fT("overview.soc"), P.fStatusBadge("soc_state", dSoc.state || "not_configured")],
        [fT("overview.heartbeat"), dHeartbeat.time ? (dHeartbeat.ok ? fT("soc.heartbeat_ok", { time: dHeartbeat.time }) : fT("soc.heartbeat_failed", { time: dHeartbeat.time, error: (dHeartbeat.status ? "HTTP " + dHeartbeat.status + " " : "") + (dHeartbeat.error || "") })) : "—"],
        [fT("overview.queue"), P.fFormatNumber((dAnswer.queue || {}).pending || 0)],
        [fT("overview.disk"), dDisk.total ? P.fFormatBytes(dDisk.free) + " · " + fT("disk." + (dDisk.level || "normal")) : ""],
        [fT("overview.database"), dDatabase.maximum ? P.fFormatBytes(dDatabase.file) + " · " + fT("sources.maximum", { size: P.fFormatBytes(dDatabase.maximum) }) : ""]
      ]));
    }

    async function fLoad() {
      try {
        const dAnswer = await P.fApi("GET", "/api/overview");
        const ldModules = dAnswer.modules || [];
        const ldEnabled = ldModules.filter(function fOn(dModule) { return dModule.enabled; });
        const vWorking = ldEnabled.filter(function fOk(dModule) { return dModule.state === "ok"; }).length;
        let vModulesSub = fT("overview.modules_none");
        if (ldEnabled.length) {
          vModulesSub = vWorking === ldEnabled.length ? fT("overview.modules_all_ok") : fT("overview.modules_issues", { count: ldEnabled.length - vWorking });
        }
        const dAlerts = dAnswer.alerts_24h || {};
        P.fClear(vStats);
        vStats.appendChild(fStat("activity", "overview.events", P.fFormatNumber(dAnswer.events_24h), fT("overview.events_sub", { alerted: P.fFormatNumber(dAnswer.alerted_24h) })));
        vStats.appendChild(fStat("shield-check", "overview.blocked", P.fFormatNumber(dAnswer.blocked_24h), fT("overview.blocked_sub")));
        vStats.appendChild(fStat("send", "overview.alerts", P.fFormatNumber(fSum(dAlerts.status)), fT("overview.alerts_sub", { pending: P.fFormatNumber((dAnswer.queue || {}).pending || 0) })));
        vStats.appendChild(fStat("plug", "overview.modules", vWorking + " / " + ldEnabled.length, vModulesSub, ldEnabled.length && vWorking === ldEnabled.length ? "stat-ok" : (ldEnabled.length ? "stat-warning" : "")));
        fDrawHistogram(dAnswer);
        fDrawModules(ldModules);
        fDrawAlerts(dAnswer.recent_alerts || []);
        fDrawSystem(dAnswer);
        P.fApplyTranslations(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    pContainer.appendChild(vStats);
    pContainer.appendChild(fEl("section", { class: "card histogram-card" }, [
      fEl("div", { class: "card-header" }, [P.fText("overview.activity", "h2", { class: "card-title" }), P.fText("overview.per_hour", "span", { class: "muted small" })]),
      vHistogram,
      P.fText("overview.activity_help", "p", { class: "muted small" })
    ]));
    pContainer.appendChild(fEl("div", { class: "card-split overview-split" }, [
      fEl("section", { class: "card" }, [
        fEl("div", { class: "card-header" }, [P.fText("overview.modules_title", "h2", { class: "card-title" }), vModulesLink]),
        vModules
      ]),
      fEl("section", { class: "card" }, [P.fText("overview.system", "h2", { class: "section-title" }), vSystem])
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      fEl("div", { class: "card-header" }, [P.fText("overview.recent_alerts", "h2", { class: "card-title" }), vAlertsLink]),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fEl("thead", {}, fEl("tr", {}, ["alerts.col_severity", "alerts.col_rule", "alerts.col_ip", "alerts.col_count", "alerts.col_status", "alerts.col_last"].map(function fCell(pKey) { return fEl("th", { i18n: pKey }); }))),
        vAlerts
      ]))
    ]));
    fLoad();
    return P.fPoll(fLoad, 15000);
  };
})();
