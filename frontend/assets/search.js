"use strict";

// Analyst views: search (with histogram, summaries, request card and
// pivots), live view, alerts and account.

window.LocalsiemViews = window.LocalsiemViews || {};

(function fSearchViews() {
  const P = window.Localsiem;
  const fEl = P.fEl;
  const fT = P.fT;
  const dRanges = { "15m": 15 * 60, "1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };
  const lRangeOrder = ["15m", "1h", "24h", "7d", "30d", "custom"];

  function fRangeBounds(pRange, pFrom, pTo) {
    if (pRange === "custom") {
      return { from: pFrom, to: pTo };
    }
    const vNow = new Date();
    return { from: P.fFormatNativeTime(new Date(vNow.getTime() - dRanges[pRange] * 1000)), to: P.fFormatNativeTime(vNow) };
  }

  function fQuote(pValue) {
    const vValue = String(pValue);
    return /^[^\s()"]+$/.test(vValue) ? vValue : "\"" + vValue.replace(/"/g, "\\\"") + "\"";
  }

  function fSearchUrl(pQuery, pFrom, pTo) {
    return P.fDashboardBase() + "search/" + P.fQuery({ q: pQuery, from: pFrom, to: pTo });
  }

  function fOpenSearch(pQuery, pFrom, pTo) {
    window.LocalsiemApp.fNavigate(fSearchUrl(pQuery, pFrom, pTo));
  }

  function fShift(pNative, pSeconds) {
    const vDate = P.fParseNativeTime(pNative);
    return vDate ? P.fFormatNativeTime(new Date(vDate.getTime() + pSeconds * 1000)) : pNative;
  }

  function fSourcesCell(aSources) {
    return fEl("span", { class: "badge-group" }, (aSources || []).map(function fBadge(pSource) {
      return fEl("span", { class: "badge source-badge source-" + pSource }, pSource);
    }));
  }

  function fActionCell(pAction) {
    if (pAction === "blocked") {
      return fEl("span", { class: "badge status status-resolved", "data-i18n": "action.blocked" }, fT("action.blocked"));
    }
    return fEl("span", { class: "muted", "data-i18n": "action.none" }, fT("action.none"));
  }

  function fRulesCell(aRules) {
    const aList = aRules || [];
    if (!aList.length) {
      return fEl("span", { class: "muted" }, "—");
    }
    const aShown = aList.slice(0, 4).map(function fRule(pRule) { return fEl("span", { class: "mono rule-chip" }, pRule); });
    if (aList.length > 4) {
      aShown.push(fEl("span", { class: "muted" }, "+" + (aList.length - 4)));
    }
    return fEl("span", { class: "rule-list" }, aShown);
  }

  function fAlertCell(aAlerts) {
    const aList = aAlerts || [];
    if (!aList.length) {
      return fEl("span", { class: "muted" }, "—");
    }
    return fEl("span", { class: "cell-stack" }, aList.slice(0, 3).map(function fAlert(dAlert) {
      if (dAlert.code) {
        return fEl("span", { class: "mono" }, dAlert.code);
      }
      return P.fStatusBadge("alert_status", dAlert.status);
    }));
  }

  function fResultRow(dRow, pColumns) {
    return fEl("tr", { class: "clickable", tabindex: "0", "data-id": dRow.id }, [
      fEl("td", { class: "mono" }, P.fFormatDateTime(dRow.time)),
      fEl("td", {}, fSourcesCell(dRow.sources)),
      fEl("td", { class: "mono cell-break" }, dRow.ip || "—"),
      fEl("td", {}, dRow.method || "—"),
      fEl("td", { class: "cell-uri" }, [fEl("span", { class: "cell-break" }, dRow.uri || "—"), dRow.vhost ? fEl("div", { class: "muted small cell-break" }, dRow.vhost) : null]),
      fEl("td", {}, dRow.status === null || dRow.status === undefined ? "—" : String(dRow.status)),
      fEl("td", {}, fActionCell(dRow.action)),
      fEl("td", {}, fRulesCell(dRow.rules)),
      fEl("td", {}, fAlertCell(dRow.alerts))
    ]);
  }

  function fResultsHead() {
    return fEl("thead", {}, fEl("tr", {}, [
      "search.col_time", "search.col_source", "search.col_ip", "search.col_method", "search.col_uri",
      "search.col_status", "search.col_action", "search.col_rules", "search.col_alert"
    ].map(function fHead(pKey) { return fEl("th", { i18n: pKey }); })));
  }

  // ---------- request card ----------

  function fPre(pText) {
    return fEl("pre", { class: "raw-block" }, fEl("code", {}, String(pText || "")));
  }

  function fMessagesTable(aMessages) {
    const vBody = fEl("tbody");
    for (const dMessage of aMessages || []) {
      vBody.appendChild(fEl("tr", {}, [
        fEl("td", { class: "mono" }, dMessage.id || "—"),
        fEl("td", { class: "cell-message" }, dMessage.msg || dMessage.head || ""),
        fEl("td", { class: "cell-data" }, dMessage.data || ""),
        fEl("td", { class: "cell-severity" }, dMessage.severity || ""),
        fEl("td", {}, dMessage.kind === "denied" ? fT("card.denied") + (dMessage.phase ? " (" + dMessage.phase + ")" : "") : (dMessage.kind || ""))
      ]));
    }
    return fEl("div", { class: "table-wrap" }, fEl("table", { class: "table compact messages-table" }, [
      fEl("thead", {}, fEl("tr", {}, ["card.rule", "card.message", "card.data", "card.severity", "card.kind"].map(function fHead(pKey) { return fEl("th", { i18n: pKey }); }))),
      vBody
    ]));
  }

  function fHeadersList(dHeaders) {
    return P.fDetailsList(Object.entries(dHeaders || {}));
  }

  function fRecordBlock(dRecord) {
    const dFields = dRecord.fields || {};
    const aChildren = [
      fEl("div", { class: "record-head" }, [
        fEl("span", { class: "badge source-badge source-" + dRecord.source }, dRecord.source),
        fEl("span", { class: "mono small" }, P.fFormatDateTime(dRecord.time)),
        dRecord.parse_status !== "ok" ? fEl("span", { class: "badge status status-awaiting" }, fT("parse." + dRecord.parse_status)) : null,
        fEl("span", { class: "muted small cell-break" }, (dRecord.source_key || "").replace(/^[a-z]+:[a-z]+:/, ""))
      ])
    ];
    if (dRecord.source === "audit") {
      const aMeta = [
        [fT("card.engine_mode"), dFields.engine_mode], [fT("card.producer"), dFields.producer],
        [fT("card.action"), dFields.action ? (dFields.action.intercepted ? fT("card.intercepted") + " (" + fT("card.phase") + " " + dFields.action.phase + ")" : fT("action.none")) : ""],
        [fT("card.handler"), dFields.handler]
      ];
      aChildren.push(P.fDetailsList(aMeta));
      if ((dFields.messages || []).length) {
        aChildren.push(P.fText("card.rules_matched", "h4"));
        aChildren.push(fMessagesTable(dFields.messages));
      }
      if (dFields.request_headers && Object.keys(dFields.request_headers).length) {
        aChildren.push(P.fText("card.request_headers", "h4"));
        aChildren.push(fHeadersList(dFields.request_headers));
      }
      if (dFields.request_body) {
        aChildren.push(P.fText("card.request_body", "h4"));
        aChildren.push(fPre(dFields.request_body));
      }
      if (dFields.response_headers && Object.keys(dFields.response_headers).length) {
        aChildren.push(P.fText("card.response_headers", "h4"));
        aChildren.push(fHeadersList(dFields.response_headers));
      }
      if (dFields.detail_dropped) {
        aChildren.push(P.fText("card.detail_dropped", "p", { class: "muted small" }));
      }
    } else if (dRecord.source === "error") {
      aChildren.push(P.fDetailsList([
        [fT("card.error_type"), dFields.error_type], [fT("card.level"), (dFields.error_module ? dFields.error_module + ":" : "") + (dFields.level || "")],
        [fT("card.ah_code"), dFields.ah_code], [fT("card.client"), dFields.client_ip]
      ]));
      if (dFields.modsecurity) {
        aChildren.push(fMessagesTable([dFields.modsecurity]));
      }
    }
    aChildren.push(fEl("details", { class: "disclosure" }, [
      fEl("summary", {}, P.fText("card.original_line")),
      fPre(dRecord.raw)
    ]));
    return fEl("div", { class: "record-block" }, aChildren);
  }

  function fPivotButtons(dEvent, pRange) {
    const aButtons = [];
    function fAdd(pKey, pQuery, pFrom, pTo) {
      aButtons.push(fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fPivot() {
        fOpenSearch(pQuery, pFrom || pRange.from, pTo || pRange.to);
      } }, fT(pKey)));
    }
    if (dEvent.ip) {
      fAdd("pivot.ip", "ip:" + fQuote(dEvent.ip));
    }
    fAdd("pivot.around", dEvent.vhost ? "vhost:" + fQuote(dEvent.vhost) : "", fShift(dEvent.time, -300), fShift(dEvent.time, 300));
    for (const vRule of (dEvent.rules || []).filter(function fReal(pRule) { return !/^9(49|59|80)/.test(pRule); }).slice(0, 3)) {
      aButtons.push(fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fPivotRule() {
        fOpenSearch("rule:" + fQuote(vRule), pRange.from, pRange.to);
      } }, fT("pivot.rule", { rule: vRule })));
    }
    if (dEvent.category) {
      fAdd("pivot.category", "category:" + fQuote(dEvent.category));
    }
    if (dEvent.uid) {
      fAdd("pivot.uid", "uid:" + fQuote(dEvent.uid), fShift(dEvent.time, -86400), fShift(dEvent.time, 86400));
    }
    return fEl("div", { class: "button-row pivot-row" }, aButtons);
  }

  function fRequestCard(dEvent, pRange) {
    const dFields = dEvent.fields || {};
    const aMeta = [
      [fT("card.time"), P.fFormatDateTime(dEvent.time)],
      [fT("card.received"), P.fFormatDateTime(dEvent.received)],
      [fT("card.vhost"), dEvent.vhost], [fT("card.ip"), dEvent.ip], [fT("card.method"), dEvent.method],
      [fT("card.uri"), dEvent.uri], [fT("card.status"), dEvent.status], [fT("card.bytes"), dEvent.bytes],
      [fT("card.duration"), dEvent.duration !== null && dEvent.duration !== undefined ? (Number(dEvent.duration) / 1000).toFixed(1) + " ms" : ""],
      [fT("card.ua"), dEvent.ua], [fT("card.referer"), dEvent.referer], [fT("card.uid"), dEvent.uid],
      [fT("card.correlation"), dEvent.correlation ? fT("correlation." + dEvent.correlation) : ""],
      [fT("card.action"), fT("action." + dEvent.action)],
      [fT("card.engine"), dEvent.engine], [fT("card.phase"), dEvent.phase],
      [fT("card.score"), dEvent.score !== null && dEvent.score !== undefined ? dEvent.score + (dEvent.threshold ? " / " + dEvent.threshold : "") : ""],
      [fT("card.category"), dEvent.category], [fT("card.severity"), dEvent.severity ? P.fSeverityBadge(dEvent.severity) : ""],
      [fT("card.alerts"), (dEvent.alerts || []).map(function fCode(dAlert) { return (dAlert.code || fT("alert_status." + dAlert.status)) + " · " + dAlert.rule; }).join("\n")]
    ];
    const aNotes = [];
    if (dFields.doubtful_block) {
      aNotes.push(P.fText("card.doubtful_block", "p", { class: "callout-note" }));
    }
    if (dFields.weak_correlation) {
      aNotes.push(P.fText("card.weak_correlation", "p", { class: "callout-note" }));
    }
    if (dFields.db_error) {
      aNotes.push(P.fText("card.db_error", "p", { class: "callout-note" }));
    }
    return fEl("div", { class: "request-card" }, [
      fPivotButtons(dEvent, pRange),
      fEl("div", { class: "request-grid" }, [
        fEl("div", { class: "stack" }, [P.fText("card.request", "h3"), P.fDetailsList(aMeta)].concat(aNotes)),
        fEl("div", { class: "stack" }, [P.fText("card.sources", "h3")].concat((dEvent.records || []).map(fRecordBlock)))
      ])
    ]);
  }

  function fToggleRow(pRow, pColumns, pRange) {
    const vNext = pRow.nextElementSibling;
    if (pRow.classList.contains("expanded")) {
      pRow.classList.remove("expanded");
      if (vNext && vNext.classList.contains("expanded-row")) {
        vNext.remove();
      }
      return;
    }
    pRow.classList.add("expanded");
    const vCell = fEl("td", { colspan: pColumns }, fEl("div", { class: "empty-state", i18n: "common.loading" }));
    const vDetail = fEl("tr", { class: "expanded-row" }, vCell);
    pRow.after(vDetail);
    P.fApi("GET", "/api/events/" + pRow.getAttribute("data-id")).then(function fShow(dEvent) {
      P.fClear(vCell).appendChild(fRequestCard(dEvent, pRange));
    }).catch(function fFail(vError) {
      P.fClear(vCell).appendChild(fEl("div", { class: "empty-state" }, P.fErrorText(vError)));
    });
  }

  function fBindRows(pBody, pColumns, fRange) {
    pBody.addEventListener("click", function fOnClick(pEvent) {
      if (pEvent.target.closest("button, a, .expanded-row")) {
        return;
      }
      const vRow = pEvent.target.closest("tr.clickable");
      if (vRow) {
        fToggleRow(vRow, pColumns, fRange());
      }
    });
    pBody.addEventListener("keydown", function fOnKey(pEvent) {
      if (pEvent.key === "Enter" && pEvent.target.matches("tr.clickable")) {
        fToggleRow(pEvent.target, pColumns, fRange());
      }
    });
  }

  // ---------- search ----------

  function fSyntaxHelp() {
    const aExamples = [
      ["ip:203.0.113.7", "help.ip"], ["rule:942100", "help.rule"], ["status:200 action:none category:sqli", "help.combined"],
      ["uri:*wp-login*", "help.wildcard"], ["\"union select\"", "help.phrase"], ["status:>=500", "help.compare"],
      ["status:400..499", "help.range"], ["uid:ZTx1kH8AAQEAAB2gTkAAAAAB", "help.uid"], ["alert:c00007a0001F", "help.alert"],
      ["ip:203.0.113.7 -status:404", "help.not"], ["(category:sqli OR category:xss) sent:no", "help.or"]
    ];
    return fEl("div", { class: "search-help", hidden: true }, [
      P.fText("help.intro", "p"),
      fEl("dl", { class: "details-list" }, aExamples.map(function fExample([vQuery, vKey]) {
        return fEl("div", { class: "details-row" }, [fEl("dt", { class: "mono" }, vQuery), fEl("dd", { i18n: vKey })]);
      })),
      P.fText("help.fields", "p", { class: "small muted" })
    ]);
  }

  window.LocalsiemViews.search = function fSearchView(pContainer) {
    const dParams = new URLSearchParams(window.location.search);
    const dState = { range: "24h", from: "", to: "", cursor: null, running: 0, bounds: null };
    if (dParams.get("from") || dParams.get("to")) {
      dState.range = "custom";
      dState.from = dParams.get("from") || "";
      dState.to = dParams.get("to") || P.fFormatNativeTime(new Date());
    } else if (dRanges[dParams.get("range")]) {
      dState.range = dParams.get("range");
    }
    const vQuery = fEl("input", { class: "input query-input", type: "search", id: "search-query", value: dParams.get("q") || "", autocomplete: "off", spellcheck: "false", maxlength: 2000, "data-i18n-placeholder": "search.placeholder", "aria-label": fT("search.query") });
    const vRange = fEl("select", { class: "select range-select", "aria-label": fT("search.range") }, lRangeOrder.map(function fOption(pRange) {
      return fEl("option", { value: pRange, i18n: "range." + pRange });
    }));
    vRange.value = dState.range;
    const vFrom = fEl("input", { class: "input mono", value: dState.from, placeholder: "2026/10/29@13:59:59.723", "aria-label": fT("search.from"), maxlength: 40 });
    const vTo = fEl("input", { class: "input mono", value: dState.to, placeholder: "2026/10/29@14:59:59.723", "aria-label": fT("search.to"), maxlength: 40 });
    const vCustom = fEl("div", { class: "custom-range", hidden: dState.range !== "custom" }, [
      fEl("label", { class: "field" }, [P.fText("search.from", "span", { class: "field-label" }), vFrom]),
      fEl("label", { class: "field" }, [P.fText("search.to", "span", { class: "field-label" }), vTo])
    ]);
    const vError = fEl("div", { class: "query-error", role: "alert", hidden: true });
    const vHelp = fSyntaxHelp();
    const vInfo = fEl("span", { class: "muted small search-info" });
    const vForm = fEl("form", { class: "search-form", novalidate: true }, [
      fEl("div", { class: "search-row" }, [
        fEl("div", { class: "search-box query-box" }, [P.fIcon("search"), vQuery]),
        vRange,
        fEl("button", { type: "submit", class: "button button-primary" }, [P.fIcon("search"), P.fText("search.submit")])
      ]),
      vCustom,
      vError,
      fEl("div", { class: "search-tools" }, [
        fEl("button", { type: "button", class: "button button-link", onclick: function fHelp() { vHelp.hidden = !vHelp.hidden; } }, [P.fIcon("info"), P.fText("search.syntax")]),
        fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fLink() {
          const dBounds = dState.bounds || fRangeBounds(vRange.value, vFrom.value, vTo.value);
          P.fCopy(window.location.origin + fSearchUrl(vQuery.value.trim(), dBounds.from, dBounds.to));
        } }, [P.fIcon("link"), P.fText("search.copy_link")]),
        fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fCsv() { fExport("csv"); } }, [P.fIcon("download"), "CSV"]),
        fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fJson() { fExport("json"); } }, [P.fIcon("download"), "JSON"]),
        vInfo
      ]),
      vHelp
    ]);
    const vHistogram = fEl("div", { class: "histogram", role: "img", "aria-label": fT("search.histogram") });
    const vHistogramLabel = fEl("span", { class: "muted small" });
    const vSummaries = fEl("div", { class: "summary-grid" });
    const vBody = fEl("tbody");
    const vMore = fEl("button", { type: "button", class: "button button-secondary", hidden: true, onclick: function fMore() { fRun(true); } }, P.fText("search.more"));
    pContainer.appendChild(fEl("section", { class: "card search-card" }, vForm));
    pContainer.appendChild(fEl("section", { class: "card histogram-card" }, [
      fEl("div", { class: "card-header" }, [P.fText("search.histogram", "h2", { class: "card-title" }), vHistogramLabel]),
      vHistogram,
      P.fText("search.histogram_help", "p", { class: "muted small" })
    ]));
    pContainer.appendChild(vSummaries);
    pContainer.appendChild(fEl("section", { class: "card results-card" }, [
      fEl("div", { class: "card-header" }, [P.fText("search.results", "h2", { class: "card-title" })]),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack results-table" }, [fResultsHead(), vBody])),
      fEl("div", { class: "pager" }, vMore)
    ]));
    fBindRows(vBody, 9, function fCurrentRange() { return dState.bounds || fRangeBounds(vRange.value, vFrom.value, vTo.value); });

    vRange.addEventListener("change", function fOnRange() {
      vCustom.hidden = vRange.value !== "custom";
      if (vRange.value === "custom" && !vFrom.value) {
        const dBounds = dState.bounds || fRangeBounds("24h");
        vFrom.value = dBounds.from;
        vTo.value = dBounds.to;
      }
      if (vRange.value !== "custom") {
        fRun(false);
      }
    });
    vForm.addEventListener("submit", function fOnSubmit(pEvent) {
      pEvent.preventDefault();
      fRun(false);
    });

    function fExport(pFormat) {
      const dBounds = dState.bounds || fRangeBounds(vRange.value, vFrom.value, vTo.value);
      P.fDownload("/api/search/export" + P.fQuery({ q: vQuery.value.trim(), from: dBounds.from, to: dBounds.to, format: pFormat }));
    }

    function fShowSyntaxError(pError) {
      const dData = pError.dData || {};
      vError.hidden = false;
      P.fClear(vError);
      vError.appendChild(fEl("p", {}, fTOrCode("query." + dData.code, dData.code) + (dData.detail ? " (" + dData.detail + ")" : "")));
      const vText = vQuery.value;
      const vPosition = Math.max(0, Math.min(Number(dData.position) || 0, vText.length));
      vError.appendChild(fEl("pre", { class: "query-caret" }, fEl("code", {}, vText + "\n" + " ".repeat(vPosition) + "^")));
      vError.appendChild(fEl("p", { class: "small muted" }, fT("query.position", { position: vPosition + 1 })));
    }

    function fTOrCode(pKey, pCode) {
      return P.fTOr(pKey, fT("query.query_unexpected") + (pCode ? " (" + pCode + ")" : ""));
    }

    function fAddFilter(pField, pValue) {
      const vTerm = pField + ":" + fQuote(pValue);
      vQuery.value = (vQuery.value.trim() ? vQuery.value.trim() + " " : "") + vTerm;
      fRun(false);
    }

    function fSummaryCard(pKey, pField, aItems) {
      const vBodyRows = fEl("tbody");
      for (const dItem of aItems || []) {
        vBodyRows.appendChild(fEl("tr", {}, [
          fEl("td", { class: "cell-break summary-value" }, pField ? fEl("button", { type: "button", class: "button-link", onclick: function fFilter() { fAddFilter(pField, dItem.value); } }, String(dItem.value)) : String(dItem.value)),
          fEl("td", { class: "mono" }, P.fFormatNumber(dItem.count))
        ]));
      }
      if (!(aItems || []).length) {
        vBodyRows.appendChild(P.fEmptyRow(2, "search.no_data"));
      }
      return fEl("section", { class: "card summary-card" }, [
        P.fText(pKey, "h3", { class: "card-title" }),
        fEl("div", { class: "table-wrap" }, fEl("table", { class: "table compact" }, vBodyRows))
      ]);
    }

    function fRenderSummaries(dSummaries) {
      P.fClear(vSummaries);
      vSummaries.appendChild(fSummaryCard("summary.ips", "ip", dSummaries.ips));
      vSummaries.appendChild(fSummaryCard("summary.paths", "path", dSummaries.paths));
      vSummaries.appendChild(fSummaryCard("summary.statuses", "status", dSummaries.statuses));
      vSummaries.appendChild(fSummaryCard("summary.rules", "rule", dSummaries.rules));
    }

    function fRenderHistogram(dHistogram) {
      P.fClear(vHistogram);
      const vSize = dHistogram.bucket_seconds * 1000;
      const vStart = Math.floor(P.fParseNativeTime(dHistogram.from).getTime() / vSize) * vSize;
      const vEnd = P.fParseNativeTime(dHistogram.to).getTime();
      const dCounts = {};
      for (const dBucket of dHistogram.buckets) {
        dCounts[P.fParseNativeTime(dBucket.start).getTime()] = dBucket;
      }
      const aBuckets = [];
      for (let vTime = vStart; vTime < vEnd && aBuckets.length < 2000; vTime += vSize) {
        aBuckets.push({ time: vTime, count: dCounts[vTime] ? dCounts[vTime].count : 0, blocked: dCounts[vTime] ? dCounts[vTime].blocked : 0 });
      }
      const vMax = Math.max(1, ...aBuckets.map(function fCount(dBucket) { return dBucket.count; }));
      vHistogramLabel.textContent = fT("search.bucket", { size: fT("bucket." + dHistogram.bucket_seconds) });
      const aBars = aBuckets.map(function fBar(dBucket, pIndex) {
        const vLabel = P.fFormatNativeTime(new Date(dBucket.time)) + " · " + P.fFormatNumber(dBucket.count);
        // Heights through the CSSOM: the Content-Security-Policy forbids
        // style attributes.
        const vBlocked = fEl("span", { class: "histogram-blocked" });
        vBlocked.style.height = (dBucket.count ? dBucket.blocked * 100 / dBucket.count : 0) + "%";
        const vFill = fEl("span", { class: "histogram-fill" }, vBlocked);
        vFill.style.height = (dBucket.count ? Math.max(3, dBucket.count * 100 / vMax) : 0) + "%";
        return fEl("div", { class: "histogram-bar", "data-index": pIndex, title: vLabel }, vFill);
      });
      for (const vBar of aBars) {
        vHistogram.appendChild(vBar);
      }
      // Dragging over the bars (or a click on one) narrows the range.
      let vFirst = null;
      function fMark(pTo) {
        for (const vBar of aBars) {
          const vIndex = Number(vBar.getAttribute("data-index"));
          vBar.classList.toggle("selected", vFirst !== null && vIndex >= Math.min(vFirst, pTo) && vIndex <= Math.max(vFirst, pTo));
        }
      }
      function fIndexAt(pEvent) {
        const vRect = vHistogram.getBoundingClientRect();
        const vRatio = (pEvent.clientX - vRect.left) / Math.max(1, vRect.width);
        return Math.max(0, Math.min(aBuckets.length - 1, Math.floor(vRatio * aBuckets.length)));
      }
      vHistogram.onpointerdown = function fDown(pEvent) {
        if (!aBuckets.length) {
          return;
        }
        vFirst = fIndexAt(pEvent);
        vHistogram.setPointerCapture(pEvent.pointerId);
        fMark(vFirst);
      };
      vHistogram.onpointermove = function fMove(pEvent) {
        if (vFirst !== null) {
          fMark(fIndexAt(pEvent));
        }
      };
      vHistogram.onpointerup = function fUp(pEvent) {
        if (vFirst === null) {
          return;
        }
        const vLast = fIndexAt(pEvent);
        const vLow = Math.min(vFirst, vLast);
        const vHigh = Math.max(vFirst, vLast);
        vFirst = null;
        vRange.value = "custom";
        vCustom.hidden = false;
        vFrom.value = P.fFormatNativeTime(new Date(aBuckets[vLow].time));
        vTo.value = P.fFormatNativeTime(new Date(aBuckets[vHigh].time + vSize));
        fRun(false);
      };
    }

    async function fRun(pMore) {
      const vQueryText = vQuery.value.trim();
      if (!pMore) {
        dState.bounds = fRangeBounds(vRange.value, vFrom.value.trim(), vTo.value.trim());
        dState.cursor = null;
        const dUrl = vRange.value === "custom" ? { q: vQueryText, from: dState.bounds.from, to: dState.bounds.to } : { q: vQueryText, range: vRange.value === "24h" ? "" : vRange.value };
        window.history.replaceState(null, "", P.fDashboardBase() + "search/" + P.fQuery(dUrl));
      }
      const dBounds = dState.bounds;
      const vRun = ++dState.running;
      vError.hidden = true;
      vMore.disabled = true;
      if (!pMore) {
        P.fClear(vBody).appendChild(fEl("tr", { class: "empty-row" }, fEl("td", { colspan: 9 }, fEl("div", { class: "empty-state", i18n: "common.loading" }))));
      }
      const dParameters = { q: vQueryText, from: dBounds.from, to: dBounds.to };
      try {
        const aRequests = [P.fApi("GET", "/api/search" + P.fQuery(Object.assign({ cursor: pMore ? dState.cursor : "" }, dParameters)))];
        if (!pMore) {
          aRequests.push(P.fApi("GET", "/api/search/histogram" + P.fQuery(dParameters)));
          aRequests.push(P.fApi("GET", "/api/search/summaries" + P.fQuery(dParameters)));
        }
        const [dResults, dHistogram, dSummaries] = await Promise.all(aRequests);
        if (vRun !== dState.running) {
          return;
        }
        if (!pMore) {
          P.fClear(vBody);
          fRenderHistogram(dHistogram);
          fRenderSummaries(dSummaries);
          vInfo.textContent = fT("search.took", { ms: dResults.took_ms });
        }
        for (const dRow of dResults.results) {
          vBody.appendChild(fResultRow(dRow));
        }
        if (!vBody.children.length) {
          vBody.appendChild(P.fEmptyRow(9, "search.no_results"));
        }
        dState.cursor = dResults.next;
        vMore.hidden = !dResults.next;
        P.fLabelStackTables(vBody.closest("table").parentElement);
      } catch (vFailure) {
        if (vRun !== dState.running) {
          return;
        }
        if (vFailure.vCode === "query_syntax") {
          fShowSyntaxError(vFailure);
          P.fClear(vBody);
        } else {
          vError.hidden = false;
          P.fClear(vError).appendChild(fEl("p", {}, P.fErrorText(vFailure)));
          if (!pMore) {
            P.fClear(vBody);
          }
        }
      } finally {
        vMore.disabled = false;
      }
    }

    fRun(false);
    vQuery.focus();
    return null;
  };

  // ---------- live ----------

  window.LocalsiemViews.live = function fLiveView(pContainer) {
    const vFilter = fEl("input", { class: "input", type: "search", autocomplete: "off", spellcheck: "false", maxlength: 2000, "data-i18n-placeholder": "live.filter_placeholder", "aria-label": fT("live.filter") });
    const vStatus = fEl("span", { class: "badge status status-awaiting" }, fT("live.connecting"));
    const vError = fEl("div", { class: "query-error", role: "alert", hidden: true });
    const vPause = fEl("button", { type: "button", class: "button button-secondary" });
    const vBody = fEl("tbody");
    let vSocket = null;
    let vPaused = false;
    let vClosed = false;
    let vRetry = null;

    function fPauseLabel() {
      P.fClear(vPause);
      vPause.appendChild(P.fIcon(vPaused ? "play" : "pause"));
      vPause.appendChild(P.fText(vPaused ? "live.resume" : "live.pause"));
    }
    fPauseLabel();

    function fSetStatus(pKey, pClass) {
      vStatus.className = "badge status " + pClass;
      vStatus.setAttribute("data-i18n", pKey);
      vStatus.textContent = fT(pKey);
    }

    function fSend(dMessage) {
      if (vSocket && vSocket.readyState === WebSocket.OPEN) {
        vSocket.send(JSON.stringify(dMessage));
      }
    }

    function fConnect() {
      if (vClosed) {
        return;
      }
      fSetStatus("live.connecting", "status-awaiting");
      vSocket = new WebSocket((window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/api/ws");
      vSocket.onmessage = function fOnMessage(pEvent) {
        let dMessage;
        try {
          dMessage = JSON.parse(pEvent.data);
        } catch (vError) {
          return;
        }
        if (dMessage.status === "ready") {
          fSetStatus(vPaused ? "live.paused" : "live.connected", vPaused ? "status-awaiting" : "status-resolved");
          fSend({ query: vFilter.value.trim(), paused: vPaused });
          return;
        }
        if (dMessage.type === "query") {
          vError.hidden = dMessage.ok;
          vError.textContent = dMessage.ok ? "" : P.fTOr("query." + dMessage.code, dMessage.code) + " — " + fT("query.position", { position: (dMessage.position || 0) + 1 });
          if (dMessage.ok) {
            P.fClear(vBody);
          }
          return;
        }
        if (dMessage.type === "events" && !vPaused) {
          const vEmpty = vBody.querySelector(".empty-row");
          if (vEmpty) {
            vEmpty.remove();
          }
          for (const dRow of dMessage.events) {
            vBody.insertBefore(fResultRow(dRow), vBody.firstChild);
          }
          while (vBody.querySelectorAll("tr.clickable").length > 300) {
            const vLast = vBody.querySelector("tr.clickable:last-of-type");
            if (vLast.nextElementSibling && vLast.nextElementSibling.classList.contains("expanded-row")) {
              vLast.nextElementSibling.remove();
            }
            vLast.remove();
          }
          P.fLabelStackTables(vBody.closest("table").parentElement);
        }
      };
      vSocket.onclose = function fOnClose(pEvent) {
        if (vClosed) {
          return;
        }
        if (pEvent.code === 4401) {
          window.location.assign("/auth/login/?next=" + encodeURIComponent(window.location.pathname));
          return;
        }
        fSetStatus("live.disconnected", "class-tp");
        vRetry = window.setTimeout(fConnect, 3000);
      };
    }

    vPause.addEventListener("click", function fOnPause() {
      vPaused = !vPaused;
      fPauseLabel();
      fSend({ paused: vPaused });
      fSetStatus(vPaused ? "live.paused" : "live.connected", vPaused ? "status-awaiting" : "status-resolved");
    });
    const vForm = fEl("form", { class: "filters live-filters", novalidate: true }, [
      fEl("div", { class: "search-box query-box" }, [P.fIcon("search"), vFilter]),
      fEl("button", { type: "submit", class: "button button-primary", i18n: "live.apply" }),
      vPause,
      fEl("div", { class: "filters-right" }, vStatus)
    ]);
    vForm.addEventListener("submit", function fOnSubmit(pEvent) {
      pEvent.preventDefault();
      fSend({ query: vFilter.value.trim() });
    });
    vBody.appendChild(P.fEmptyRow(9, "live.waiting"));
    pContainer.appendChild(fEl("section", { class: "card" }, [vForm, vError, P.fText("live.help", "p", { class: "muted small live-help" })]));
    pContainer.appendChild(fEl("section", { class: "card" }, fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack results-table" }, [fResultsHead(), vBody]))));
    fBindRows(vBody, 9, function fRange() { return fRangeBounds("1h"); });
    fConnect();
    return function fCleanup() {
      vClosed = true;
      window.clearTimeout(vRetry);
      if (vSocket) {
        vSocket.close();
      }
    };
  };

  // ---------- alerts ----------

  window.LocalsiemViews.alerts = function fAlertsView(pContainer) {
    const vStatus = fEl("select", { class: "select", "aria-label": fT("alerts.status") }, ["", "buffer", "queued", "sent", "rejected"].map(function fOption(pValue) {
      return fEl("option", { value: pValue, i18n: pValue ? "alert_status." + pValue : "alerts.all_statuses" });
    }));
    const vBody = fEl("tbody");
    const vMore = fEl("button", { type: "button", class: "button button-secondary", hidden: true }, P.fText("search.more"));
    let vNext = null;
    const dById = {};

    function fRow(dAlert) {
      dById[dAlert.id] = dAlert;
      return fEl("tr", { class: "clickable", tabindex: "0", "data-id": dAlert.id }, [
        fEl("td", { class: "mono" }, dAlert.soc_code || "—"),
        fEl("td", {}, P.fSeverityBadge(dAlert.severity)),
        fEl("td", { class: "cell-rule" }, dAlert.rule),
        fEl("td", { class: "cell-where" }, dAlert.module === "localsiem"
          ? [fEl("div", {}, "localSIEM"), fEl("div", { class: "muted small cell-break" }, dAlert.vhost || "")]
          : [fEl("div", { class: "mono cell-break" }, dAlert.ip || "—"), fEl("div", { class: "muted small cell-break" }, dAlert.vhost || "")]),
        fEl("td", { class: "mono" }, P.fFormatNumber(dAlert.count)),
        fEl("td", { class: "cell-times" }, [fEl("div", { class: "mono" }, P.fFormatDateTime(dAlert.first_seen)), fEl("div", { class: "mono muted" }, P.fFormatDateTime(dAlert.last_seen))]),
        fEl("td", {}, P.fStatusBadge("alert_status", dAlert.status)),
        fEl("td", { class: "cell-action" }, fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fOpen() {
          fOpenSearch(dAlert.soc_code ? "alert:" + dAlert.soc_code : dAlert.search, fShift(dAlert.window_start, -1), fShift(dAlert.last_seen > dAlert.window_end ? dAlert.last_seen : dAlert.window_end, 1));
        } }, [P.fIcon("search"), P.fText("alerts.open_search")]))
      ]);
    }

    async function fLoad(pMore) {
      try {
        const dAnswer = await P.fApi("GET", "/api/alerts" + P.fQuery({ status: vStatus.value, before: pMore ? vNext : "" }));
        if (!pMore) {
          P.fClear(vBody);
        }
        for (const dAlert of dAnswer.alerts) {
          vBody.appendChild(fRow(dAlert));
        }
        if (!vBody.children.length) {
          vBody.appendChild(P.fEmptyRow(8, "alerts.none"));
        }
        vNext = dAnswer.next;
        vMore.hidden = !vNext;
        P.fLabelStackTables(vBody.closest("table").parentElement);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    vBody.addEventListener("click", function fOnClick(pEvent) {
      if (pEvent.target.closest("button, a, .expanded-row")) {
        return;
      }
      const vRow = pEvent.target.closest("tr.clickable");
      if (!vRow) {
        return;
      }
      if (vRow.classList.contains("expanded")) {
        vRow.classList.remove("expanded");
        vRow.nextElementSibling.remove();
        return;
      }
      vRow.classList.add("expanded");
      const vCell = fEl("td", { colspan: 8 }, fEl("div", { class: "empty-state", i18n: "common.loading" }));
      vRow.after(fEl("tr", { class: "expanded-row" }, vCell));
      P.fApi("GET", "/api/alerts/" + vRow.getAttribute("data-id")).then(function fShow(dAlert) {
        P.fClear(vCell).appendChild(fEl("div", { class: "stack" }, [
          fEl("p", { class: "prewrap" }, dAlert.description),
          P.fDetailsList([
            [fT("alerts.category"), dAlert.category], [fT("alerts.type"), dAlert.type], [fT("alerts.external_id"), dAlert.external_id],
            [fT("alerts.window"), P.fFormatDateTime(dAlert.window_start) + " → " + P.fFormatDateTime(dAlert.window_end)],
            [fT("alerts.created"), P.fFormatDateTime(dAlert.created)], [fT("alerts.sent_at"), P.fFormatDateTime(dAlert.sent_at)],
            [fT("alerts.search"), dAlert.search], [fT("alerts.last_error"), dAlert.last_error ? P.fTOr("alert_error." + dAlert.last_error, dAlert.last_error) : ""],
            [fT("alerts.samples"), (dAlert.sample_uids || []).join(", ")]
          ]),
          dAlert.payload ? fEl("details", { class: "disclosure" }, [fEl("summary", {}, P.fText("alerts.payload")), fPre(JSON.stringify(dAlert.payload, null, 2))]) : null
        ]));
      }).catch(function fFail(vError) {
        P.fClear(vCell).appendChild(fEl("div", { class: "empty-state" }, P.fErrorText(vError)));
      });
    });
    vStatus.addEventListener("change", function fOnStatus() { fLoad(false); });
    vMore.addEventListener("click", function fOnMore() { fLoad(true); });
    pContainer.appendChild(fEl("section", { class: "card" }, [
      fEl("div", { class: "filters" }, [vStatus, fEl("button", { type: "button", class: "button button-secondary", onclick: function fRefresh() { fLoad(false); } }, [P.fIcon("reset"), P.fText("common.refresh")])]),
      P.fText("alerts.help", "p", { class: "muted small" }),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fEl("thead", {}, fEl("tr", {}, ["alerts.col_code", "alerts.col_severity", "alerts.col_rule", "alerts.col_where", "alerts.col_count", "alerts.col_times", "alerts.col_status", "alerts.col_actions"].map(function fHead(pKey) { return fEl("th", { i18n: pKey }); }))),
        vBody
      ])),
      fEl("div", { class: "pager" }, vMore)
    ]));
    fLoad(false);
    const fStop = P.fPoll(function fRefresh() { return vNext === null ? fLoad(false) : Promise.resolve(); }, 30000);
    return fStop;
  };

  // ---------- account ----------

  window.LocalsiemViews.account = function fAccountView(pContainer, pContext) {
    const dUser = pContext.vSession.user;
    const vName = fEl("input", { class: "input", value: dUser.full_name || "", maxlength: 120 });
    const vLanguage = fEl("select", { class: "select" }, P.cLanguages.map(function fOption(pCode) { return fEl("option", { value: pCode }, pCode); }));
    vLanguage.value = P.fGetLanguage();
    const vTheme = fEl("select", { class: "select" }, ["system", "light", "dark"].map(function fOption(pValue) { return fEl("option", { value: pValue, i18n: "theme." + pValue }); }));
    vTheme.value = P.fStoredTheme();
    vTheme.addEventListener("change", function fOnTheme() { P.fSetTheme(vTheme.value); });
    const vProfileError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    const vProfile = fEl("form", { class: "form-grid", novalidate: true }, [
      P.fDetailsList([[fT("account.username"), dUser.username], [fT("account.role"), fT("roles." + dUser.role)]]),
      vProfileError,
      fEl("label", { class: "field" }, [P.fText("account.full_name", "span", { class: "field-label" }), vName]),
      fEl("label", { class: "field" }, [P.fText("account.language", "span", { class: "field-label" }), vLanguage]),
      fEl("label", { class: "field" }, [P.fText("account.theme", "span", { class: "field-label" }), vTheme]),
      fEl("div", { class: "button-row" }, fEl("button", { type: "submit", class: "button button-primary", i18n: "common.save" }))
    ]);
    vProfile.addEventListener("submit", async function fSave(pEvent) {
      pEvent.preventDefault();
      vProfileError.hidden = true;
      try {
        await P.fApi("PATCH", "/api/account", { full_name: vName.value, language: vLanguage.value });
        dUser.full_name = vName.value;
        await P.fSetLanguage(vLanguage.value, false);
        P.fToast(fT("common.saved"), "success");
      } catch (vError) {
        vProfileError.hidden = false;
        vProfileError.textContent = P.fErrorText(vError);
      }
    });
    const vCurrent = fEl("input", { class: "input", type: "password", autocomplete: "current-password", maxlength: 256 });
    const vNew = fEl("input", { class: "input", type: "password", autocomplete: "new-password", maxlength: 256 });
    const vRepeat = fEl("input", { class: "input", type: "password", autocomplete: "new-password", maxlength: 256 });
    const vPasswordError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    const vPassword = fEl("form", { class: "form-grid", novalidate: true }, [
      vPasswordError,
      fEl("label", { class: "field" }, [P.fText("account.current_password", "span", { class: "field-label" }), vCurrent]),
      fEl("label", { class: "field" }, [P.fText("account.new_password", "span", { class: "field-label" }), vNew, P.fText("account.password_help", "span", { class: "field-help" })]),
      fEl("label", { class: "field" }, [P.fText("account.repeat_password", "span", { class: "field-label" }), vRepeat]),
      fEl("div", { class: "button-row" }, fEl("button", { type: "submit", class: "button button-primary", i18n: "account.change_password" }))
    ]);
    vPassword.addEventListener("submit", async function fChange(pEvent) {
      pEvent.preventDefault();
      vPasswordError.hidden = true;
      if (vNew.value !== vRepeat.value) {
        vPasswordError.hidden = false;
        vPasswordError.textContent = P.fErrorText({ vCode: "passwords_differ" });
        return;
      }
      try {
        await P.fApi("POST", "/api/account/password", { current: vCurrent.value, new: vNew.value });
        vCurrent.value = "";
        vNew.value = "";
        vRepeat.value = "";
        P.fToast(fT("account.password_changed"), "success");
      } catch (vError) {
        vPasswordError.hidden = false;
        vPasswordError.textContent = P.fErrorText(vError);
      }
    });
    const vResetTotp = fEl("button", { type: "button", class: "button button-secondary", i18n: "account.reset_totp", onclick: function fReset() {
      const vInput = fEl("input", { class: "input", type: "password", autocomplete: "current-password", maxlength: 256 });
      const vError = fEl("div", { class: "form-error", role: "alert", hidden: true });
      P.fModal(fT("account.reset_totp"), fEl("div", { class: "form-grid" }, [P.fText("account.reset_totp_help", "p"), vError, fEl("label", { class: "field" }, [P.fText("account.current_password", "span", { class: "field-label" }), vInput])]), [
        { i18n: "common.cancel", onClick: function fCancel(pClose) { pClose(); } },
        { i18n: "account.reset_totp", kind: "danger", onClick: async function fConfirm() {
          try {
            await P.fApi("POST", "/api/account/totp/reset", { password: vInput.value });
            window.location.assign("/auth/login/");
          } catch (vFailure) {
            vError.hidden = false;
            vError.textContent = P.fErrorText(vFailure);
          }
        } }
      ]);
    } });
    pContainer.appendChild(fEl("div", { class: "card-split account-grid" }, [
      fEl("section", { class: "card" }, [P.fText("account.profile", "h2", { class: "section-title" }), vProfile]),
      fEl("section", { class: "card" }, [P.fText("account.change_password", "h2", { class: "section-title" }), vPassword])
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("account.totp", "h2", { class: "section-title" }),
      fEl("p", {}, pContext.vSession.mfa_enabled ? fT(dUser.totp_enabled ? "account.totp_on" : "account.totp_pending") : fT("account.totp_disabled")),
      // With two-step verification off there is no authenticator app to set up again.
      pContext.vSession.mfa_enabled ? fEl("div", { class: "button-row" }, vResetTotp) : null
    ]));
    return null;
  };

  window.LocalsiemSearch = { fOpenSearch: fOpenSearch, fQuote: fQuote, fPre: fPre };
})();
