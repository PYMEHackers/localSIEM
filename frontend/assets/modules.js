"use strict";

// Modules: the installed modules of both dashboards, one row each (state;
// in the administrator dashboard also the switch to turn it on and off,
// locked while the server lacks what the module needs, Uninstall and, when
// the repository has a newer version, a notice with Update). The
// administrator dashboard has two sections, each at its own URL: Installed
// (/admin/dashboard/modules/installed/) and Installable
// (/admin/dashboard/modules/installable/: the modules of the
// localSIEM-modules repository that are not installed yet; modules are
// installed, updated and uninstalled only here). And the page of one module,
// /admin/dashboard/modules/installed/<name>/: state, requirements with
// Reconfigure, settings (built from its module.json), sources, doctor and
// rules.

window.LocalsiemViews = window.LocalsiemViews || {};

(function fModulesViews() {
  const P = window.Localsiem;
  const fEl = P.fEl;
  const fT = P.fT;
  const lStates = ["ok", "warning", "error", "pending", "disabled", "unknown"];

  // Texts of a module come with it (its locales/<language>.json).
  function fModuleText(dModule, pPath, pFallback) {
    function fLookup(dTexts) {
      let vNode = dTexts;
      for (const vPart of pPath.split(".")) {
        if (!vNode || typeof vNode !== "object" || !(vPart in vNode)) {
          return null;
        }
        vNode = vNode[vPart];
      }
      return typeof vNode === "string" ? vNode : null;
    }
    const dTexts = dModule.texts || {};
    const vText = fLookup(dTexts[P.fGetLanguage()]) || fLookup(dTexts["en-US"]);
    return vText === null ? (pFallback === undefined ? pPath : pFallback) : vText;
  }

  function fStatePill(pState) {
    const vState = lStates.includes(pState) ? pState : "unknown";
    return fEl("span", { class: "module-state module-state-" + vState, "data-i18n": "module_state." + vState }, fT("module_state." + vState));
  }

  function fReasons(dModule) {
    if (!(dModule.reasons || []).length) {
      return null;
    }
    return fEl("ul", { class: "module-reasons" }, dModule.reasons.map(function fReason(pReason) {
      if (pReason === "requirements_missing" && (dModule.requirements_missing || []).length) {
        return fEl("li", { class: "cell-break" }, fT("module_reason.requirements_missing") + " " + dModule.requirements_missing.join("; "));
      }
      return fEl("li", { class: "cell-break" }, pReason === "load_error" && dModule.error ? fT("module_reason.load_error") + " " + dModule.error : fT("module_reason." + pReason));
    }));
  }

  // A text to copy: the command for root or what fixes a check.
  function fCommandBox(pText) {
    return fEl("div", { class: "doctor-fix" }, [
      window.LocalsiemSearch.fPre(pText),
      fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fCopyText() { P.fCopy(pText); } }, [P.fIcon("copy"), P.fText("common.copy")])
    ]);
  }

  // One check of the doctor or of the requirements of a module: its state,
  // title and detail and, when it is not OK, what fixes it.
  function fCheckItem(dCheck) {
    return fEl("div", { class: "doctor-check doctor-" + dCheck.status }, [
      fEl("div", { class: "doctor-head" }, [P.fStatusBadge("check", dCheck.status), fEl("strong", { class: "cell-break" }, dCheck.title)]),
      dCheck.detail ? fEl("p", { class: "small cell-break" }, dCheck.detail) : null,
      dCheck.fix && dCheck.status !== "ok" ? fCommandBox(dCheck.fix) : null
    ]);
  }

  function fMetrics(dModule) {
    const aItems = [];
    aItems.push(["modules.sources_reading", dModule.sources_reading + " / " + dModule.sources]);
    aItems.push(["modules.lines_hour", P.fFormatNumber(dModule.lines_hour)]);
    aItems.push(["modules.last_data", dModule.last_data || "—"]);
    aItems.push(["modules.events_24h", P.fFormatNumber(dModule.events_24h)]);
    aItems.push(["modules.blocked_24h", P.fFormatNumber(dModule.blocked_24h)]);
    const dChecks = dModule.checks || {};
    aItems.push(["modules.doctor", fT("modules.doctor_counts", { ok: dChecks.ok || 0, warning: dChecks.warning || 0, error: dChecks.error || 0 })]);
    return fEl("dl", { class: "module-metrics" }, aItems.map(function fItem(aItem) {
      return fEl("div", { class: "module-metric" }, [fEl("dt", { i18n: aItem[0] }), fEl("dd", {}, aItem[1])]);
    }));
  }

  function fInternalLink(pContext, pHref, pChildren, pClass) {
    const vLink = fEl("a", { class: pClass || "button button-secondary", href: pHref }, pChildren);
    vLink.addEventListener("click", function fOnClick(pEvent) {
      if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
        return;
      }
      pEvent.preventDefault();
      pContext.fNavigate(pHref);
    });
    return vLink;
  }

  // On/off switch of a module (administrators). pDone runs after the change.
  function fSwitch(dModule, pDone) {
    const vName = fModuleText(dModule, "name", dModule.id);
    if (!dModule.enabled && (dModule.requirements_missing || []).length) {
      // Locked while the server lacks what the module needs: Reconfigure, in
      // the page of the module, unlocks it once it finds it.
      const vLocked = fEl("input", { type: "checkbox", role: "switch", disabled: true, "aria-label": fT("modules.switch_label", { module: vName }) });
      return fEl("label", { class: "toggle toggle-locked", title: fT("modules.locked_help") }, [vLocked, fEl("span", {}, fT("modules.locked_label"))]);
    }
    const vInput = fEl("input", { type: "checkbox", role: "switch", "aria-label": fT("modules.switch_label", { module: vName }) });
    vInput.checked = Boolean(dModule.enabled);
    const vLabel = fEl("span", {}, fT(dModule.enabled ? "modules.enabled_label" : "modules.disabled_label"));
    vInput.addEventListener("change", async function fOnChange() {
      const vEnable = vInput.checked;
      if (!vEnable && !await P.fConfirm(fT("modules.disable_title"), fT("modules.disable_confirm", { module: vName }), "modules.disable", true)) {
        vInput.checked = true;
        return;
      }
      vInput.disabled = true;
      try {
        const dAnswer = await P.fApi("POST", "/api/admin/modules/" + encodeURIComponent(dModule.id), { enabled: vEnable });
        P.fToast(fT(vEnable ? "modules.enabled_toast" : "modules.disabled_toast", { module: vName }) + (dAnswer.collector_notified ? "" : " " + fT("modules.collector_not_notified")), "success");
      } catch (vError) {
        vInput.checked = !vEnable;
        if (vError.vCode === "requirements_missing" && vError.dData && Array.isArray(vError.dData.requirements)) {
          // What is missing; the refresh below locks the switch.
          P.fToast(P.fErrorText(vError) + " " + vError.dData.requirements.map(function fTitle(dCheck) { return dCheck.title || dCheck.id; }).join("; "), "error");
        } else {
          P.fToastError(vError);
        }
      } finally {
        vInput.disabled = false;
      }
      vLabel.textContent = fT(vInput.checked ? "modules.enabled_label" : "modules.disabled_label");
      window.setTimeout(pDone, 1500);
    });
    return fEl("label", { class: "toggle" }, [vInput, vLabel]);
  }

  // Uninstall an installed module (administrators), also one that does not
  // load: after confirming, the web deletes it and the collector restarts
  // without it. pDone runs after the change.
  function fUninstallButton(dModule, pDone) {
    const vName = fModuleText(dModule, "name", dModule.id);
    const vButton = fEl("button", { type: "button", class: "button button-danger" }, fT("modules.uninstall"));
    vButton.addEventListener("click", async function fOnUninstall() {
      if (!await P.fConfirm(fT("modules.uninstall_title"), fT("modules.uninstall_confirm", { module: vName, id: dModule.id }), "modules.uninstall", true)) {
        return;
      }
      vButton.disabled = true;
      try {
        const dAnswer = await P.fApi("DELETE", "/api/admin/modules/" + encodeURIComponent(dModule.id));
        fForgetCatalog();
        P.fToast(fT("modules.uninstalled_toast", { module: vName }) + (dAnswer.collector_restarted ? "" : " " + fT("modules.uninstall_not_restarted")), "success");
        pDone();
      } catch (vError) {
        P.fToastError(vError);
        vButton.disabled = false;
      }
    });
    return vButton;
  }

  // ---------- the localSIEM-modules repository (administrators) ----------

  // The last answer of the repository (GET /api/admin/module-catalog), shared
  // by both sections for a while, so that Installed does not download the
  // repository each time it opens. Check the repository (Installable) always
  // downloads it again; installing, updating or uninstalling a module
  // forgets it.
  const cCatalogSeconds = 600;
  let dCatalogCache = null;

  async function fFetchCatalog(pFresh) {
    if (!pFresh && dCatalogCache && Date.now() - dCatalogCache.vTime < cCatalogSeconds * 1000) {
      return dCatalogCache.dAnswer;
    }
    const dAnswer = await P.fApi("GET", "/api/admin/module-catalog");
    dCatalogCache = { vTime: Date.now(), dAnswer: dAnswer };
    return dAnswer;
  }

  function fForgetCatalog() {
    dCatalogCache = null;
  }

  // ---------- sections of the administrator dashboard ----------

  // Sections of the Modules tab, each one at its own URL:
  // /admin/dashboard/modules/installed/ and /admin/dashboard/modules/installable/.
  function fModuleSections(pContext, pActive) {
    return fEl("nav", { class: "subtabs", "aria-label": fT("nav.modules") }, ["installed", "installable"].map(function fLink(pName) {
      const vHref = pContext.fBase() + "modules/" + pName + "/";
      const vLink = fEl("a", { class: "subtab" + (pName === pActive ? " active" : ""), href: vHref, i18n: "modules.section_" + pName, "aria-current": pName === pActive ? "page" : null });
      vLink.addEventListener("click", function fOnClick(pEvent) {
        if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
          return;
        }
        pEvent.preventDefault();
        pContext.fNavigate(vHref);
      });
      return vLink;
    }));
  }

  // ---------- installable modules (administrators) ----------

  // The modules of the localSIEM-modules repository (GitHub by default) that
  // are not installed yet: the only way to install them. Once one is
  // installed it leaves the list, and a dialog says what comes next: letting
  // localsiem read its logs needs root, so the answer brings the command that
  // does it.
  function fCatalogPanel(pContext) {
    const vBody = fEl("div", { class: "catalog-list" });
    const vSource = fEl("p", { class: "muted small cell-break", hidden: true });
    const vCheck = fEl("button", { type: "button", class: "button button-secondary" }, [P.fIcon("download"), P.fText("catalog.check")]);
    // Modules of the repository that are not installed (installed: null).
    let ldItems = [];
    let vRepositoryEmpty = false;

    function fResult(dItem, dAnswer) {
      const vName = fModuleText(dItem, "name", dItem.id);
      const vResult = fEl("div", { class: "stack cell-break" });
      if ((dAnswer.requirements_missing || []).length) {
        // The server lacks what the module needs (installing it never
        // installs that software): installed turned off, and the command for
        // root comes with Reconfigure, once it is there.
        vResult.appendChild(fEl("p", { class: "cell-break" }, fT(dAnswer.enabled ? "catalog.installed_detail" : "catalog.installed_off", { module: vName, version: dAnswer.version })));
        vResult.appendChild(fEl("div", { class: "doctor-list" }, dAnswer.requirements_missing.map(fCheckItem)));
        vResult.appendChild(fEl("p", { class: "muted small cell-break" }, fT("catalog.reconfigure_hint")));
      } else {
        vResult.appendChild(fEl("p", { class: "cell-break" }, fT("catalog.installed_detail", { module: vName, version: dAnswer.version })));
        vResult.appendChild(fEl("p", { class: "cell-break" }, fT("catalog.root_needed")));
        vResult.appendChild(fCommandBox(dAnswer.root_command));
        if (dAnswer.setup_option) {
          vResult.appendChild(fEl("p", { class: "muted small cell-break" }, fT("catalog.setup_hint", { option: dAnswer.setup_option })));
        }
      }
      if (!dAnswer.collector_restarted) {
        vResult.appendChild(fEl("p", { class: "muted small cell-break" }, fT("catalog.collector_not_restarted")));
      }
      return vResult;
    }

    async function fInstall(dItem, vButton) {
      const vName = fModuleText(dItem, "name", dItem.id);
      vButton.disabled = true;
      vButton.textContent = fT("catalog.installing");
      try {
        const dAnswer = await P.fApi("POST", "/api/admin/module-catalog/" + encodeURIComponent(dItem.id));
        fForgetCatalog();
        P.fToast(fT("catalog.installed_toast", { module: vName, version: dAnswer.version }), "success");
        // Installed, so it is no longer installable.
        ldItems = ldItems.filter(function fOther(dOther) { return dOther.id !== dItem.id; });
        fDraw();
        P.fModal(fT("catalog.installed_title", { module: vName }), fResult(dItem, dAnswer), [
          { i18n: "common.close", onClick: function fClose(pClose) { pClose(); } },
          { i18n: "catalog.go_installed", kind: "primary", onClick: function fGoInstalled(pClose) {
            pClose();
            pContext.fNavigate(pContext.fBase() + "modules/installed/");
          } }
        ], true);
      } catch (vError) {
        P.fToastError(vError);
        vButton.disabled = false;
        vButton.textContent = fT("catalog.action_install");
      }
    }

    function fItem(dItem) {
      const vName = fModuleText(dItem, "name", dItem.id);
      let vAction;
      if (dItem.action === "install") {
        vAction = fEl("button", { type: "button", class: "button button-small button-primary" }, fT("catalog.action_install"));
        vAction.addEventListener("click", function fOnInstall() { fInstall(dItem, vAction); });
      } else {
        vAction = fEl("span", { class: "muted small cell-break" }, fT("catalog.action_" + dItem.action, { core: dItem.core || "?" }));
      }
      return fEl("div", { class: "catalog-item" }, [
        fEl("div", { class: "catalog-item-text" }, [
          fEl("strong", {}, vName),
          fEl("span", { class: "module-meta" }, [fEl("span", { class: "mono" }, dItem.id), " · ", fT("modules.version", { version: dItem.version || "?" })]),
          fModuleText(dItem, "summary", "") ? fEl("p", { class: "small cell-break" }, fModuleText(dItem, "summary", "")) : null
        ]),
        vAction
      ]);
    }

    function fDraw() {
      P.fClear(vBody);
      for (const dItem of ldItems) {
        vBody.appendChild(fItem(dItem));
      }
      if (!ldItems.length) {
        vBody.appendChild(fEl("p", { class: "muted small", i18n: vRepositoryEmpty ? "catalog.empty" : "catalog.all_installed" }));
      }
    }

    async function fCheck() {
      vCheck.disabled = true;
      P.fClear(vBody);
      vBody.appendChild(fEl("p", { class: "muted small", i18n: "catalog.loading" }));
      try {
        const dAnswer = await fFetchCatalog(true);
        vSource.hidden = false;
        vSource.textContent = fT("catalog.source", { repository: dAnswer.repository, ref: dAnswer.ref });
        vRepositoryEmpty = !dAnswer.modules.length;
        // Only the modules that are not installed yet.
        ldItems = dAnswer.modules.filter(function fNotInstalled(dItem) { return dItem.installed === null || dItem.installed === undefined; });
        fDraw();
      } catch (vError) {
        P.fClear(vBody);
        P.fToastError(vError);
      } finally {
        vCheck.disabled = false;
      }
    }

    vCheck.addEventListener("click", fCheck);
    return fEl("section", { class: "card catalog-card" }, [
      fEl("h2", { class: "card-title", i18n: "catalog.title" }),
      P.fText("catalog.intro", "p", { class: "muted small cell-break" }),
      fEl("div", { class: "module-actions" }, vCheck),
      vSource,
      vBody
    ]);
  }

  // ---------- installed modules ----------

  window.LocalsiemViews.modules = function fModulesView(pContainer, pContext) {
    const vAdmin = pContext.fIsAdmin();
    // Administrators: Installed or Installable; the other users only see the
    // installed modules.
    const vSection = vAdmin && pContext.vParameter === "installable" ? "installable" : "installed";
    if (vAdmin) {
      pContainer.appendChild(fModuleSections(pContext, vSection));
    }
    if (vSection === "installable") {
      pContainer.appendChild(fCatalogPanel(pContext));
      return null;
    }
    const vList = fEl("div", { class: "module-list" });
    const vNotice = fEl("div", { class: "callout-note", hidden: true, i18n: "modules.collector_stopped" });
    // Administrators: whether the repository has newer versions of the
    // installed modules (checked when the section opens).
    const vRepositoryNote = fEl("p", { class: "muted small cell-break", hidden: true });
    // Items of the repository with a newer version of an installed module, by
    // id: action update (Update) or incompatible (it needs a newer localSIEM).
    let dNewer = {};
    // Modules being updated: the list is drawn again every 10 seconds.
    const sUpdating = new Set();
    // The last answer of /api/modules, to draw the list again without asking.
    let dLast = null;

    // The repository has a newer version of the module: Update or, when this
    // localSIEM cannot install it, what it needs. Only while the installed
    // version is the one the repository was compared with.
    function fUpdateNotice(dModule) {
      const dItem = dNewer[dModule.id];
      if (!vAdmin || !dItem || String(dItem.installed) !== String(dModule.version || "")) {
        return null;
      }
      if (dItem.action !== "update") {
        return fEl("p", { class: "module-update module-update-blocked small cell-break" }, fT("modules.update_incompatible", { version: dItem.version, core: dItem.core || "?" }));
      }
      const vUpdating = sUpdating.has(dModule.id);
      const vButton = fEl("button", { type: "button", class: "button button-small button-primary", disabled: vUpdating }, [P.fIcon("download"), P.fText(vUpdating ? "modules.updating" : "modules.update")]);
      vButton.addEventListener("click", function fOnUpdate() { fUpdate(dModule, dItem); });
      return fEl("div", { class: "module-update" }, [
        fEl("p", { class: "cell-break" }, fT("modules.update_notice", { version: dItem.version, installed: dItem.installed })),
        vButton
      ]);
    }

    // What the update did and, when the new version reads other logs or has
    // another setup option, the command for root.
    function fUpdateResult(pName, dAnswer) {
      const vResult = fEl("div", { class: "stack cell-break" });
      vResult.appendChild(fEl("p", { class: "cell-break" }, fT("modules.updated_detail", { module: pName, previous: dAnswer.previous || "?", version: dAnswer.version })));
      if (dAnswer.access_changed) {
        vResult.appendChild(fEl("p", { class: "cell-break" }, fT("modules.update_root_needed")));
        vResult.appendChild(fCommandBox(dAnswer.root_command));
        if (dAnswer.setup_option) {
          vResult.appendChild(fEl("p", { class: "muted small cell-break" }, fT("catalog.setup_hint", { option: dAnswer.setup_option })));
        }
      }
      if (!dAnswer.collector_restarted) {
        vResult.appendChild(fEl("p", { class: "muted small cell-break" }, fT("modules.update_not_restarted")));
      }
      return vResult;
    }

    // Installs the version of the repository over the installed one (the
    // same call that installs it): its settings are kept, and it stays on or
    // off. A dialog only when there is something else to do.
    async function fUpdate(dModule, dItem) {
      const vName = fModuleText(dModule, "name", dModule.id);
      if (!await P.fConfirm(fT("modules.update_title"), fT("modules.update_confirm", { module: vName, installed: dItem.installed, version: dItem.version }), "modules.update")) {
        return;
      }
      sUpdating.add(dModule.id);
      fDraw();
      try {
        const dAnswer = await P.fApi("POST", "/api/admin/module-catalog/" + encodeURIComponent(dModule.id));
        delete dNewer[dModule.id];
        fForgetCatalog();
        P.fToast(fT("modules.updated_toast", { module: vName, version: dAnswer.version }), "success");
        if (dAnswer.access_changed || !dAnswer.collector_restarted) {
          P.fModal(fT("modules.updated_title", { module: vName }), fUpdateResult(vName, dAnswer), [
            { i18n: "common.close", kind: "primary", onClick: function fClose(pClose) { pClose(); } }
          ], true);
        }
      } catch (vError) {
        P.fToastError(vError);
      } finally {
        sUpdating.delete(dModule.id);
        fLoad();
      }
    }

    // One card per module, the whole width, laid out like the header of the
    // page of the module, one part under the other: name, id and version
    // with, for administrators, the switch on the right; state, summary,
    // reasons and the notice of a newer version; its counters; and, for
    // administrators, the actions at the bottom.
    function fCard(dModule) {
      const vName = fModuleText(dModule, "name", dModule.id);
      const vSummary = fModuleText(dModule, "summary", "");
      const vNoMetrics = dModule.state === "disabled" || (dModule.state === "error" && !dModule.version);
      return fEl("section", { class: "card module-card module-card-" + dModule.state }, [
        fEl("div", { class: "module-head" }, [
          fEl("div", { class: "module-title" }, [
            fEl("h2", { class: "card-title" }, vName),
            fEl("span", { class: "module-meta" }, [
              fEl("span", { class: "mono" }, dModule.id),
              dModule.version ? " · " + fT("modules.version", { version: dModule.version }) : ""
            ])
          ]),
          vAdmin ? fSwitch(dModule, fLoad) : null
        ]),
        fStatePill(dModule.state),
        vSummary ? fEl("p", { class: "small cell-break" }, vSummary) : null,
        fReasons(dModule),
        fUpdateNotice(dModule),
        vNoMetrics ? null : fMetrics(dModule),
        vAdmin ? fCardActions(dModule) : null
      ]);
    }

    // Configure (a module that loads) and Uninstall (an installed one, also
    // when it does not load).
    function fCardActions(dModule) {
      const aActions = [];
      if (dModule.version) {
        aActions.push(fInternalLink(pContext, "/admin/dashboard/modules/installed/" + encodeURIComponent(dModule.id) + "/", [P.fIcon("settings"), P.fText("modules.configure")], "button button-primary"));
      }
      aActions.push(fUninstallButton(dModule, fLoad));
      return aActions.length ? fEl("div", { class: "module-actions" }, aActions) : null;
    }

    function fDraw() {
      if (!dLast) {
        return;
      }
      P.fClear(vList);
      vNotice.hidden = dLast.collector_running;
      for (const dModule of dLast.modules) {
        vList.appendChild(fCard(dModule));
      }
      if (!dLast.modules.length) {
        vList.appendChild(fEl("div", { class: "card empty-state", i18n: vAdmin ? "modules.none_admin" : "modules.none" }));
      }
    }

    async function fLoad() {
      try {
        dLast = await P.fApi("GET", "/api/modules");
        fDraw();
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    // Newer versions in the repository (administrators): downloaded once
    // when the section opens (or taken from the last answer, see
    // fFetchCatalog), never on each refresh of the list.
    async function fCheckRepository() {
      vRepositoryNote.hidden = false;
      vRepositoryNote.textContent = fT("modules.checking_updates");
      try {
        const dAnswer = await fFetchCatalog(false);
        dNewer = {};
        for (const dItem of dAnswer.modules) {
          if (dItem.newer && (dItem.action === "update" || dItem.action === "incompatible")) {
            dNewer[dItem.id] = dItem;
          }
        }
        vRepositoryNote.hidden = true;
        fDraw();
      } catch (vError) {
        vRepositoryNote.textContent = fT("modules.updates_failed", { error: P.fErrorText(vError) });
      }
    }

    pContainer.appendChild(P.fText(vAdmin ? "modules.help_admin" : "modules.help_user", "p", { class: "muted view-intro" }));
    pContainer.appendChild(vNotice);
    if (vAdmin) {
      pContainer.appendChild(vRepositoryNote);
    }
    pContainer.appendChild(vList);
    fLoad();
    if (vAdmin) {
      fCheckRepository();
    }
    return P.fPoll(fLoad, 10000);
  };

  // ---------- one module ----------

  function fSettingText(dModule, pKey, pPart) {
    return fModuleText(dModule, "settings." + pKey + "." + pPart, pPart === "label" ? pKey : "");
  }

  function fChoiceLabel(dModule, pValue) {
    return fModuleText(dModule, "choices." + pValue, pValue);
  }

  // Input of one setting (or of one field of a record); returns
  // {element, read()}.
  function fInput(dModule, dSetting, pValue) {
    if (dSetting.type === "boolean") {
      const vInput = fEl("input", { type: "checkbox" });
      vInput.checked = Boolean(pValue);
      return { element: vInput, read: function fRead() { return vInput.checked; } };
    }
    if (dSetting.type === "integer") {
      const vInput = fEl("input", { class: "input", type: "number", step: 1, inputmode: "numeric", min: dSetting.min, max: dSetting.max });
      vInput.value = pValue === null || pValue === undefined ? "" : String(pValue);
      return { element: vInput, read: function fRead() { return vInput.value === "" ? null : Number(vInput.value); } };
    }
    if (dSetting.type === "choice") {
      const aOptions = dSetting.required ? [] : [fEl("option", { value: "" }, "—")];
      for (const vChoice of dSetting.choices) {
        aOptions.push(fEl("option", { value: vChoice }, fChoiceLabel(dModule, vChoice)));
      }
      const vSelect = fEl("select", { class: "select" }, aOptions);
      vSelect.value = pValue || (dSetting.required ? dSetting.choices[0] : "");
      return { element: vSelect, read: function fRead() { return vSelect.value; } };
    }
    const vInput = fEl("input", { class: "input" + (dSetting.type === "path" ? " mono" : ""), type: "text", spellcheck: "false", autocomplete: "off", maxlength: dSetting.type === "path" ? 1024 : (dSetting.max_length || 500) });
    vInput.value = pValue || "";
    return { element: vInput, read: function fRead() { return vInput.value.trim(); } };
  }

  // Editor of a "records" setting: one block per record, add and remove.
  function fRecordsEditor(dModule, dSetting, aValues) {
    const vList = fEl("div", { class: "records" });
    const aRows = [];
    const vEmpty = fEl("p", { class: "muted small" }, fSettingText(dModule, dSetting.key, "empty"));

    function fRefreshEmpty() {
      vEmpty.hidden = aRows.length > 0;
    }

    function fAdd(dRecord) {
      const dInputs = {};
      const aFields = [];
      for (const dField of dSetting.fields) {
        dInputs[dField.key] = fInput(dModule, dField, (dRecord || {})[dField.key]);
        aFields.push(fEl("label", { class: "field" }, [
          fEl("span", { class: "field-label" }, fModuleText(dModule, "settings." + dSetting.key + ".fields." + dField.key, dField.key) + (dField.required ? " *" : "")),
          dInputs[dField.key].element
        ]));
      }
      const dRow = { inputs: dInputs };
      const vRemove = fEl("button", { type: "button", class: "button button-secondary button-small" }, fSettingText(dModule, dSetting.key, "remove") || fT("modules.remove"));
      const vItem = fEl("div", { class: "record-item" }, aFields.concat([fEl("div", { class: "record-actions" }, vRemove)]));
      vRemove.addEventListener("click", function fRemove() {
        aRows.splice(aRows.indexOf(dRow), 1);
        vItem.remove();
        fRefreshEmpty();
      });
      aRows.push(dRow);
      vList.appendChild(vItem);
      fRefreshEmpty();
    }

    for (const dRecord of aValues || []) {
      fAdd(dRecord);
    }
    fRefreshEmpty();
    const vAddButton = fEl("button", { type: "button", class: "button button-secondary button-small" }, [P.fIcon("list"), fSettingText(dModule, dSetting.key, "add") || fT("modules.add")]);
    vAddButton.addEventListener("click", function fOnAdd() {
      if (aRows.length >= (dSetting.max_items || 50)) {
        return;
      }
      fAdd({});
    });
    return {
      element: fEl("div", { class: "records-editor" }, [vEmpty, vList, fEl("div", { class: "button-row" }, vAddButton)]),
      read: function fRead() {
        return aRows.map(function fRow(dRow) {
          const dValues = {};
          for (const [vKey, dInput] of Object.entries(dRow.inputs)) {
            dValues[vKey] = dInput.read();
          }
          return dValues;
        });
      }
    };
  }

  function fSettingError(dModule, pError) {
    // invalid_setting:<key> or invalid_setting:<key>.<field>
    const vCode = pError && pError.vCode ? pError.vCode : "";
    if (!vCode.startsWith("invalid_setting:")) {
      return P.fErrorText(pError);
    }
    const aParts = vCode.slice("invalid_setting:".length).split(".");
    let vLabel = fSettingText(dModule, aParts[0], "label");
    if (aParts[1]) {
      vLabel += " › " + fModuleText(dModule, "settings." + aParts[0] + ".fields." + aParts[1], aParts[1]);
    }
    return fT("errors.invalid_setting", { setting: vLabel });
  }

  window.LocalsiemViews.module = function fModuleView(pContainer, pContext) {
    const vName = pContext.vParameter;
    const vApi = "/api/admin/modules/" + encodeURIComponent(vName);
    const vHeader = fEl("section", { class: "card module-card" });
    const vSettings = fEl("section", { class: "card" });
    const vSources = fEl("tbody");
    const vSkipped = fEl("div");
    const vDoctor = fEl("div", { class: "doctor-list" });
    const vSetupHint = fEl("div", { class: "module-requirements", hidden: true });
    // Answer of Reconfigure, kept while the header is drawn again.
    const vReconfigured = fEl("div", { class: "catalog-result", hidden: true });
    const vRules = fEl("tbody");
    const vRuleErrors = fEl("div");
    const vRulesError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    let vFormsBuilt = false;

    function fHead(aKeys) {
      return fEl("thead", {}, fEl("tr", {}, aKeys.map(function fCell(pKey) { return fEl("th", { i18n: pKey }); })));
    }

    // What the server must have before the module can be turned on, also
    // while it is off; once it is on and has them, its doctor checks them.
    function fRequirementsBlock(dModule) {
      const dRequirements = dModule.requirements || {};
      const ldChecks = dRequirements.checks || [];
      if (!ldChecks.length || (dModule.enabled && dRequirements.met)) {
        return null;
      }
      return fEl("div", { class: "module-requirements" }, [
        P.fText("modules.requirements", "h3", { class: "panel-subtitle" }),
        P.fText("modules.requirements_help", "p", { class: "muted small cell-break" }),
        dRequirements.time ? fEl("p", { class: "muted small" }, fT("sources.updated", { time: dRequirements.time })) : null,
        fEl("div", { class: "doctor-list" }, ldChecks.map(fCheckItem))
      ]);
    }

    function fShowReconfigured(dAnswer) {
      const dRequirements = dAnswer.requirements || {};
      P.fClear(vReconfigured);
      vReconfigured.hidden = false;
      if (!dRequirements.met) {
        P.fToast(fT("modules.reconfigure_missing"), "error");
        vReconfigured.appendChild(fEl("p", { class: "cell-break" }, fT("modules.reconfigure_missing")));
        return;
      }
      P.fToast(fT("modules.reconfigure_met"), "success");
      // Turning it on is the decision of the administrator: never done here.
      vReconfigured.appendChild(fEl("p", { class: "cell-break" }, fT(dAnswer.enabled ? "modules.reconfigure_met_on" : "modules.reconfigure_met_off")));
      if (dAnswer.root_command) {
        // The logs created after installing the module can only be read with
        // the read access that root gives.
        vReconfigured.appendChild(fEl("p", { class: "cell-break" }, fT("modules.reconfigure_root")));
        vReconfigured.appendChild(fCommandBox(dAnswer.root_command));
        if (dAnswer.setup_option) {
          vReconfigured.appendChild(fEl("p", { class: "muted small cell-break" }, fT("catalog.setup_hint", { option: dAnswer.setup_option })));
        }
      }
      if (!dAnswer.collector_notified) {
        vReconfigured.appendChild(fEl("p", { class: "muted small cell-break" }, fT("modules.collector_not_notified")));
      }
    }

    async function fReconfigure(pEvent) {
      const vButton = pEvent.currentTarget;
      vButton.disabled = true;
      try {
        const dAnswer = await P.fApi("POST", vApi + "/reconfigure");
        fShowReconfigured(dAnswer);
        await fLoad();
        // The collector checks them too, and with the module on it discovers
        // its sources again and runs its doctor.
        window.setTimeout(fLoad, 3000);
      } catch (vError) {
        P.fToastError(vError);
        vButton.disabled = false;
      }
    }

    function fDrawHeader(dModule) {
      P.fClear(vHeader);
      vHeader.className = "card module-card module-card-" + dModule.state;
      const vTitle = fModuleText(dModule, "name", dModule.id);
      pContext.fSetTitle(vTitle);
      vHeader.appendChild(fEl("div", { class: "module-head" }, [
        fEl("div", { class: "module-title" }, [
          fEl("h2", { class: "card-title" }, vTitle),
          fEl("span", { class: "module-meta" }, [
            fEl("span", { class: "mono" }, dModule.id), " · ", fT("modules.version", { version: dModule.version })
          ]),
          fEl("span", { class: "module-meta mono cell-break" }, dModule.path || "")
        ]),
        fSwitch(dModule, fLoad)
      ]));
      vHeader.appendChild(fStatePill(dModule.state));
      const vSummary = fModuleText(dModule, "summary", "");
      if (vSummary) {
        vHeader.appendChild(fEl("p", { class: "small cell-break" }, vSummary));
      }
      const vReasons = fReasons(dModule);
      if (vReasons) {
        vHeader.appendChild(vReasons);
      }
      if (dModule.state !== "disabled") {
        vHeader.appendChild(fMetrics(dModule));
      }
      const vRequirements = fRequirementsBlock(dModule);
      if (vRequirements) {
        vHeader.appendChild(vRequirements);
      }
      vHeader.appendChild(fEl("div", { class: "module-actions" }, [
        fInternalLink(pContext, "/admin/dashboard/modules/installed/", [P.fIcon("arrow-left"), P.fText("modules.back")]),
        fEl("button", { type: "button", class: "button button-secondary", onclick: async function fRunDoctor() {
          try {
            await P.fApi("POST", vApi + "/doctor");
            P.fToast(fT("sources.doctor_started"), "success");
            window.setTimeout(fLoad, 3000);
          } catch (vError) {
            P.fToastError(vError);
          }
        } }, [P.fIcon("reset"), P.fText("sources.rediscover")]),
        // Modules with requirements, also while they are off.
        dModule.has_requirements ? fEl("button", { type: "button", class: "button button-primary", onclick: fReconfigure }, [P.fIcon("settings"), P.fText("modules.reconfigure")]) : null,
        // Back to the list once it is uninstalled.
        fUninstallButton(dModule, function fBackToList() { pContext.fNavigate("/admin/dashboard/modules/installed/"); })
      ]));
      vHeader.appendChild(vReconfigured);
    }

    function fBuildSettings(dModule) {
      P.fClear(vSettings);
      vSettings.appendChild(P.fText("modules.settings", "h2", { class: "section-title" }));
      if (!(dModule.settings || []).length) {
        vSettings.appendChild(fEl("p", { class: "muted" }, fT("modules.settings_none")));
        return;
      }
      const vError = fEl("div", { class: "form-error", role: "alert", hidden: true });
      const dReaders = {};
      const aFields = [];
      for (const dSetting of dModule.settings) {
        const vValue = (dModule.values || {})[dSetting.key];
        const vHelp = fSettingText(dModule, dSetting.key, "help");
        if (dSetting.type === "records") {
          dReaders[dSetting.key] = fRecordsEditor(dModule, dSetting, vValue);
          aFields.push(fEl("div", { class: "field field-wide" }, [
            fEl("span", { class: "field-label" }, fSettingText(dModule, dSetting.key, "label")),
            vHelp ? fEl("span", { class: "field-help" }, vHelp) : null,
            dReaders[dSetting.key].element
          ]));
        } else if (dSetting.type === "boolean") {
          dReaders[dSetting.key] = fInput(dModule, dSetting, vValue);
          aFields.push(fEl("div", { class: "field field-wide" }, [
            fEl("label", { class: "check" }, [dReaders[dSetting.key].element, fEl("span", {}, fSettingText(dModule, dSetting.key, "label"))]),
            vHelp ? fEl("span", { class: "field-help" }, vHelp) : null
          ]));
        } else {
          dReaders[dSetting.key] = fInput(dModule, dSetting, vValue);
          aFields.push(fEl("label", { class: "field" }, [
            fEl("span", { class: "field-label" }, fSettingText(dModule, dSetting.key, "label")),
            dReaders[dSetting.key].element,
            vHelp ? fEl("span", { class: "field-help" }, vHelp) : null
          ]));
        }
      }
      const vForm = fEl("form", { class: "stack module-settings", novalidate: true }, [
        vError,
        fEl("div", { class: "form-grid form-grid-2 module-settings-grid" }, aFields),
        fEl("div", { class: "button-row" }, fEl("button", { type: "submit", class: "button button-primary", i18n: "modules.save_settings" }))
      ]);
      vForm.addEventListener("submit", async function fSave(pEvent) {
        pEvent.preventDefault();
        vError.hidden = true;
        const dValues = {};
        for (const [vKey, dReader] of Object.entries(dReaders)) {
          dValues[vKey] = dReader.read();
        }
        try {
          const dAnswer = await P.fApi("POST", vApi, { settings: dValues });
          P.fToast(fT(dAnswer.collector_notified ? "modules.saved_applying" : "modules.collector_not_notified"), "success");
          window.setTimeout(fLoad, 2000);
        } catch (vFailure) {
          vError.hidden = false;
          vError.textContent = fSettingError(dModule, vFailure);
        }
      });
      vSettings.appendChild(vForm);
    }

    function fBuildRules(dModule) {
      P.fClear(vRules);
      for (const dRule of dModule.rules || []) {
        const vEnabled = fEl("input", { type: "checkbox", "data-rule": dRule.id, "data-field": "enabled", "aria-label": dRule.name });
        vEnabled.checked = dRule.enabled;
        const vSeverity = fEl("select", { class: "select select-compact", "data-rule": dRule.id, "data-field": "severity" }, P.cSeverities.slice().reverse().map(function fOption(pValue) { return fEl("option", { value: pValue, i18n: "severity." + pValue }); }));
        vSeverity.value = dRule.severity;
        const vThreshold = fEl("input", { class: "input input-small", type: "number", min: 1, "data-rule": dRule.id, "data-field": "threshold", value: dRule.threshold, disabled: dRule.kind === "match" });
        const vWindow = fEl("input", { class: "input input-small", type: "number", min: 1, "data-rule": dRule.id, "data-field": "window", value: dRule.window, disabled: dRule.kind === "match" });
        vRules.appendChild(fEl("tr", {}, [
          fEl("td", {}, vEnabled),
          fEl("td", { class: "cell-rule" }, [fEl("div", {}, dRule.name), fEl("div", { class: "mono small muted" }, dRule.id + " · " + dRule.category)]),
          fEl("td", {}, vSeverity),
          fEl("td", {}, vThreshold),
          fEl("td", {}, vWindow)
        ]));
      }
      if (!vRules.children.length) {
        vRules.appendChild(P.fEmptyRow(5, "settings.no_rules"));
      }
    }

    async function fSaveRules() {
      vRulesError.hidden = true;
      const dRules = {};
      for (const vInput of vRules.querySelectorAll("[data-rule]")) {
        const vRule = vInput.getAttribute("data-rule");
        dRules[vRule] = dRules[vRule] || {};
        if (vInput.type === "checkbox") {
          dRules[vRule].enabled = vInput.checked;
        } else if (vInput.tagName === "SELECT") {
          dRules[vRule].severity = vInput.value;
        } else if (!vInput.disabled && vInput.value) {
          dRules[vRule][vInput.getAttribute("data-field")] = Number(vInput.value);
        }
      }
      try {
        const dAnswer = await P.fApi("POST", vApi, { rules: dRules });
        P.fToast(fT(dAnswer.collector_notified ? "modules.saved_applying" : "modules.collector_not_notified"), "success");
      } catch (vError) {
        vRulesError.hidden = false;
        vRulesError.textContent = P.fErrorText(vError);
      }
    }

    function fDrawStatus(dModule) {
      P.fClear(vSources);
      P.fClear(vSkipped);
      P.fClear(vDoctor);
      P.fClear(vRuleErrors);
      for (const dSource of dModule.sources_detail || []) {
        let vState = "ok";
        if (dSource.unreadable) {
          vState = "error";
        } else if (!dSource.exists) {
          vState = "warning";
        }
        vSources.appendChild(fEl("tr", {}, [
          fEl("td", {}, fEl("span", { class: "badge source-badge source-" + dSource.kind }, dSource.kind)),
          fEl("td", { class: "cell-break mono small" }, dSource.path),
          fEl("td", { class: "cell-break" }, dSource.vhost || "—"),
          fEl("td", { class: "mono" }, P.fFormatNumber(dSource.lines_hour)),
          fEl("td", { class: "mono" }, P.fFormatNumber(dSource.unparsed_hour)),
          fEl("td", { class: "mono" }, dSource.last_data || "—"),
          fEl("td", {}, P.fStatusBadge("check", vState))
        ]));
      }
      if (!vSources.children.length) {
        vSources.appendChild(P.fEmptyRow(7, dModule.enabled ? "sources.none" : "modules.disabled_no_sources"));
      }
      for (const dSkipped of dModule.skipped || []) {
        vSkipped.appendChild(fEl("p", { class: "small muted cell-break" }, dSkipped.kind + " · " + dSkipped.path + " · " + P.fTOr("skipped." + dSkipped.reason, dSkipped.reason)));
      }
      const dDoctor = dModule.doctor || {};
      if (dDoctor.time) {
        vDoctor.appendChild(fEl("p", { class: "muted small" }, fT("sources.updated", { time: dDoctor.time })));
      }
      for (const dCheck of dDoctor.checks || []) {
        vDoctor.appendChild(fCheckItem(dCheck));
      }
      if (!(dDoctor.checks || []).length) {
        vDoctor.appendChild(fEl("div", { class: "empty-state" }, fT(dModule.enabled ? "modules.doctor_none" : "modules.disabled_no_doctor")));
      }
      // The setup option is applied as root, with the command of the web.
      P.fClear(vSetupHint);
      vSetupHint.hidden = !dModule.setup_option || !dModule.root_command;
      if (!vSetupHint.hidden) {
        vSetupHint.appendChild(fEl("p", { class: "muted small cell-break" }, fT("modules.setup_hint", { option: dModule.setup_option })));
        vSetupHint.appendChild(fCommandBox(dModule.root_command + " " + dModule.setup_option));
      }
      for (const vError of dModule.rule_errors || []) {
        vRuleErrors.appendChild(fEl("p", { class: "small cell-break severity-critical" }, vError));
      }
    }

    async function fLoad() {
      try {
        const dModule = await P.fApi("GET", vApi);
        fDrawHeader(dModule);
        fDrawStatus(dModule);
        if (!vFormsBuilt) {
          fBuildSettings(dModule);
          fBuildRules(dModule);
          vFormsBuilt = true;
        }
        P.fApplyTranslations(pContainer);
      } catch (vError) {
        if (vError.vCode === "not_found") {
          pContext.fNavigate("/admin/dashboard/modules/installed/", true);
          return;
        }
        P.fToastError(vError);
      }
    }

    pContainer.appendChild(vHeader);
    pContainer.appendChild(vSettings);
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("modules.sources", "h2", { class: "section-title" }),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["sources.col_kind", "sources.col_path", "sources.col_vhost", "sources.col_lines", "sources.col_unparsed", "sources.col_last", "sources.col_state"]), vSources
      ])),
      vSkipped
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("modules.doctor_title", "h2", { class: "section-title" }),
      P.fText("modules.doctor_help", "p", { class: "muted small" }),
      vSetupHint,
      vDoctor
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("modules.rules", "h2", { class: "section-title" }),
      P.fText("modules.rules_help", "p", { class: "muted small" }),
      vRulesError,
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["settings.col_enabled", "settings.col_rule", "settings.col_severity", "settings.col_threshold", "settings.col_window"]), vRules
      ])),
      vRuleErrors,
      fEl("div", { class: "button-row" }, fEl("button", { type: "button", class: "button button-primary", onclick: fSaveRules, i18n: "modules.save_rules" }))
    ]));
    fLoad();
    return P.fPoll(fLoad, 15000);
  };

  window.LocalsiemModules = { fModuleText: fModuleText, fStatePill: fStatePill };
})();
