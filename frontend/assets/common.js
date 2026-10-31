"use strict";

// Shared browser code (adapted from the SOC, so both look and behave the
// same): translations, API calls, DOM building, modals, toasts, theme, clock
// and formatting. Every view uses window.Localsiem.

window.Localsiem = (function fCreateLocalsiem() {
  const cLanguages = ["en-GB", "en-US", "es-AR", "es-ES"];
  const cDefaultLanguage = "en-US";
  const cSeverities = ["critical", "high", "medium", "low"];
  let dMessages = {};
  let dFallback = {};
  let vLanguage = cDefaultLanguage;
  let vCsrf = "";
  const lLanguageListeners = [];

  // ---------- translations ----------

  function fLookup(pData, pKey) {
    let vNode = pData;
    for (const vPart of pKey.split(".")) {
      if (!vNode || typeof vNode !== "object" || !(vPart in vNode)) {
        return null;
      }
      vNode = vNode[vPart];
    }
    return typeof vNode === "string" ? vNode : null;
  }

  function fT(pKey, pValues) {
    let vText = fLookup(dMessages, pKey);
    if (vText === null) {
      vText = fLookup(dFallback, pKey);
    }
    if (vText === null) {
      return pKey;
    }
    if (pValues) {
      for (const [vName, vValue] of Object.entries(pValues)) {
        vText = vText.split("{" + vName + "}").join(String(vValue));
      }
    }
    return vText;
  }

  function fTOr(pKey, pFallback) {
    const vText = fT(pKey);
    return vText === pKey ? pFallback : vText;
  }

  async function fFetchLanguage(pLanguage) {
    // The version changes with the files, so an updated translation is never
    // read from an old copy in the browser's cache.
    const vVersion = document.body.getAttribute("data-lang-version") || "";
    const vResponse = await fetch("/locales/" + pLanguage + ".json?v=" + vVersion, { credentials: "same-origin" });
    if (!vResponse.ok) {
      throw new Error("language " + pLanguage);
    }
    return vResponse.json();
  }

  async function fLoadLanguage(pLanguage) {
    const vWanted = cLanguages.includes(pLanguage) ? pLanguage : cDefaultLanguage;
    try {
      if (!Object.keys(dFallback).length) {
        dFallback = await fFetchLanguage(cDefaultLanguage);
      }
      dMessages = vWanted === cDefaultLanguage ? dFallback : await fFetchLanguage(vWanted);
      vLanguage = vWanted;
    } catch (vError) {
      dMessages = dFallback;
      vLanguage = cDefaultLanguage;
    }
    document.documentElement.setAttribute("lang", vLanguage);
    fApplyTranslations(document);
    for (const vSelect of document.querySelectorAll(".language-select")) {
      vSelect.value = vLanguage;
    }
    for (const fListener of lLanguageListeners) {
      fListener(vLanguage);
    }
  }

  function fApplyTranslations(pRoot) {
    for (const vElement of pRoot.querySelectorAll("[data-i18n]")) {
      vElement.textContent = fT(vElement.getAttribute("data-i18n"));
    }
    for (const vElement of pRoot.querySelectorAll("[data-i18n-placeholder]")) {
      vElement.setAttribute("placeholder", fT(vElement.getAttribute("data-i18n-placeholder")));
    }
    for (const vElement of pRoot.querySelectorAll("[data-i18n-title]")) {
      vElement.setAttribute("title", fT(vElement.getAttribute("data-i18n-title")));
      vElement.setAttribute("aria-label", fT(vElement.getAttribute("data-i18n-title")));
    }
    fLabelStackTables(pRoot);
  }

  // Base of the dashboard on screen: /admin/dashboard/ or /user/dashboard/.
  function fDashboardBase() {
    return window.location.pathname.startsWith("/admin/") ? "/admin/dashboard/" : "/user/dashboard/";
  }

  function fSetTitle(pKey) {
    document.title = fT(pKey) + " · PYMEHackers localSIEM";
  }

  function fOnLanguageChange(pListener) {
    lLanguageListeners.push(pListener);
  }

  function fGetLanguage() {
    return vLanguage;
  }

  async function fSetLanguage(pLanguage, pPersist) {
    try {
      window.localStorage.setItem("localsiem.language", pLanguage);
    } catch (vError) {
      // Storage may be unavailable; the account setting still applies.
    }
    await fLoadLanguage(pLanguage);
    if (pPersist && vCsrf) {
      try {
        await fApi("PATCH", "/api/account", { language: vLanguage });
      } catch (vError) {
        fToastError(vError);
      }
    }
  }

  function fStoredLanguage() {
    try {
      return window.localStorage.getItem("localsiem.language");
    } catch (vError) {
      return null;
    }
  }

  // ---------- API ----------

  function fSetCsrf(pToken) {
    vCsrf = pToken || "";
  }

  class ApiError extends Error {
    constructor(pCode, pStatus, pData) {
      super(pCode);
      this.vCode = pCode;
      this.vStatus = pStatus;
      this.dData = pData || null;
    }
  }

  async function fApi(pMethod, pPath, pBody) {
    const dOptions = { method: pMethod, credentials: "same-origin", headers: { "Accept": "application/json" } };
    if (pMethod !== "GET") {
      dOptions.headers["X-CSRF-Token"] = vCsrf;
    }
    if (pBody !== undefined) {
      dOptions.headers["Content-Type"] = "application/json";
      dOptions.body = JSON.stringify(pBody);
    }
    let vResponse;
    try {
      vResponse = await fetch(pPath, dOptions);
    } catch (vError) {
      throw new ApiError("network_error", 0);
    }
    let dData = null;
    const vType = vResponse.headers.get("content-type") || "";
    if (vType.includes("application/json")) {
      try {
        dData = await vResponse.json();
      } catch (vError) {
        dData = null;
      }
    }
    // Only an expired session sends the user to the login page, keeping the
    // URL and its parameters to come back to.
    if (vResponse.status === 401 && !pPath.startsWith("/api/auth/") && !pPath.startsWith("/api/account/") && dData && dData.error === "authentication_required") {
      window.location.assign("/auth/login/?next=" + encodeURIComponent(window.location.pathname + window.location.search));
      throw new ApiError("authentication_required", 401);
    }
    if (!vResponse.ok) {
      const vCode = dData && typeof dData.error === "string" ? dData.error : "http_" + vResponse.status;
      throw new ApiError(vCode, vResponse.status, dData);
    }
    return dData;
  }

  function fQuery(pParameters) {
    const aParts = [];
    for (const [vKey, vValue] of Object.entries(pParameters || {})) {
      if (vValue !== null && vValue !== undefined && vValue !== "") {
        aParts.push(encodeURIComponent(vKey) + "=" + encodeURIComponent(vValue));
      }
    }
    return aParts.length ? "?" + aParts.join("&") : "";
  }

  function fErrorText(pError) {
    const vCode = pError && pError.vCode ? pError.vCode : "unknown_error";
    return fTOr("errors." + vCode, fT("errors.unknown_error") + " (" + vCode + ")");
  }

  // ---------- DOM ----------

  // Builds elements without innerHTML: every text from the API is inserted as
  // text, never as markup.
  function fEl(pTag, pAttributes, pChildren) {
    const vElement = pTag === "svg" || pTag === "use" ? document.createElementNS("http://www.w3.org/2000/svg", pTag) : document.createElement(pTag);
    for (const [vKey, vValue] of Object.entries(pAttributes || {})) {
      if (vValue === null || vValue === undefined || vValue === false) {
        continue;
      }
      if (vKey === "class") {
        vElement.setAttribute("class", vValue);
      } else if (vKey === "text") {
        vElement.textContent = vValue;
      } else if (vKey === "i18n") {
        vElement.setAttribute("data-i18n", vValue);
        vElement.textContent = fT(vValue);
      } else if (vKey.startsWith("on") && typeof vValue === "function") {
        vElement.addEventListener(vKey.slice(2), vValue);
      } else if (vValue === true) {
        vElement.setAttribute(vKey, "");
      } else {
        vElement.setAttribute(vKey, String(vValue));
      }
    }
    for (const vChild of [].concat(pChildren === undefined ? [] : pChildren)) {
      if (vChild === null || vChild === undefined || vChild === false) {
        continue;
      }
      vElement.appendChild(typeof vChild === "string" || typeof vChild === "number" ? document.createTextNode(String(vChild)) : vChild);
    }
    return vElement;
  }

  function fIcon(pName, pClass) {
    const vSvg = fEl("svg", { class: "icon" + (pClass ? " " + pClass : ""), "aria-hidden": "true", focusable: "false" });
    const vUse = fEl("use");
    vUse.setAttribute("href", document.body.getAttribute("data-icons") + "#i-" + pName);
    vSvg.appendChild(vUse);
    return vSvg;
  }

  function fText(pKey, pTag, pAttributes) {
    return fEl(pTag || "span", Object.assign({ i18n: pKey }, pAttributes || {}));
  }

  function fClear(pElement) {
    while (pElement.firstChild) {
      pElement.removeChild(pElement.firstChild);
    }
    return pElement;
  }

  function fById(pId) {
    return document.getElementById(pId);
  }

  // ---------- formatting ----------

  // Dates and times travel in the native format, UTC to the millisecond:
  // 2026/10/29@13:59:59.723. Any other format is calculated from it.
  const cNativeTimeRegex = /^(\d{4})\/(\d{2})\/(\d{2})@(\d{2}):(\d{2}):(\d{2})\.(\d{3})(?:([+-])(\d{2}):?(\d{2}))?$/;

  function fParseNativeTime(pValue) {
    const aMatch = cNativeTimeRegex.exec(String(pValue || "").trim());
    if (!aMatch) {
      return null;
    }
    let vMillis = Date.UTC(
      Number(aMatch[1]), Number(aMatch[2]) - 1, Number(aMatch[3]),
      Number(aMatch[4]), Number(aMatch[5]), Number(aMatch[6]), Number(aMatch[7])
    );
    if (aMatch[8]) {
      // The digits are the local time of that offset: UTC is the time minus the offset.
      const vOffset = (Number(aMatch[9]) * 60 + Number(aMatch[10])) * 60000;
      vMillis = aMatch[8] === "+" ? vMillis - vOffset : vMillis + vOffset;
    }
    return new Date(vMillis);
  }

  function fFormatNativeTime(pDate) {
    function fPad(pNumber, pSize) {
      return String(pNumber).padStart(pSize, "0");
    }
    return fPad(pDate.getUTCFullYear(), 4) + "/" + fPad(pDate.getUTCMonth() + 1, 2) + "/" + fPad(pDate.getUTCDate(), 2) +
      "@" + fPad(pDate.getUTCHours(), 2) + ":" + fPad(pDate.getUTCMinutes(), 2) + ":" + fPad(pDate.getUTCSeconds(), 2) +
      "." + fPad(pDate.getUTCMilliseconds(), 3);
  }

  function fFormatDateTime(pValue) {
    // Times are shown as they are stored: native format, in UTC, never relative.
    if (!pValue) {
      return "—";
    }
    const vDate = fParseNativeTime(pValue);
    return vDate === null ? String(pValue) : fFormatNativeTime(vDate);
  }

  function fFormatNumber(pValue) {
    return new Intl.NumberFormat(vLanguage).format(Number(pValue) || 0);
  }

  function fFormatBytes(pValue) {
    const vValue = Number(pValue) || 0;
    const aUnits = ["B", "KB", "MB", "GB", "TB"];
    let vIndex = 0;
    let vSize = vValue;
    while (vSize >= 1024 && vIndex < aUnits.length - 1) {
      vSize /= 1024;
      vIndex += 1;
    }
    return new Intl.NumberFormat(vLanguage, { maximumFractionDigits: vIndex ? 1 : 0 }).format(vSize) + " " + aUnits[vIndex];
  }

  function fSeverityBadge(pSeverity) {
    if (!pSeverity) {
      return fEl("span", { class: "muted" }, "—");
    }
    return fEl("span", { class: "badge severity severity-" + pSeverity, "data-i18n": "severity." + pSeverity }, fT("severity." + pSeverity));
  }

  function fStatusBadge(pKind, pStatus) {
    const dClass = { ok: "status-resolved", sent: "status-resolved", idle: "status-resolved", queued: "status-progress", buffer: "status-awaiting", rejected: "class-tp", error: "class-tp", warning: "status-awaiting", info: "status-progress" };
    return fEl("span", { class: "badge status " + (dClass[pStatus] || ""), "data-i18n": pKind + "." + pStatus }, fT(pKind + "." + pStatus));
  }

  // ---------- toasts and modals ----------

  function fToast(pMessage, pKind) {
    let vRegion = document.querySelector(".toast-region");
    if (!vRegion) {
      vRegion = fEl("div", { class: "toast-region", "aria-live": "polite" });
      document.body.appendChild(vRegion);
    }
    const vToast = fEl("div", { class: "toast toast-" + (pKind || "info"), role: "status" }, pMessage);
    vRegion.appendChild(vToast);
    window.setTimeout(function fHide() {
      vToast.classList.add("toast-leaving");
      window.setTimeout(function fRemove() {
        vToast.remove();
      }, 300);
    }, pKind === "error" ? 6000 : 3500);
  }

  function fToastError(pError) {
    fToast(fErrorText(pError), "error");
  }

  // Centred modal dialog: pContent is an element; pActions a list of
  // {i18n, kind, onClick(close)} buttons; pOnClose runs whenever it closes.
  function fModal(pTitle, pContent, pActions, pWide, pOnClose, pLocked) {
    const vPrevious = document.activeElement;
    const vBackdrop = fEl("div", { class: "modal-backdrop" });
    const vTitleId = "modal-title-" + Date.now();
    const vDialog = fEl("div", { class: "modal" + (pWide ? " modal-wide" : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": vTitleId });
    function fClose() {
      vBackdrop.remove();
      document.removeEventListener("keydown", fOnKey);
      if (vPrevious && vPrevious.focus) {
        vPrevious.focus();
      }
      if (pOnClose) {
        pOnClose();
      }
    }
    function fOnKey(pEvent) {
      if (pEvent.key === "Escape" && !pLocked) {
        fClose();
      }
    }
    const vHeader = fEl("div", { class: "modal-header" }, [
      fEl("h2", { id: vTitleId, class: "modal-title" }, pTitle),
      pLocked ? null : fEl("button", { type: "button", class: "icon-button", "aria-label": fT("common.close"), title: fT("common.close"), onclick: fClose }, "✕")
    ]);
    const vFooter = fEl("div", { class: "modal-footer" });
    for (const dAction of pActions || []) {
      vFooter.appendChild(fEl("button", {
        type: "button",
        class: "button " + (dAction.kind ? "button-" + dAction.kind : "button-secondary"),
        onclick: function fOnAction() {
          dAction.onClick(fClose);
        }
      }, fT(dAction.i18n)));
    }
    vDialog.appendChild(vHeader);
    vDialog.appendChild(fEl("div", { class: "modal-body" }, pContent));
    if ((pActions || []).length) {
      vDialog.appendChild(vFooter);
    }
    vBackdrop.appendChild(vDialog);
    vBackdrop.addEventListener("mousedown", function fOnBackdrop(pEvent) {
      if (pEvent.target === vBackdrop && !pLocked) {
        fClose();
      }
    });
    document.addEventListener("keydown", fOnKey);
    document.body.appendChild(vBackdrop);
    const vFocus = vDialog.querySelector("input, textarea, select, .modal-footer .button-primary, .modal-footer .button-danger") || vDialog.querySelector("button");
    if (vFocus) {
      vFocus.focus({ preventScroll: true });
    }
    vBackdrop.scrollTop = 0;
    return fClose;
  }

  function fConfirm(pTitle, pMessage, pConfirmKey, pDanger) {
    return new Promise(function fExecutor(pResolve) {
      fModal(pTitle, fEl("p", {}, pMessage), [
        { i18n: "common.cancel", kind: "secondary", onClick: function fCancel(pClose) { pResolve(false); pClose(); } },
        { i18n: pConfirmKey || "common.confirm", kind: pDanger ? "danger" : "primary", onClick: function fOk(pClose) { pResolve(true); pClose(); } }
      ], false, function fClosed() { pResolve(false); });
    });
  }

  async function fCopy(pText) {
    try {
      await navigator.clipboard.writeText(pText);
      fToast(fT("common.copied"), "success");
    } catch (vError) {
      fToast(fT("common.copy_failed"), "error");
    }
  }

  // Shows a secret once (generated password) with a copy button.
  function fShowSecret(pTitle, pExplanation, pSecret) {
    const vCode = fEl("code", { class: "secret-value" }, pSecret);
    const vCopy = fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fOnCopy() { fCopy(pSecret); } }, [fIcon("copy"), fT("common.copy")]);
    fModal(pTitle, fEl("div", { class: "secret-box" }, [fEl("p", {}, pExplanation), vCode, vCopy]), [
      { i18n: "common.done", kind: "primary", onClick: function fDone(pClose) { pClose(); } }
    ]);
  }

  // QR code and secret of a new second factor.
  function fMfaSetupBox(dSetup) {
    return fEl("div", { class: "mfa-setup" }, [
      dSetup.qr ? fEl("img", { class: "qr-image", src: dSetup.qr, alt: fT("mfa.qr_alt"), width: 200, height: 200 }) : null,
      fEl("div", { class: "stack" }, [
        fEl("p", {}, fT("mfa.scan_help")),
        fEl("p", { class: "muted small" }, fT("mfa.manual_help")),
        fEl("code", { class: "secret-value" }, String(dSetup.secret || "").replace(/(.{4})/g, "$1 ").trim())
      ])
    ]);
  }

  // ---------- theme, clock, tables ----------

  function fStoredTheme() {
    try {
      const vTheme = window.localStorage.getItem("localsiem.theme");
      return vTheme === "light" || vTheme === "dark" ? vTheme : "system";
    } catch (vError) {
      return "system";
    }
  }

  function fApplyTheme(pChoice) {
    let vTheme = pChoice;
    if (pChoice !== "light" && pChoice !== "dark") {
      vTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    document.documentElement.setAttribute("data-theme", vTheme);
    const vMeta = document.querySelector('meta[name="theme-color"]');
    if (vMeta) {
      vMeta.setAttribute("content", vTheme === "light" ? "#e5e5e5" : "#1a1a1a");
    }
  }

  function fSetTheme(pChoice) {
    try {
      if (pChoice === "light" || pChoice === "dark") {
        window.localStorage.setItem("localsiem.theme", pChoice);
      } else {
        window.localStorage.removeItem("localsiem.theme");
      }
    } catch (vError) {
      // The choice then only lasts for this page.
    }
    fApplyTheme(pChoice);
  }

  function fInitTheme() {
    for (const vButton of document.querySelectorAll(".theme-toggle")) {
      fClear(vButton);
      vButton.appendChild(fIcon("sun", "theme-icon-dark"));
      vButton.appendChild(fIcon("moon", "theme-icon-light"));
      vButton.addEventListener("click", function fToggle() {
        fSetTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
      });
    }
    // Without an explicit choice the page follows the system, also live.
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", function fOnSystem() {
        if (fStoredTheme() === "system") {
          fApplyTheme("system");
        }
      });
    }
  }

  function fStartClock() {
    function fTick() {
      const vText = fFormatNativeTime(new Date()).slice(11, 19);
      for (const vClock of document.querySelectorAll(".utc-clock")) {
        vClock.textContent = vText;
      }
    }
    fTick();
    window.setInterval(fTick, 1000);
  }

  // Tables shown as one card per row on phones: every cell gets the text of
  // its column header in data-label (CSS shows it before the value).
  function fLabelStackTables(pRoot) {
    for (const vTable of (pRoot || document).querySelectorAll("table.table-stack")) {
      const aLabels = Array.from(vTable.querySelectorAll("thead th")).map(function fText(pHeader) { return pHeader.textContent.trim(); });
      for (const vRow of vTable.querySelectorAll("tbody tr")) {
        const aCells = Array.from(vRow.children);
        if (aCells.length === 1 && aCells[0].hasAttribute("colspan")) {
          continue;
        }
        aCells.forEach(function fLabel(pCell, pIndex) {
          if (aLabels[pIndex]) {
            pCell.setAttribute("data-label", aLabels[pIndex]);
          }
        });
      }
    }
  }

  function fInitLanguageSelects() {
    for (const vSelect of document.querySelectorAll(".language-select")) {
      fClear(vSelect);
      for (const vCode of cLanguages) {
        vSelect.appendChild(fEl("option", { value: vCode }, vCode));
      }
      vSelect.value = vLanguage;
      vSelect.addEventListener("change", function fOnChange() {
        fSetLanguage(vSelect.value, true);
      });
    }
  }

  // A language selector and a theme button for a page built after the start
  // (the sign-in form, under its button): fInitLanguageSelects and fInitTheme
  // only wire the ones already in the page. Without a session the language
  // is only kept in this browser.
  function fLanguageSelect() {
    const vSelect = fEl("select", { class: "select select-compact language-select", "data-i18n-title": "common.language", title: fT("common.language"), "aria-label": fT("common.language") });
    for (const vCode of cLanguages) {
      vSelect.appendChild(fEl("option", { value: vCode }, vCode));
    }
    vSelect.value = vLanguage;
    vSelect.addEventListener("change", function fOnChange() {
      fSetLanguage(vSelect.value, true);
    });
    return vSelect;
  }

  function fThemeToggle() {
    const vButton = fEl("button", { type: "button", class: "icon-button theme-toggle", "data-i18n-title": "common.toggle_theme", title: fT("common.toggle_theme"), "aria-label": fT("common.toggle_theme") }, [
      fIcon("sun", "theme-icon-dark"),
      fIcon("moon", "theme-icon-light")
    ]);
    vButton.addEventListener("click", function fToggle() {
      fSetTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
    });
    return vButton;
  }

  function fEmptyRow(pColumns, pKey) {
    return fEl("tr", { class: "empty-row" }, fEl("td", { colspan: pColumns }, fEl("div", { class: "empty-state" }, fT(pKey))));
  }

  // Key/value list in the order given.
  function fDetailsList(aEntries) {
    const vList = fEl("dl", { class: "details-list" });
    for (const [vKey, vValue] of aEntries) {
      if (vValue === null || vValue === undefined || vValue === "") {
        continue;
      }
      vList.appendChild(fEl("div", { class: "details-row" }, [
        fEl("dt", {}, vKey),
        fEl("dd", {}, vValue instanceof Node ? vValue : (typeof vValue === "object" ? JSON.stringify(vValue) : String(vValue)))
      ]));
    }
    return vList;
  }

  function fDownload(pUrl) {
    const vLink = fEl("a", { href: pUrl, download: "" });
    document.body.appendChild(vLink);
    vLink.click();
    vLink.remove();
  }

  // Repeats pTask every pMilliseconds while the page is visible.
  function fPoll(pTask, pMilliseconds) {
    let vTimer = null;
    let vStopped = false;
    async function fTick() {
      if (vStopped) {
        return;
      }
      if (!document.hidden) {
        try {
          await pTask();
        } catch (vError) {
          // A failed refresh is retried on the next tick.
        }
      }
      if (!vStopped) {
        vTimer = window.setTimeout(fTick, pMilliseconds);
      }
    }
    vTimer = window.setTimeout(fTick, pMilliseconds);
    return function fStop() {
      vStopped = true;
      window.clearTimeout(vTimer);
    };
  }

  return {
    cLanguages, cSeverities,
    fT, fTOr, fLoadLanguage, fApplyTranslations, fOnLanguageChange, fGetLanguage, fSetLanguage, fStoredLanguage, fSetTitle, fDashboardBase,
    fApi, fQuery, fErrorText, ApiError, fSetCsrf,
    fEl, fIcon, fText, fClear, fById,
    fParseNativeTime, fFormatNativeTime, fFormatDateTime, fFormatNumber, fFormatBytes,
    fSeverityBadge, fStatusBadge, fMfaSetupBox,
    fToast, fToastError, fModal, fConfirm, fShowSecret, fCopy,
    fStoredTheme, fSetTheme, fApplyTheme, fInitTheme, fStartClock, fInitLanguageSelects, fLanguageSelect, fThemeToggle, fLabelStackTables,
    fEmptyRow, fDetailsList, fDownload, fPoll
  };
})();
