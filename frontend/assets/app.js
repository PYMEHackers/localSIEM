"use strict";

// Shell of localSIEM: sign-in pages, sidebar with one tab per URL, title bar
// (title on the left; language, theme and UTC clock on the right) and the
// router that shows each view. Views live in overview.js, search.js,
// modules.js and admin.js.
//
// Two dashboards: administrators work in /admin/dashboard/<tab>/ (with the
// configuration tabs) and the other users in /user/dashboard/<tab>/. A URL
// of the other dashboard is taken to the same tab of one's own.

(function fApp() {
  const P = window.Localsiem;
  const fEl = P.fEl;
  const fT = P.fT;
  const dState = { vSession: null, fCleanup: null };
  // group: section of the sidebar (adminGroup: the one of the administrator
  // dashboard); adminOnly: only in /admin/dashboard/.
  const ldTabs = [
    { name: "overview", icon: "dashboard", key: "nav.overview", group: "analysis" },
    { name: "search", icon: "search", key: "nav.search", group: "analysis" },
    { name: "live", icon: "activity", key: "nav.live", group: "analysis" },
    { name: "alerts", icon: "bell", key: "nav.alerts", group: "analysis" },
    { name: "modules", icon: "plug", key: "nav.modules", group: "analysis", adminGroup: "admin" },
    { name: "users", icon: "users", key: "nav.users", group: "admin", adminOnly: true },
    { name: "soc", icon: "soc", key: "nav.soc", group: "admin", adminOnly: true },
    { name: "channels", icon: "channels", key: "nav.channels", group: "admin", adminOnly: true },
    { name: "settings", icon: "settings", key: "nav.settings", group: "admin", adminOnly: true },
    { name: "audit", icon: "eye", key: "nav.audit", group: "admin", adminOnly: true },
    { name: "logins", icon: "shield-check", key: "nav.logins", group: "admin", adminOnly: true },
    { name: "account", icon: "user", key: "nav.account", group: "account" }
  ];
  const cPathRegex = /^\/(user|admin)\/dashboard\/([a-z]+)\/(?:([a-z][a-z0-9_]{1,31})\/)?(?:([a-z][a-z0-9_]{1,31})\/)?$/;
  // Sections of the Users tab (the first one opens by default).
  const lUserSections = ["accounts", "tokens"];
  // Sections of the Channels tab (the first one opens by default).
  const lChannelSections = ["general", "telegram"];
  // Sections of the Modules tab of administrators (the first one opens by
  // default); the page of one module is /admin/dashboard/modules/installed/<name>/.
  const lModuleSections = ["installed", "installable"];

  function fSafeNext(pValue) {
    // Only a path of this site: never another origin, never the sign-in pages.
    const vValue = String(pValue || "");
    if (!vValue.startsWith("/") || vValue.startsWith("//") || vValue.startsWith("/\\") || vValue.startsWith("/auth/")) {
      return "";
    }
    return vValue;
  }

  function fIsAdmin() {
    return dState.vSession && dState.vSession.user && dState.vSession.user.role === "admin";
  }

  function fBoard() {
    return fIsAdmin() ? "admin" : "user";
  }

  function fBase() {
    return "/" + fBoard() + "/dashboard/";
  }

  function fHome() {
    return fBase() + "overview/";
  }

  function fTabGroup(dTab) {
    return fIsAdmin() && dTab.adminGroup ? dTab.adminGroup : dTab.group;
  }

  function fNavigate(pUrl, pReplace) {
    if (pReplace) {
      window.history.replaceState(null, "", pUrl);
    } else {
      window.history.pushState(null, "", pUrl);
    }
    fRoute();
  }

  // ---------- sign-in pages ----------

  // The sign-in pages are only the form: the logo on top, then the fields and
  // the button at the bottom (the sign-in form adds the language and the
  // theme under its button).
  function fAuthLogo() {
    return fEl("div", { class: "brand auth-logo" }, [
      fEl("img", { src: document.body.getAttribute("data-logo"), alt: "" }),
      fEl("span", { class: "brand-text" }, [fEl("span", { class: "brand-name" }, "PYMEHackers"), fEl("span", { class: "brand-product" }, "localSIEM")])
    ]);
  }

  function fFormError(pElement, pError) {
    pElement.hidden = !pError;
    pElement.textContent = pError ? P.fErrorText(pError) : "";
  }

  function fLoginView() {
    const vContent = P.fClear(P.fById("auth-content"));
    P.fSetTitle("login.title");
    const vNext = fSafeNext(new URLSearchParams(window.location.search).get("next"));
    let vChallenge = "";
    const vError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    // A direct sign-in with a token that does not work comes back here with
    // ?error=<reason>.
    const vReason = new URLSearchParams(window.location.search).get("error");
    if (vReason) {
      fFormError(vError, { vCode: vReason });
    }
    const vUsername = fEl("input", { class: "input", type: "text", autocomplete: "username", required: true, maxlength: 128, id: "login-username" });
    const vPassword = fEl("input", { class: "input", type: "password", autocomplete: "current-password", required: true, maxlength: 256, id: "login-password" });
    const vToggle = fEl("button", { type: "button", class: "icon-button", "aria-pressed": "false", "data-i18n-title": "login.show_password", title: fT("login.show_password"), "aria-label": fT("login.show_password") }, P.fIcon("eye"));
    vToggle.addEventListener("click", function fToggle() {
      const vShow = vPassword.type === "password";
      vPassword.type = vShow ? "text" : "password";
      vToggle.setAttribute("aria-pressed", vShow ? "true" : "false");
    });
    const vSubmit = fEl("button", { type: "submit", class: "button button-primary button-block", i18n: "login.submit" });
    // The language shown when the button is pressed becomes the language of
    // the account (fDone).
    let vLoginLanguage = "";
    const vForm = fEl("form", { class: "auth-card auth-card-narrow", novalidate: true }, [
      fAuthLogo(),
      P.fText("login.title", "h1", { class: "sr-only" }),
      vError,
      fEl("label", { class: "field" }, [P.fText("login.username", "span", { class: "field-label" }), vUsername]),
      fEl("label", { class: "field" }, [P.fText("login.password", "span", { class: "field-label" }), fEl("span", { class: "password-wrap" }, [vPassword, vToggle])]),
      vSubmit,
      fEl("div", { class: "auth-preferences" }, [P.fLanguageSelect(), P.fThemeToggle()])
    ]);
    const vCodeError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    const vCode = fEl("input", { class: "input otp-input", autocomplete: "one-time-code", inputmode: "numeric", maxlength: 8, required: true, id: "login-code" });
    const vSetupBox = fEl("div");
    const vCodeTitle = P.fText("mfa.verify_title", "h2");
    const vCodeHelp = P.fText("mfa.verify_help", "p");
    const vCodeForm = fEl("form", { class: "auth-card", novalidate: true, hidden: true }, [
      fAuthLogo(),
      fEl("div", { class: "stack" }, [vCodeTitle, vCodeHelp]),
      vSetupBox,
      vCodeError,
      fEl("label", { class: "field" }, [P.fText("mfa.code", "span", { class: "field-label" }), vCode]),
      fEl("button", { type: "submit", class: "button button-primary button-block", i18n: "mfa.verify" }),
      fEl("button", { type: "button", class: "button button-link", onclick: function fBack() {
        vCodeForm.hidden = true;
        vForm.hidden = false;
        vPassword.value = "";
        vPassword.focus();
      } }, [P.fIcon("arrow-left"), P.fText("mfa.back")])
    ]);
    vContent.appendChild(vForm);
    vContent.appendChild(vCodeForm);
    vUsername.focus();

    async function fDone() {
      dState.vSession = await P.fApi("GET", "/api/auth/session");
      P.fSetCsrf(dState.vSession.csrf);
      // The dashboards open in the language of the account: it takes the one
      // of the sign-in page, and keeps it until the user changes it.
      if (vLoginLanguage && dState.vSession.user && dState.vSession.user.language !== vLoginLanguage) {
        try {
          await P.fApi("PATCH", "/api/account", { language: vLoginLanguage });
        } catch (vFailure) {
          // The sign-in never fails for it: the dashboard then opens in the
          // language the account already had.
        }
      }
      window.location.assign(vNext || fHome());
    }

    vForm.addEventListener("submit", async function fOnSubmit(pEvent) {
      pEvent.preventDefault();
      fFormError(vError, null);
      if (!vUsername.value.trim() || !vPassword.value) {
        fFormError(vError, { vCode: "credentials_required" });
        return;
      }
      vLoginLanguage = P.fGetLanguage();
      vSubmit.disabled = true;
      try {
        const dAnswer = await P.fApi("POST", "/api/auth/login", { username: vUsername.value.trim(), password: vPassword.value });
        if (dAnswer.step === "done") {
          await fDone();
          return;
        }
        vChallenge = dAnswer.challenge;
        P.fClear(vSetupBox);
        if (dAnswer.step === "enroll") {
          vCodeTitle.setAttribute("data-i18n", "mfa.setup_title");
          vCodeHelp.setAttribute("data-i18n", "mfa.setup_required");
          vSetupBox.appendChild(P.fMfaSetupBox(dAnswer));
        } else {
          vCodeTitle.setAttribute("data-i18n", "mfa.verify_title");
          vCodeHelp.setAttribute("data-i18n", "mfa.verify_help");
        }
        vCodeTitle.textContent = fT(vCodeTitle.getAttribute("data-i18n"));
        vCodeHelp.textContent = fT(vCodeHelp.getAttribute("data-i18n"));
        // Only the code: as narrow as the sign-in form. The setup puts the QR
        // code next to the text, so it keeps the full width.
        vCodeForm.classList.toggle("auth-card-narrow", dAnswer.step !== "enroll");
        vForm.hidden = true;
        vCodeForm.hidden = false;
        vCode.value = "";
        vCode.focus();
      } catch (vFailure) {
        fFormError(vError, vFailure);
      } finally {
        vSubmit.disabled = false;
      }
    });

    vCodeForm.addEventListener("submit", async function fOnCode(pEvent) {
      pEvent.preventDefault();
      fFormError(vCodeError, null);
      try {
        await P.fApi("POST", "/api/auth/totp", { challenge: vChallenge, code: vCode.value.replace(/\s+/g, "") });
        await fDone();
      } catch (vFailure) {
        fFormError(vCodeError, vFailure);
        if (vFailure.vCode === "challenge_expired") {
          vCodeForm.hidden = true;
          vForm.hidden = false;
        }
      }
    });
  }

  function fInfoView(pTitleKey, pTextKey) {
    const vContent = P.fClear(P.fById("auth-content"));
    P.fSetTitle(pTitleKey);
    vContent.appendChild(fEl("div", { class: "auth-card" }, [
      fAuthLogo(),
      fEl("div", { class: "stack" }, [P.fText(pTitleKey, "h2"), P.fText(pTextKey, "p")]),
      fEl("a", { class: "button button-primary button-block", href: "/auth/login/", i18n: "login.back_to_login" })
    ]));
  }

  // ---------- dashboard shell ----------

  function fBuildNav() {
    const vNav = P.fClear(P.fById("nav"));
    let vGroup = "";
    for (const dTab of ldTabs) {
      if (dTab.adminOnly && !fIsAdmin()) {
        continue;
      }
      const vTabGroup = fTabGroup(dTab);
      if (vGroup && vTabGroup !== vGroup) {
        vNav.appendChild(fEl("hr", { class: "nav-separator" }));
      }
      vGroup = vTabGroup;
      const vPath = fBase() + dTab.name + "/";
      const vLink = fEl("a", { class: "nav-item", href: vPath, "data-view": dTab.name }, [P.fIcon(dTab.icon), fEl("span", { class: "nav-label", i18n: dTab.key })]);
      vLink.addEventListener("click", function fOnClick(pEvent) {
        if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
          return;
        }
        pEvent.preventDefault();
        document.body.classList.remove("sidebar-open");
        fNavigate(vPath);
      });
      vNav.appendChild(vLink);
    }
    for (const vBrand of document.querySelectorAll(".app .brand")) {
      vBrand.setAttribute("href", fHome());
    }
  }

  function fInitShell() {
    const vMenu = P.fById("menu-toggle");
    vMenu.appendChild(P.fIcon("menu"));
    vMenu.addEventListener("click", function fToggleMenu() {
      document.body.classList.toggle("sidebar-open");
    });
    P.fById("sidebar-scrim").addEventListener("click", function fCloseMenu() {
      document.body.classList.remove("sidebar-open");
    });
    const vLogout = P.fById("logout-button");
    vLogout.appendChild(P.fIcon("logout"));
    vLogout.appendChild(P.fText("common.logout"));
    vLogout.addEventListener("click", async function fLogout() {
      try {
        await P.fApi("POST", "/api/auth/logout");
      } catch (vError) {
        // The session may already be gone; the login page follows anyway.
      }
      window.location.assign("/auth/login/");
    });
  }

  function fForcePasswordChange() {
    const vError = fEl("div", { class: "form-error", role: "alert", hidden: true });
    const vCurrent = fEl("input", { class: "input", type: "password", autocomplete: "current-password", maxlength: 256 });
    const vNew = fEl("input", { class: "input", type: "password", autocomplete: "new-password", maxlength: 256 });
    const vRepeat = fEl("input", { class: "input", type: "password", autocomplete: "new-password", maxlength: 256 });
    P.fModal(fT("account.change_password"), fEl("div", { class: "form-grid" }, [
      P.fText("account.must_change", "p"),
      vError,
      fEl("label", { class: "field" }, [P.fText("account.current_password", "span", { class: "field-label" }), vCurrent]),
      fEl("label", { class: "field" }, [P.fText("account.new_password", "span", { class: "field-label" }), vNew, P.fText("account.password_help", "span", { class: "field-help" })]),
      fEl("label", { class: "field" }, [P.fText("account.repeat_password", "span", { class: "field-label" }), vRepeat])
    ]), [{ i18n: "common.save", kind: "primary", onClick: async function fSave(pClose) {
      fFormError(vError, null);
      if (vNew.value !== vRepeat.value) {
        fFormError(vError, { vCode: "passwords_differ" });
        return;
      }
      try {
        await P.fApi("POST", "/api/account/password", { current: vCurrent.value, new: vNew.value });
        dState.vSession.user.must_change_password = false;
        P.fToast(fT("account.password_changed"), "success");
        pClose();
      } catch (vFailure) {
        fFormError(vError, vFailure);
      }
    } }], false, null, true);
  }

  function fShowView(pName, pParameter, pItem) {
    if (dState.fCleanup) {
      try {
        dState.fCleanup();
      } catch (vError) {
        // A view that fails to clean up never blocks the next one.
      }
      dState.fCleanup = null;
    }
    const dTab = ldTabs.find(function fFind(pTab) { return pTab.name === pName; });
    for (const vLink of document.querySelectorAll(".nav-item")) {
      const vActive = vLink.getAttribute("data-view") === pName;
      vLink.classList.toggle("active", vActive);
      if (vActive) {
        vLink.setAttribute("aria-current", "page");
      } else {
        vLink.removeAttribute("aria-current");
      }
    }
    const vTitle = P.fById("page-title");
    vTitle.setAttribute("data-i18n", dTab.key);
    vTitle.textContent = fT(dTab.key);
    P.fSetTitle(dTab.key);
    const vView = P.fClear(P.fById("view"));
    const dContext = {
      vSession: dState.vSession, fNavigate: fNavigate, fIsAdmin: fIsAdmin, fBase: fBase, vParameter: pItem || pParameter || "",
      fSetTitle: function fSetPageTitle(pText) {
        vTitle.removeAttribute("data-i18n");
        vTitle.textContent = pText;
        document.title = pText + " · PYMEHackers localSIEM";
      }
    };
    // /admin/dashboard/modules/installed/<name>/ is the page of one module.
    const fRender = window.LocalsiemViews[pName === "modules" && pItem ? "module" : pName];
    dState.fCleanup = fRender ? fRender(vView, dContext) || null : null;
    P.fApplyTranslations(vView);
    window.scrollTo(0, 0);
  }

  function fRoute() {
    const vPath = window.location.pathname;
    if (vPath.startsWith("/auth/")) {
      P.fById("app-root").hidden = true;
      P.fById("auth-root").hidden = false;
      if (vPath === "/auth/register/") {
        fInfoView("register.title", "register.text");
      } else if (vPath === "/auth/recover/") {
        fInfoView("recover.title", "recover.text");
      } else if (dState.vSession && dState.vSession.authenticated) {
        window.location.replace(fSafeNext(new URLSearchParams(window.location.search).get("next")) || fHome());
      } else {
        fLoginView();
      }
      return;
    }
    if (!dState.vSession || !dState.vSession.authenticated) {
      window.location.replace("/auth/login/?next=" + encodeURIComponent(vPath + window.location.search));
      return;
    }
    P.fById("auth-root").hidden = true;
    P.fById("app-root").hidden = false;
    const aMatch = vPath.match(cPathRegex);
    const dTab = aMatch ? ldTabs.find(function fFind(pTab) { return pTab.name === aMatch[2]; }) : null;
    if (!dTab || (dTab.adminOnly && !fIsAdmin())) {
      fNavigate(fHome(), true);
      return;
    }
    const vParameter = aMatch[3] || "";
    // Only the page of one installed module has a second part.
    const vItem = aMatch[4] || "";
    if (dTab.name === "users" && fIsAdmin() && !lUserSections.includes(vParameter)) {
      fNavigate(fBase() + "users/" + lUserSections[0] + "/", true);
      return;
    }
    if (dTab.name === "users" && vItem) {
      fNavigate(fBase() + "users/" + vParameter + "/", true);
      return;
    }
    if (dTab.name === "channels" && !lChannelSections.includes(vParameter)) {
      fNavigate(fBase() + "channels/" + lChannelSections[0] + "/", true);
      return;
    }
    if (dTab.name === "channels" && vItem) {
      fNavigate(fBase() + "channels/" + vParameter + "/", true);
      return;
    }
    if (dTab.name === "modules" && fIsAdmin()) {
      if (!lModuleSections.includes(vParameter)) {
        // /admin/dashboard/modules/ opens Installed; the older URL of a
        // module, /admin/dashboard/modules/<name>/, goes to its page.
        fNavigate(fBase() + "modules/" + lModuleSections[0] + "/" + (vParameter ? vParameter + "/" : ""), true);
        return;
      }
      if (vItem && vParameter !== "installed") {
        fNavigate(fBase() + "modules/" + vParameter + "/", true);
        return;
      }
    }
    if (vParameter && dTab.name !== "users" && dTab.name !== "channels" && (dTab.name !== "modules" || !fIsAdmin())) {
      fNavigate(fBase() + dTab.name + "/", true);
      return;
    }
    if (aMatch[1] !== fBoard()) {
      // The same tab, in the dashboard of this user.
      fNavigate(fBase() + dTab.name + "/" + (vParameter ? vParameter + "/" : "") + (vItem ? vItem + "/" : "") + window.location.search, true);
      return;
    }
    fShowView(dTab.name, vParameter, vItem);
  }

  async function fStart() {
    P.fInitTheme();
    P.fStartClock();
    try {
      dState.vSession = await P.fApi("GET", "/api/auth/session");
    } catch (vError) {
      dState.vSession = { authenticated: false };
    }
    P.fSetCsrf(dState.vSession.csrf || "");
    const vLanguage = dState.vSession.authenticated ? dState.vSession.user.language : (P.fStoredLanguage() || (navigator.language || "en-US"));
    const vMatch = P.cLanguages.find(function fFind(pCode) { return pCode.toLowerCase() === String(vLanguage).toLowerCase(); })
      || P.cLanguages.find(function fFind(pCode) { return pCode.slice(0, 2) === String(vLanguage).slice(0, 2).toLowerCase(); });
    await P.fLoadLanguage(vMatch || "en-US");
    P.fInitLanguageSelects();
    if (dState.vSession.authenticated) {
      fInitShell();
      fBuildNav();
    }
    P.fApplyTranslations(document);
    P.fOnLanguageChange(function fOnLanguage() {
      P.fApplyTranslations(document);
      const vTitle = P.fById("page-title");
      if (vTitle && vTitle.getAttribute("data-i18n")) {
        P.fSetTitle(vTitle.getAttribute("data-i18n"));
      }
    });
    window.addEventListener("popstate", fRoute);
    fRoute();
    if (dState.vSession.authenticated && dState.vSession.user.must_change_password) {
      fForcePasswordChange();
    }
    document.body.classList.add("ready");
  }

  window.LocalsiemApp = { fNavigate: fNavigate, fIsAdmin: fIsAdmin, fBase: fBase };
  fStart();
})();
