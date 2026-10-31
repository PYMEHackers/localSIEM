"use strict";

// Administrator views: accounts and access tokens (Users), SOC connection,
// channels (General and Telegram), settings, the audit log of the searches
// and the record of the sign-ins.
// The modules (with their sources, doctor and rules) are in modules.js.

window.LocalsiemViews = window.LocalsiemViews || {};

(function fAdminViews() {
  const P = window.Localsiem;
  const fEl = P.fEl;
  const fT = P.fT;

  function fHead(aKeys) {
    return fEl("thead", {}, fEl("tr", {}, aKeys.map(function fCell(pKey) { return fEl("th", { i18n: pKey }); })));
  }

  function fField(pKey, pInput, pHelpKey) {
    return fEl("label", { class: "field" }, [P.fText(pKey, "span", { class: "field-label" }), pInput, pHelpKey ? P.fText(pHelpKey, "span", { class: "field-help" }) : null]);
  }

  function fError() {
    return fEl("div", { class: "form-error", role: "alert", hidden: true });
  }

  function fShowError(pElement, pError) {
    pElement.hidden = !pError;
    pElement.textContent = pError ? P.fErrorText(pError) : "";
  }

  // ---------- users ----------

  // Sections of the Users tab, each one at its own URL:
  // /admin/dashboard/users/accounts/ and /admin/dashboard/users/tokens/.
  function fUserSections(pContext, pActive) {
    return fEl("nav", { class: "subtabs", "aria-label": fT("nav.users") }, ["accounts", "tokens"].map(function fLink(pName) {
      const vHref = pContext.fBase() + "users/" + pName + "/";
      const vLink = fEl("a", { class: "subtab" + (pName === pActive ? " active" : ""), href: vHref, i18n: "users.section_" + pName, "aria-current": pName === pActive ? "page" : null });
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

  window.LocalsiemViews.users = function fUsersView(pContainer, pContext) {
    const vSection = pContext.vParameter === "tokens" ? "tokens" : "accounts";
    pContainer.appendChild(fUserSections(pContext, vSection));
    if (vSection === "tokens") {
      return fTokensSection(pContainer);
    }
    const vBody = fEl("tbody");

    function fActions(dUser) {
      const aButtons = [];
      function fButton(pKey, pKind, pClick) {
        aButtons.push(fEl("button", { type: "button", class: "button button-small " + (pKind || "button-secondary"), onclick: pClick }, fT(pKey)));
      }
      fButton("users.reset_password", "", async function fReset() {
        if (!await P.fConfirm(fT("users.reset_password"), fT("users.reset_password_confirm", { user: dUser.username }), "users.reset_password")) {
          return;
        }
        try {
          const dAnswer = await P.fApi("POST", "/api/admin/users/" + dUser.id + "/password");
          P.fShowSecret(fT("users.new_password"), fT("users.new_password_help", { user: dUser.username }), dAnswer.password);
        } catch (vError) {
          P.fToastError(vError);
        }
      });
      fButton("users.reset_totp", "", async function fResetTotp() {
        if (!await P.fConfirm(fT("users.reset_totp"), fT("users.reset_totp_confirm", { user: dUser.username }), "users.reset_totp")) {
          return;
        }
        try {
          await P.fApi("POST", "/api/admin/users/" + dUser.id + "/totp-reset");
          P.fToast(fT("common.saved"), "success");
          fLoad();
        } catch (vError) {
          P.fToastError(vError);
        }
      });
      if (dUser.id !== pContext.vSession.user.id) {
        fButton(dUser.is_active ? "users.disable" : "users.enable", "", async function fToggle() {
          try {
            await P.fApi("PATCH", "/api/admin/users/" + dUser.id, { is_active: !dUser.is_active });
            fLoad();
          } catch (vError) {
            P.fToastError(vError);
          }
        });
        fButton(dUser.role === "admin" ? "users.make_analyst" : "users.make_admin", "", async function fRole() {
          try {
            await P.fApi("PATCH", "/api/admin/users/" + dUser.id, { role: dUser.role === "admin" ? "analyst" : "admin" });
            fLoad();
          } catch (vError) {
            P.fToastError(vError);
          }
        });
        fButton("users.delete", "button-danger", async function fDelete() {
          if (!await P.fConfirm(fT("users.delete"), fT("users.delete_confirm", { user: dUser.username }), "users.delete", true)) {
            return;
          }
          try {
            await P.fApi("DELETE", "/api/admin/users/" + dUser.id);
            fLoad();
          } catch (vError) {
            P.fToastError(vError);
          }
        });
      }
      return fEl("div", { class: "button-row" }, aButtons);
    }

    async function fLoad() {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/users");
        P.fClear(vBody);
        for (const dUser of dAnswer.users) {
          vBody.appendChild(fEl("tr", {}, [
            fEl("td", { class: "cell-break" }, [fEl("div", {}, dUser.username), dUser.full_name ? fEl("div", { class: "muted small" }, dUser.full_name) : null]),
            fEl("td", {}, fT("roles." + dUser.role)),
            fEl("td", {}, P.fStatusBadge("user_status", dUser.is_active ? "ok" : "rejected")),
            fEl("td", {}, dUser.totp_enabled_at ? fEl("span", { class: "mono" }, dUser.totp_enabled_at) : fEl("span", { class: "muted", i18n: pContext.vSession.mfa_enabled ? "users.totp_pending" : "users.totp_off" })),
            fEl("td", { class: "mono" }, dUser.last_login_at || "—"),
            fEl("td", {}, fActions(dUser))
          ]));
        }
        P.fLabelStackTables(vBody.closest("table").parentElement);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    function fCreate() {
      const vUsername = fEl("input", { class: "input", maxlength: 64, autocomplete: "off" });
      const vFullName = fEl("input", { class: "input", maxlength: 120 });
      const vRole = fEl("select", { class: "select" }, ["analyst", "admin"].map(function fOption(pRole) { return fEl("option", { value: pRole, i18n: "roles." + pRole }); }));
      const vLanguage = fEl("select", { class: "select" }, P.cLanguages.map(function fOption(pCode) { return fEl("option", { value: pCode }, pCode); }));
      vLanguage.value = P.fGetLanguage();
      const vErrorBox = fError();
      P.fModal(fT("users.create"), fEl("div", { class: "form-grid" }, [
        vErrorBox, fField("users.username", vUsername, "users.username_help"), fField("users.full_name", vFullName),
        fField("users.role", vRole), fField("account.language", vLanguage)
      ]), [
        { i18n: "common.cancel", onClick: function fCancel(pClose) { pClose(); } },
        { i18n: "users.create", kind: "primary", onClick: async function fSave(pClose) {
          try {
            const dAnswer = await P.fApi("POST", "/api/admin/users", { username: vUsername.value.trim(), full_name: vFullName.value, role: vRole.value, language: vLanguage.value });
            pClose();
            P.fShowSecret(fT("users.new_password"), fT("users.new_password_help", { user: vUsername.value.trim() }), dAnswer.password);
            fLoad();
          } catch (vError) {
            fShowError(vErrorBox, vError);
          }
        } }
      ]);
    }

    pContainer.appendChild(fEl("section", { class: "card" }, [
      fEl("div", { class: "card-header" }, [
        P.fText("users.title", "h2", { class: "card-title" }),
        fEl("button", { type: "button", class: "button button-primary", onclick: fCreate }, [P.fIcon("user-plus"), P.fText("users.create")])
      ]),
      P.fText("users.help", "p", { class: "muted small" }),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["users.col_user", "users.col_role", "users.col_status", "users.col_totp", "users.col_last_login", "users.col_actions"]), vBody
      ]))
    ]));
    fLoad();
    return null;
  };

  // ---------- access tokens (direct sign-in) ----------

  // An administrator creates a token for an analyst account and gives the
  // analyst the URL /auth/login/auto?token=..., which opens the dashboard
  // without password nor second factor. The token is shown only once.
  function fTokensSection(pContainer) {
    const vBody = fEl("tbody");
    const dBadges = { active: "ok", expired: "warning", revoked: "rejected", unusable: "error" };

    async function fLoad() {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/tokens");
        P.fClear(vBody);
        for (const dToken of dAnswer.tokens) {
          vBody.appendChild(fEl("tr", {}, [
            fEl("td", { class: "cell-break" }, [fEl("div", {}, dToken.username || "—"), dToken.label ? fEl("div", { class: "muted small" }, dToken.label) : null]),
            fEl("td", { class: "mono" }, "…" + dToken.token_hint),
            fEl("td", {}, P.fStatusBadge("token_state", dBadges[dToken.state] || "error")),
            fEl("td", { class: "mono small" }, [fEl("div", {}, dToken.created_at), fEl("div", { class: "muted" }, dToken.created_by)]),
            fEl("td", { class: "mono small" }, dToken.expires_at),
            fEl("td", { class: "mono small cell-break" }, dToken.last_used_at ? [fEl("div", {}, dToken.last_used_at), fEl("div", { class: "muted" }, dToken.last_used_ip || "")] : "—"),
            fEl("td", {}, dToken.state === "revoked" ? "" : fEl("button", { type: "button", class: "button button-small button-danger", onclick: async function fRevoke() {
              if (!await P.fConfirm(fT("tokens.revoke"), fT("tokens.revoke_confirm", { user: dToken.username }), "tokens.revoke", true)) {
                return;
              }
              try {
                await P.fApi("DELETE", "/api/admin/tokens/" + dToken.id);
                fLoad();
              } catch (vError) {
                P.fToastError(vError);
              }
            } }, fT("tokens.revoke")))
          ]));
        }
        if (!vBody.children.length) {
          vBody.appendChild(P.fEmptyRow(7, "tokens.none"));
        }
        P.fLabelStackTables(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    async function fCreate() {
      let ldAnalysts = [];
      try {
        ldAnalysts = (await P.fApi("GET", "/api/admin/users")).users.filter(function fAnalyst(dUser) { return dUser.role === "analyst" && dUser.is_active; });
      } catch (vError) {
        P.fToastError(vError);
        return;
      }
      if (!ldAnalysts.length) {
        P.fToast(fT("tokens.no_analysts"), "error");
        return;
      }
      const vUser = fEl("select", { class: "select" }, ldAnalysts.map(function fOption(dUser) { return fEl("option", { value: String(dUser.id) }, dUser.username + (dUser.full_name ? " · " + dUser.full_name : "")); }));
      const vLabel = fEl("input", { class: "input", maxlength: 80, autocomplete: "off" });
      const vDays = fEl("select", { class: "select" }, [7, 30, 90, 180, 365].map(function fOption(pDays) { return fEl("option", { value: String(pDays) }, fT("tokens.days_value", { days: pDays })); }));
      vDays.value = "90";
      const vErrorBox = fError();
      P.fModal(fT("tokens.create"), fEl("div", { class: "form-grid" }, [
        vErrorBox, fField("tokens.user", vUser, "tokens.user_help"), fField("tokens.label", vLabel, "tokens.label_help"), fField("tokens.days", vDays)
      ]), [
        { i18n: "common.cancel", onClick: function fCancel(pClose) { pClose(); } },
        { i18n: "tokens.create", kind: "primary", onClick: async function fSave(pClose) {
          try {
            const dAnswer = await P.fApi("POST", "/api/admin/tokens", { user_id: Number(vUser.value), label: vLabel.value, days: Number(vDays.value) });
            pClose();
            const vName = vUser.options[vUser.selectedIndex].textContent;
            P.fShowSecret(fT("tokens.created_title"), fT("tokens.created_help", { user: vName }), window.location.origin + dAnswer.path);
            fLoad();
          } catch (vError) {
            fShowError(vErrorBox, vError);
          }
        } }
      ]);
    }

    pContainer.appendChild(fEl("section", { class: "card" }, [
      fEl("div", { class: "card-header" }, [
        P.fText("tokens.title", "h2", { class: "card-title" }),
        fEl("button", { type: "button", class: "button button-primary", onclick: fCreate }, [P.fIcon("key"), P.fText("tokens.create")])
      ]),
      P.fText("tokens.help", "p", { class: "muted small" }),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["tokens.col_user", "tokens.col_token", "tokens.col_state", "tokens.col_created", "tokens.col_expires", "tokens.col_last_used", "tokens.col_actions"]), vBody
      ]))
    ]));
    fLoad();
    return null;
  }

  // ---------- SOC ----------

  window.LocalsiemViews.soc = function fSocView(pContainer) {
    const vUrl = fEl("input", { class: "input", type: "url", maxlength: 300 });
    const vToken = fEl("input", { class: "input", type: "password", autocomplete: "off", maxlength: 512 });
    const vCa = fEl("input", { class: "input", maxlength: 300, placeholder: "/opt/localsiem/config/soc-ca.pem" });
    const vEnabled = fEl("input", { type: "checkbox" });
    const vErrorBox = fError();
    const vStatus = fEl("div", { class: "stack" });
    const vAddress = fEl("code", { class: "secret-value" }, window.location.origin);
    const vForm = fEl("form", { class: "form-grid", novalidate: true }, [
      vErrorBox,
      fField("soc.url", vUrl),
      fField("soc.token", vToken, "soc.token_help"),
      fField("soc.ca_file", vCa, "soc.ca_help"),
      fEl("label", { class: "check" }, [vEnabled, P.fText("soc.enabled")]),
      fEl("div", { class: "button-row" }, [
        fEl("button", { type: "submit", class: "button button-primary", i18n: "common.save" }),
        fEl("button", { type: "button", class: "button button-secondary", onclick: async function fTest() {
          try {
            const dAnswer = await P.fApi("POST", "/api/admin/soc/test");
            if (dAnswer.ok) {
              P.fToast(fT("soc.test_ok"), "success");
            } else {
              P.fToast(fT("soc.test_failed", { error: (dAnswer.status ? "HTTP " + dAnswer.status + " " : "") + (dAnswer.error || "") }), "error");
            }
          } catch (vError) {
            P.fToastError(vError);
          }
        } }, [P.fIcon("plug"), P.fText("soc.test")])
      ])
    ]);
    vForm.addEventListener("submit", async function fSave(pEvent) {
      pEvent.preventDefault();
      fShowError(vErrorBox, null);
      const dBody = { url: vUrl.value.trim(), ca_file: vCa.value.trim(), enabled: vEnabled.checked };
      if (vToken.value.trim()) {
        dBody.token = vToken.value.trim();
      }
      try {
        await P.fApi("POST", "/api/admin/soc", dBody);
        vToken.value = "";
        P.fToast(fT("common.saved"), "success");
        fLoad();
      } catch (vError) {
        fShowError(vErrorBox, vError);
      }
    });

    async function fLoad() {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/soc");
        const dSettings = dAnswer.settings;
        if (document.activeElement !== vUrl) {
          vUrl.value = dSettings.url;
        }
        if (document.activeElement !== vCa) {
          vCa.value = dSettings.ca_file || "";
        }
        vEnabled.checked = dSettings.enabled;
        vToken.placeholder = dSettings.token_set ? dSettings.token : fT("soc.token_missing");
        P.fClear(vStatus);
        const dState = dAnswer.status || {};
        const dHeartbeat = dAnswer.heartbeat || {};
        const dQueue = (dAnswer.queue || {}).queue || {};
        vStatus.appendChild(P.fDetailsList([
          [fT("soc.state"), P.fStatusBadge("soc_state", dState.state || "not_configured")],
          [fT("soc.last_error"), dState.error || (dAnswer.queue || {}).last_error || ""],
          [fT("soc.last_success"), dState.last_success || ""],
          [fT("soc.heartbeat"), dHeartbeat.time ? (dHeartbeat.ok ? fT("soc.heartbeat_ok", { time: dHeartbeat.time }) : fT("soc.heartbeat_failed", { time: dHeartbeat.time, error: (dHeartbeat.status ? "HTTP " + dHeartbeat.status + " " : "") + (dHeartbeat.error || "") })) : "—"],
          [fT("soc.heartbeat_last_ok"), dHeartbeat.last_ok || ""],
          [fT("soc.pending"), P.fFormatNumber(dQueue.pending || 0)],
          [fT("soc.sent"), P.fFormatNumber(dQueue.sent || 0)],
          [fT("soc.rejected"), P.fFormatNumber(dQueue.rejected || 0)],
          [fT("soc.oldest"), (dAnswer.queue || {}).oldest_pending || ""]
        ]));
        vStatus.appendChild(fEl("div", { class: "button-row" }, [
          fEl("button", { type: "button", class: "button button-secondary", onclick: async function fRetry() {
            try {
              await P.fApi("POST", "/api/admin/soc/retry");
              P.fToast(fT("soc.retry_started"), "success");
              window.setTimeout(fLoad, 3000);
            } catch (vError) {
              P.fToastError(vError);
            }
          } }, [P.fIcon("send"), P.fText("soc.retry")]),
          dQueue.rejected ? fEl("button", { type: "button", class: "button button-secondary", onclick: async function fRequeue() {
            try {
              await P.fApi("POST", "/api/admin/soc/requeue");
              fLoad();
            } catch (vError) {
              P.fToastError(vError);
            }
          } }, P.fText("soc.requeue")) : null
        ]));
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    pContainer.appendChild(fEl("div", { class: "card-split" }, [
      fEl("section", { class: "card" }, [P.fText("soc.connection", "h2", { class: "section-title" }), P.fText("soc.optional_help", "p", { class: "muted small" }), vForm]),
      fEl("section", { class: "card" }, [P.fText("soc.status", "h2", { class: "section-title" }), vStatus])
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("soc.address", "h2", { class: "section-title" }),
      P.fText("soc.address_help", "p"),
      fEl("div", { class: "secret-box" }, [vAddress, fEl("button", { type: "button", class: "button button-secondary button-small", onclick: function fCopyAddress() { P.fCopy(window.location.origin); } }, [P.fIcon("copy"), P.fText("common.copy")])]),
      P.fText("soc.allow_help", "p", { class: "muted small" })
    ]));
    fLoad();
    return P.fPoll(fLoad, 15000);
  };

  // ---------- channels ----------

  // Sections of the Channels tab, each one at its own URL:
  // /admin/dashboard/channels/general/ (the default one) and
  // /admin/dashboard/channels/telegram/.
  const lChannelSections = ["general", "telegram"];

  function fChannelSections(pContext, pActive) {
    return fEl("nav", { class: "subtabs", "aria-label": fT("nav.channels") }, lChannelSections.map(function fLink(pName) {
      const vHref = pContext.fBase() + "channels/" + pName + "/";
      const vLink = fEl("a", { class: "subtab" + (pName === pActive ? " active" : ""), href: vHref, i18n: "channels.section_" + pName, "aria-current": pName === pActive ? "page" : null });
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

  // The state of one channel as the collector wrote it (channels.status):
  // unknown while the collector has not written it.
  function fChannelState(pStatus, pName) {
    const dChannel = (pStatus && pStatus[pName]) || {};
    return { dChannel: dChannel, vState: pStatus && dChannel.state ? dChannel.state : "unknown" };
  }

  function fChannelError(dChannel) {
    if (!dChannel.last_error) {
      return "";
    }
    return fEl("span", {}, [fEl("span", { class: "mono" }, dChannel.last_error_time || ""), " ", dChannel.last_error]);
  }

  window.LocalsiemViews.channels = function fChannelsView(pContainer, pContext) {
    const vSection = lChannelSections.includes(pContext.vParameter) ? pContext.vParameter : lChannelSections[0];
    pContainer.appendChild(fChannelSections(pContext, vSection));
    if (vSection === "telegram") {
      return fTelegramSection(pContainer, pContext);
    }
    return fChannelsGeneralSection(pContainer, pContext);
  };

  // General: all the channels on or off, the minimum severity of the alerts
  // they send, the language of the messages, and the state of each channel.
  function fChannelsGeneralSection(pContainer, pContext) {
    const vEnabled = fEl("input", { type: "checkbox" });
    const vSeverity = fEl("select", { class: "select" }, ["low", "medium", "high", "critical"].map(function fOption(pValue) { return fEl("option", { value: pValue, i18n: "severity." + pValue }); }));
    const vLanguage = fEl("select", { class: "select" }, P.cLanguages.map(function fOption(pCode) { return fEl("option", { value: pCode }, pCode); }));
    const vErrorBox = fError();
    const vBody = fEl("tbody");
    // The form is filled when the page opens and after saving; the refresh
    // every 15 seconds only updates the state of the channels.
    let vFilled = false;

    async function fLoad(pFill) {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/channels");
        const dSettings = dAnswer.settings;
        if (pFill || !vFilled) {
          vEnabled.checked = dSettings.enabled;
          vSeverity.value = dSettings.min_severity;
          vLanguage.value = dSettings.language;
          vFilled = true;
        }
        P.fClear(vBody);
        for (const vName of dAnswer.channels) {
          const { dChannel, vState } = fChannelState(dAnswer.status, vName);
          const vHref = pContext.fBase() + "channels/" + vName + "/";
          const vLink = fEl("a", { href: vHref, i18n: "channels.section_" + vName });
          vLink.addEventListener("click", function fOnClick(pEvent) {
            if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
              return;
            }
            pEvent.preventDefault();
            pContext.fNavigate(vHref);
          });
          vBody.appendChild(fEl("tr", {}, [
            fEl("td", {}, vLink),
            fEl("td", {}, P.fStatusBadge("channel_state", vState)),
            fEl("td", { class: "mono" }, P.fFormatNumber(dChannel.sent || 0)),
            fEl("td", { class: "mono" }, dChannel.last_sent || "—"),
            fEl("td", { class: "cell-break" }, fChannelError(dChannel) || "—")
          ]));
        }
        P.fApplyTranslations(vBody);
        P.fLabelStackTables(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    const vForm = fEl("form", { class: "form-grid", novalidate: true }, [
      vErrorBox,
      fEl("div", { class: "field" }, [
        fEl("label", { class: "check" }, [vEnabled, P.fText("channels.enabled")]),
        P.fText("channels.enabled_help", "span", { class: "field-help" })
      ]),
      fField("channels.min_severity", vSeverity, "channels.min_severity_help"),
      fField("channels.language", vLanguage, "channels.language_help"),
      fEl("div", { class: "button-row" }, fEl("button", { type: "submit", class: "button button-primary", i18n: "common.save" }))
    ]);
    vForm.addEventListener("submit", async function fSave(pEvent) {
      pEvent.preventDefault();
      fShowError(vErrorBox, null);
      try {
        await P.fApi("POST", "/api/admin/channels", { enabled: vEnabled.checked, min_severity: vSeverity.value, language: vLanguage.value });
        P.fToast(fT("common.saved"), "success");
        fLoad(true);
      } catch (vError) {
        fShowError(vErrorBox, vError);
      }
    });

    pContainer.appendChild(fEl("div", { class: "card-split" }, [
      fEl("section", { class: "card" }, [P.fText("channels.general_title", "h2", { class: "section-title" }), P.fText("channels.general_help", "p", { class: "muted small" }), vForm]),
      fEl("section", { class: "card" }, [
        P.fText("channels.list_title", "h2", { class: "section-title" }),
        P.fText("channels.list_help", "p", { class: "muted small" }),
        fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
          fHead(["channels.col_channel", "channels.col_state", "channels.col_sent", "channels.col_last_sent", "channels.col_last_error"]), vBody
        ]))
      ])
    ]));
    fLoad(true);
    return P.fPoll(function fRefresh() { return fLoad(false); }, 15000);
  }

  // Telegram: the token of the bot, the chat that receives the messages, a
  // test message and the state of the channel.
  function fTelegramSection(pContainer, pContext) {
    const vEnabled = fEl("input", { type: "checkbox" });
    const vToken = fEl("input", { class: "input", type: "password", autocomplete: "off", spellcheck: "false", maxlength: 130 });
    const vChatId = fEl("input", { class: "input", autocomplete: "off", spellcheck: "false", maxlength: 40, placeholder: "123456789" });
    const vErrorBox = fError();
    const vStatus = fEl("div", { class: "stack" });
    let vFilled = false;

    async function fSave(pQuiet) {
      fShowError(vErrorBox, null);
      const dBody = { enabled: vEnabled.checked, chat_id: vChatId.value.trim() };
      if (vToken.value.trim()) {
        dBody.token = vToken.value.trim();
      }
      try {
        await P.fApi("POST", "/api/admin/channels/telegram", dBody);
        vToken.value = "";
        if (!pQuiet) {
          P.fToast(fT("common.saved"), "success");
        }
        fLoad(true);
        return true;
      } catch (vError) {
        fShowError(vErrorBox, vError);
        return false;
      }
    }

    const vRemove = fEl("button", { type: "button", class: "button button-secondary", hidden: true, onclick: async function fRemoveToken() {
      if (!await P.fConfirm(fT("channels.telegram_remove_token"), fT("channels.telegram_remove_token_confirm"), "channels.telegram_remove_token", true)) {
        return;
      }
      try {
        await P.fApi("POST", "/api/admin/channels/telegram", { remove_token: true });
        P.fToast(fT("common.saved"), "success");
        fLoad(true);
      } catch (vError) {
        P.fToastError(vError);
      }
    } }, P.fText("channels.telegram_remove_token"));

    const vForm = fEl("form", { class: "form-grid", novalidate: true }, [
      vErrorBox,
      fEl("div", { class: "field" }, [
        fEl("label", { class: "check" }, [vEnabled, P.fText("channels.telegram_enabled")]),
        P.fText("channels.telegram_enabled_help", "span", { class: "field-help" })
      ]),
      fField("channels.telegram_token", vToken, "channels.telegram_token_help"),
      fField("channels.telegram_chat_id", vChatId, "channels.telegram_chat_id_help"),
      fEl("div", { class: "button-row" }, [
        fEl("button", { type: "submit", class: "button button-primary", i18n: "common.save" }),
        fEl("button", { type: "button", class: "button button-secondary", onclick: async function fTest() {
          // The test uses what is saved: the form is saved first.
          if (!await fSave(true)) {
            return;
          }
          try {
            const dAnswer = await P.fApi("POST", "/api/admin/channels/telegram/test");
            if (dAnswer.ok) {
              P.fToast(fT("channels.telegram_test_ok", { bot: dAnswer.bot && dAnswer.bot.username ? "@" + dAnswer.bot.username : "" }), "success");
            } else {
              P.fToast(fT("channels.telegram_test_failed", { error: (dAnswer.status ? "HTTP " + dAnswer.status + " " : "") + (dAnswer.error || "") }), "error");
            }
          } catch (vError) {
            P.fToastError(vError);
          }
        } }, [P.fIcon("send"), P.fText("channels.telegram_test")]),
        vRemove
      ])
    ]);
    vForm.addEventListener("submit", function fOnSubmit(pEvent) {
      pEvent.preventDefault();
      fSave(false);
    });

    async function fLoad(pFill) {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/channels");
        const dTelegram = dAnswer.settings.telegram;
        if (pFill || !vFilled) {
          vEnabled.checked = dTelegram.enabled;
          vChatId.value = dTelegram.chat_id || "";
          vFilled = true;
        }
        vToken.placeholder = dTelegram.token_set ? dTelegram.token : fT("channels.telegram_token_missing");
        vRemove.hidden = !dTelegram.token_set;
        const { dChannel, vState } = fChannelState(dAnswer.status, "telegram");
        P.fClear(vStatus);
        if (!dAnswer.settings.enabled) {
          const vHref = pContext.fBase() + "channels/general/";
          const vLink = fEl("a", { href: vHref, i18n: "channels.section_general" });
          vLink.addEventListener("click", function fOnClick(pEvent) {
            if (pEvent.ctrlKey || pEvent.metaKey || pEvent.shiftKey || pEvent.button !== 0) {
              return;
            }
            pEvent.preventDefault();
            pContext.fNavigate(vHref);
          });
          vStatus.appendChild(fEl("p", { class: "muted small" }, [P.fText("channels.all_off"), " ", vLink]));
        }
        vStatus.appendChild(P.fDetailsList([
          [fT("channels.col_state"), P.fStatusBadge("channel_state", vState)],
          [fT("channels.telegram_bot_id"), dTelegram.bot_id || ""],
          [fT("channels.col_sent"), P.fFormatNumber(dChannel.sent || 0)],
          [fT("channels.failed"), P.fFormatNumber(dChannel.failed || 0)],
          [fT("channels.dropped"), P.fFormatNumber(dChannel.dropped || 0)],
          [fT("channels.pending"), P.fFormatNumber(dChannel.pending || 0)],
          [fT("channels.col_last_sent"), dChannel.last_sent || ""],
          [fT("channels.col_last_error"), fChannelError(dChannel)]
        ]));
        P.fApplyTranslations(vStatus);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    pContainer.appendChild(fEl("div", { class: "card-split" }, [
      fEl("section", { class: "card" }, [P.fText("channels.telegram_title", "h2", { class: "section-title" }), vForm]),
      fEl("section", { class: "card" }, [P.fText("channels.telegram_status", "h2", { class: "section-title" }), vStatus])
    ]));
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("channels.telegram_setup", "h2", { class: "section-title" }),
      fEl("ol", { class: "steps-list" }, [1, 2, 3, 4, 5].map(function fStep(pNumber) { return P.fText("channels.telegram_step_" + pNumber, "li"); })),
      P.fText("channels.telegram_network", "p", { class: "muted small" })
    ]));
    fLoad(true);
    return P.fPoll(function fRefresh() { return fLoad(false); }, 15000);
  }

  // ---------- settings ----------

  window.LocalsiemViews.settings = function fSettingsView(pContainer, pContext) {
    const dInputs = {};
    const vErrorBox = fError();
    const vAllow = fEl("textarea", { class: "input", rows: 5, spellcheck: "false" });
    const vMfa = fEl("input", { type: "checkbox" });
    // Value of two-step verification when the page was loaded: changing it
    // asks for confirmation before saving.
    let vMfaLoaded = false;
    const vSeverity = fEl("select", { class: "select" }, ["low", "medium", "high", "critical"].map(function fOption(pValue) { return fEl("option", { value: pValue, i18n: "severity." + pValue }); }));
    const vUsage = fEl("p", { class: "muted small" });
    const lNumbers = [
      ["retention_days", "settings.retention_days", 1], ["alert_retention_days", "settings.alert_retention_days", 1],
      ["max_disk_mb", "settings.max_disk", 1], ["group_window_minutes", "settings.group_window", 1],
      ["group_buffer_seconds", "settings.group_buffer", 1], ["correlation_window_seconds", "settings.correlation_window", 1],
      ["search_timeout_seconds", "settings.search_timeout", 1], ["export_max_rows", "settings.export_max_rows", 1]
    ];
    for (const [vName] of lNumbers) {
      dInputs[vName] = fEl("input", { class: "input", type: "number", min: 0, step: 1, inputmode: "numeric" });
    }

    async function fLoad() {
      try {
        const dSettings = await P.fApi("GET", "/api/admin/settings");
        dInputs.retention_days.value = dSettings.retention_days;
        dInputs.alert_retention_days.value = dSettings.alert_retention_days;
        dInputs.max_disk_mb.value = Math.round((dSettings.max_disk_bytes || 0) / (1024 * 1024));
        dInputs.group_window_minutes.value = Math.round(dSettings.group_window_seconds / 60);
        dInputs.group_buffer_seconds.value = dSettings.group_buffer_seconds;
        dInputs.correlation_window_seconds.value = dSettings.correlation_window_seconds;
        dInputs.search_timeout_seconds.value = dSettings.search_timeout_seconds;
        dInputs.export_max_rows.value = dSettings.export_max_rows;
        vAllow.value = (dSettings.allow_from || []).join("\n");
        vMfaLoaded = Boolean(dSettings.mfa_enabled);
        vMfa.checked = vMfaLoaded;
        vSeverity.value = dSettings.below_threshold_severity;
        if (dSettings.database) {
          vUsage.textContent = fT("settings.usage", { used: P.fFormatBytes(dSettings.database.file), maximum: P.fFormatBytes(dSettings.database.maximum) });
        }
        P.fLabelStackTables(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    async function fSave(pEvent) {
      pEvent.preventDefault();
      fShowError(vErrorBox, null);
      if (vMfa.checked !== vMfaLoaded) {
        const vKey = vMfa.checked ? "settings.mfa_turn_on" : "settings.mfa_turn_off";
        if (!await P.fConfirm(fT(vKey), fT(vKey + "_confirm"), vKey, !vMfa.checked)) {
          vMfa.checked = vMfaLoaded;
          return;
        }
      }
      const dBody = {
        retention_days: Number(dInputs.retention_days.value),
        alert_retention_days: Number(dInputs.alert_retention_days.value),
        max_disk_bytes: Number(dInputs.max_disk_mb.value) * 1024 * 1024,
        group_window_seconds: Number(dInputs.group_window_minutes.value) * 60,
        group_buffer_seconds: Number(dInputs.group_buffer_seconds.value),
        correlation_window_seconds: Number(dInputs.correlation_window_seconds.value),
        search_timeout_seconds: Number(dInputs.search_timeout_seconds.value),
        export_max_rows: Number(dInputs.export_max_rows.value),
        allow_from: vAllow.value.split(/[\s,]+/).filter(Boolean),
        mfa_enabled: vMfa.checked,
        below_threshold_severity: vSeverity.value
      };
      try {
        const dAnswer = await P.fApi("POST", "/api/admin/settings", dBody);
        pContext.vSession.mfa_enabled = Boolean(dAnswer.settings.mfa_enabled);
        if (dAnswer.session_closed) {
          // Two-step verification turned on and this account has not set it
          // up yet: its session is over, and the sign-in shows the QR code.
          window.location.assign("/auth/login/?next=" + encodeURIComponent(window.location.pathname));
          return;
        }
        P.fToast(fT("common.saved"), "success");
        fLoad();
      } catch (vError) {
        if (vError.vCode === "allow_from_excludes_you" && vError.dData) {
          vErrorBox.hidden = false;
          vErrorBox.textContent = fT("errors.allow_from_excludes_you", { ip: vError.dData.ip || "" });
        } else {
          fShowError(vErrorBox, vError);
        }
      }
    }

    const vForm = fEl("form", { class: "stack", novalidate: true }, [
      vErrorBox,
      fEl("div", { class: "card-split" }, [
        fEl("section", { class: "card" }, [
          P.fText("settings.retention", "h2", { class: "section-title" }),
          fEl("div", { class: "form-grid" }, [
            fField("settings.retention_days", dInputs.retention_days),
            fField("settings.alert_retention_days", dInputs.alert_retention_days),
            fField("settings.max_disk", dInputs.max_disk_mb, "settings.max_disk_help"),
            vUsage
          ])
        ]),
        fEl("section", { class: "card" }, [
          P.fText("settings.access", "h2", { class: "section-title" }),
          fEl("div", { class: "form-grid" }, [
            fField("settings.allow_from", vAllow, "settings.allow_from_help"),
            fEl("div", { class: "field" }, [
              fEl("label", { class: "check" }, [vMfa, P.fText("settings.mfa_enabled")]),
              P.fText("settings.mfa_enabled_help", "span", { class: "field-help" })
            ]),
            fField("settings.search_timeout", dInputs.search_timeout_seconds),
            fField("settings.export_max_rows", dInputs.export_max_rows)
          ])
        ])
      ]),
      fEl("section", { class: "card" }, [
        P.fText("settings.alerts", "h2", { class: "section-title" }),
        fEl("div", { class: "form-grid form-grid-2" }, [
          fField("settings.group_window", dInputs.group_window_minutes, "settings.group_window_help"),
          fField("settings.group_buffer", dInputs.group_buffer_seconds, "settings.group_buffer_help"),
          fField("settings.correlation_window", dInputs.correlation_window_seconds, "settings.correlation_window_help"),
          fField("settings.below_threshold", vSeverity, "settings.below_threshold_help")
        ]),
        P.fText("settings.rules_moved", "p", { class: "muted small settings-subtitle" })
      ]),
      fEl("div", { class: "button-row" }, fEl("button", { type: "submit", class: "button button-primary", i18n: "common.save" }))
    ]);
    vForm.addEventListener("submit", fSave);
    pContainer.appendChild(vForm);
    fLoad();
    return null;
  };

  // ---------- audit ----------

  window.LocalsiemViews.audit = function fAuditView(pContainer) {
    const vBody = fEl("tbody");
    const vMore = fEl("button", { type: "button", class: "button button-secondary", hidden: true }, P.fText("search.more"));
    let vNext = null;

    async function fLoad(pMore) {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/audit" + P.fQuery({ before: pMore ? vNext : "" }));
        if (!pMore) {
          P.fClear(vBody);
        }
        for (const dEntry of dAnswer.entries) {
          vBody.appendChild(fEl("tr", {}, [
            fEl("td", { class: "mono" }, dEntry.time),
            fEl("td", { class: "cell-break" }, dEntry.username),
            fEl("td", { class: "mono cell-break" }, dEntry.ip),
            fEl("td", {}, P.fTOr("audit.kind_" + dEntry.kind, dEntry.kind)),
            fEl("td", { class: "cell-break mono small" }, dEntry.query || "—"),
            fEl("td", { class: "mono small" }, dEntry.range_from + " → " + dEntry.range_to),
            fEl("td", { class: "mono" }, dEntry.results === null ? "—" : P.fFormatNumber(dEntry.results)),
            fEl("td", { class: "mono" }, dEntry.took_ms === null ? "—" : dEntry.took_ms + " ms")
          ]));
        }
        if (!vBody.children.length) {
          vBody.appendChild(P.fEmptyRow(8, "audit.none"));
        }
        vNext = dAnswer.next;
        vMore.hidden = !vNext;
        P.fLabelStackTables(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    vMore.addEventListener("click", function fOnMore() { fLoad(true); });
    pContainer.appendChild(fEl("section", { class: "card" }, [
      P.fText("audit.help", "p", { class: "muted small" }),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["audit.col_time", "audit.col_user", "audit.col_ip", "audit.col_kind", "audit.col_query", "audit.col_range", "audit.col_results", "audit.col_took"]), vBody
      ])),
      fEl("div", { class: "pager" }, vMore)
    ]));
    fLoad(false);
    return null;
  };

  // ---------- record of the sign-ins ----------

  window.LocalsiemViews.logins = function fLoginsView(pContainer) {
    const vBody = fEl("tbody");
    const vMore = fEl("button", { type: "button", class: "button button-secondary", hidden: true }, P.fText("search.more"));
    const vResult = fEl("select", { class: "select select-compact", "aria-label": fT("logins.filter") }, ["", "ok", "failed"].map(function fOption(pValue) {
      return fEl("option", { value: pValue, i18n: "logins.filter_" + (pValue || "all") });
    }));
    let vNext = null;

    async function fLoad(pMore) {
      try {
        const dAnswer = await P.fApi("GET", "/api/admin/logins" + P.fQuery({ before: pMore ? vNext : "", result: vResult.value }));
        if (!pMore) {
          P.fClear(vBody);
        }
        for (const dEntry of dAnswer.entries) {
          vBody.appendChild(fEl("tr", {}, [
            fEl("td", { class: "mono" }, dEntry.time),
            fEl("td", { class: "cell-break" }, dEntry.username || "—"),
            fEl("td", {}, P.fTOr("logins.method_" + dEntry.method, dEntry.method)),
            fEl("td", {}, P.fStatusBadge("login_result", dEntry.result === "ok" ? "ok" : "rejected")),
            fEl("td", { class: "cell-break" }, dEntry.reason ? P.fTOr("logins.reason_" + dEntry.reason, dEntry.reason) : "—"),
            fEl("td", { class: "mono cell-break" }, dEntry.ip),
            fEl("td", { class: "cell-break small muted" }, dEntry.user_agent || "—")
          ]));
        }
        if (!vBody.children.length) {
          vBody.appendChild(P.fEmptyRow(7, "logins.none"));
        }
        vNext = dAnswer.next;
        vMore.hidden = !vNext;
        P.fLabelStackTables(pContainer);
      } catch (vError) {
        P.fToastError(vError);
      }
    }

    vMore.addEventListener("click", function fOnMore() { fLoad(true); });
    vResult.addEventListener("change", function fOnFilter() { fLoad(false); });
    pContainer.appendChild(fEl("section", { class: "card" }, [
      fEl("div", { class: "card-header" }, [P.fText("logins.help", "p", { class: "muted small" }), vResult]),
      fEl("div", { class: "table-wrap" }, fEl("table", { class: "table table-stack" }, [
        fHead(["logins.col_time", "logins.col_user", "logins.col_method", "logins.col_result", "logins.col_reason", "logins.col_ip", "logins.col_agent"]), vBody
      ])),
      fEl("div", { class: "pager" }, vMore)
    ]));
    fLoad(false);
    return null;
  };
})();
