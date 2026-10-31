"""FastAPI application of localsiem-web.

Pages (one HTML shell, each tab at its own URL):

  /auth/login/  /auth/register/  /auth/recover/
  /auth/login/auto?token=TOKEN       direct sign-in with an access token (or
                                     ?TOKEN; optional next=<path>)
  /user/dashboard/            -> /user/dashboard/overview/
  /user/dashboard/overview/ search/ live/ alerts/ modules/ account/
  /admin/dashboard/           -> /admin/dashboard/overview/
  /admin/dashboard/overview/ search/ live/ alerts/ modules/ soc/ settings/
                   audit/ logins/ account/
  /admin/dashboard/users/     -> /admin/dashboard/users/accounts/
  /admin/dashboard/users/accounts/ tokens/   accounts; access tokens
  /admin/dashboard/channels/  -> /admin/dashboard/channels/general/
  /admin/dashboard/channels/general/ telegram/   settings of all the
                                     channels; the Telegram channel
  /admin/dashboard/modules/   -> /admin/dashboard/modules/installed/
  /admin/dashboard/modules/installed/ installable/   installed modules;
                                     modules of the repository not installed
  /admin/dashboard/modules/installed/<name>/   one module: state, settings,
                                     sources, doctor and rules (the older
                                     /admin/dashboard/modules/<name>/ goes
                                     there)
  /admin/dashboards/...       -> /admin/dashboard/...

Two dashboards: administrators always work in /admin/dashboard/ (a
/user/dashboard/ URL takes them to the same tab there) and the other users
in /user/dashboard/, without the configuration tabs. A dashboard URL without
a session goes to /auth/login/?next=<URL with its parameters>, and back
there after signing in. The whole API lives under /api/ and is documented in
/api/doc/.
"""

import asyncio
import json

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.core.config import cVersion
from backend.web.auth import cSessionCookie, cTokenAttempt, fIsAllowed, fIsSameOrigin
from backend.web.context import WebContext, cFrontendPath

lUserTabs = ["overview", "search", "live", "alerts", "modules", "account"]
lAdminTabs = ["overview", "search", "live", "alerts", "modules", "users", "soc", "channels", "settings", "audit", "logins", "account"]
# Sections of the Users tab; the first one opens by default.
lUserSections = ["accounts", "tokens"]
# Sections of the Channels tab; the first one opens by default.
lChannelSections = ["general", "telegram"]
# Sections of the Modules tab of administrators; the first one opens by
# default.
lModuleSections = ["installed", "installable"]
cContentSecurityPolicy = (
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
  "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
# Swagger UI (/api/doc/) loads its script and styles from a CDN and starts
# with an inline script: it gets a policy of its own.
cDocumentationPolicy = (
  "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
  "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)
lLanguages = ["en-GB", "en-US", "es-AR", "es-ES"]


class GuardMiddleware:
  # Allowed IPs for the whole web (HTTP and WebSocket) and security headers.

  def __init__(self, pApp, pContext: WebContext):
    self.vApp = pApp
    self.vContext = pContext

  async def __call__(self, pScope, pReceive, pSend):
    if pScope["type"] not in ("http", "websocket"):
      return await self.vApp(pScope, pReceive, pSend)
    self.vContext.mRefreshSettings()
    vClient = pScope.get("client") or ("", 0)
    if not fIsAllowed(vClient[0], self.vContext.lAllowed):
      if pScope["type"] == "websocket":
        await pSend({"type": "websocket.close", "code": 4403})
        return
      vBody = b"Forbidden"
      await pSend({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(vBody)).encode())]})
      await pSend({"type": "http.response.body", "body": vBody})
      return
    if pScope["type"] == "websocket":
      return await self.vApp(pScope, pReceive, pSend)

    async def fSend(pMessage):
      if pMessage["type"] == "http.response.start":
        lHeaders = list(pMessage.get("headers", []))
        vPolicy = cDocumentationPolicy if pScope.get("path", "").startswith("/api/doc") else cContentSecurityPolicy
        lHeaders += [
          (b"content-security-policy", vPolicy.encode()),
          (b"x-content-type-options", b"nosniff"),
          (b"x-frame-options", b"DENY"),
          (b"referrer-policy", b"no-referrer"),
          (b"strict-transport-security", b"max-age=31536000"),
          (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
          (b"x-robots-tag", b"noindex, nofollow")
        ]
        vPath = pScope.get("path", "")
        if vPath.startswith("/api/"):
          lHeaders.append((b"cache-control", b"no-store"))
        elif vPath.startswith("/assets/") or vPath.startswith("/locales/"):
          lHeaders.append((b"cache-control", b"public, max-age=31536000, immutable"))
        pMessage["headers"] = lHeaders
      await pSend(pMessage)
    return await self.vApp(pScope, pReceive, fSend)


def fCreateApp() -> FastAPI:
  vContext = WebContext()
  vApp = FastAPI(
    title="localSIEM",
    version=cVersion,
    docs_url="/api/doc/",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    swagger_ui_oauth2_redirect_url="/api/doc/oauth2-redirect",
    description=(
      "Lightweight SIEM for a Linux server. Everything under /api/ needs a signed-in session (cookie localsiem_session; "
      "writes also need the X-CSRF-Token header and the page's own origin). "
      "Times use the native format 2026/10/29@13:59:59.723 (UTC). "
      "WebSocket /api/ws: the live view, with the session cookie. The server answers {\"status\": \"ready\"} and then sends "
      "{\"type\": \"events\", \"events\": [...]} frames; send {\"query\": \"...\"} to filter and {\"paused\": true|false}. "
      "Close code 4401 means missing or expired authentication, 4403 an address that is not allowed. "
      "GET /api/ws describes this protocol (Swagger cannot open WebSocket sessions)."
    )
  )
  vApp.state.vContext = vContext

  @vApp.exception_handler(HTTPException)
  async def fHttpError(pRequest: Request, pError: HTTPException):
    vDetail = pError.detail
    dBody = {"error": vDetail, "detail": vDetail} if isinstance(vDetail, str) else (vDetail if isinstance(vDetail, dict) else {"error": "error", "detail": vDetail})
    return JSONResponse(dBody, status_code=pError.status_code, headers=getattr(pError, "headers", None))

  @vApp.exception_handler(RequestValidationError)
  async def fValidationError(pRequest: Request, pError: RequestValidationError):
    return JSONResponse({"error": "invalid_request", "detail": json.loads(json.dumps(pError.errors(), default=str))[:5]}, status_code=422)

  vApp.mount("/assets", StaticFiles(directory=cFrontendPath / "assets"), name="assets")
  vApp.mount("/locales", StaticFiles(directory=cFrontendPath / "locales"), name="locales")

  # Pages

  def fPage(pRequest: Request) -> HTMLResponse:
    return HTMLResponse(vContext.vIndex, headers={"cache-control": "no-store"})

  def fHome(pSession: dict) -> str:
    return "/admin/dashboard/overview/" if pSession["role"] == "admin" else "/user/dashboard/overview/"

  def fQueryPart(pRequest: Request) -> str:
    return ("?" + pRequest.url.query) if pRequest.url.query else ""

  def fLoginRedirect(pRequest: Request) -> RedirectResponse:
    vTarget = pRequest.url.path + (("?" + pRequest.url.query) if pRequest.url.query else "")
    from urllib.parse import quote
    return RedirectResponse("/auth/login/?next=" + quote(vTarget, safe=""), status_code=302)

  @vApp.get("/", include_in_schema=False)
  async def fRoot(pRequest: Request):
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return RedirectResponse("/auth/login/", status_code=302)
    return RedirectResponse(fHome(dSession), status_code=302)

  @vApp.get("/favicon.ico", include_in_schema=False)
  async def fFavicon():
    return RedirectResponse("/assets/img/logo.svg?v=" + vContext.dVersions.get("assets/img/logo.svg", ""), status_code=302)

  for vPath in ("/auth/login/", "/auth/register/", "/auth/recover/"):
    vApp.add_api_route(vPath, fPage, methods=["GET"], include_in_schema=False)

  @vApp.get("/auth/{pName}", include_in_schema=False)
  async def fAuthNoSlash(pName: str, pRequest: Request):
    if pName in ("login", "register", "recover"):
      return RedirectResponse(f"/auth/{pName}/" + (("?" + pRequest.url.query) if pRequest.url.query else ""), status_code=301)
    raise HTTPException(status_code=404, detail="not_found")

  @vApp.get("/user/dashboard", include_in_schema=False)
  @vApp.get("/user/dashboard/", include_in_schema=False)
  async def fUserDashboard(pRequest: Request):
    return RedirectResponse("/user/dashboard/overview/" + fQueryPart(pRequest), status_code=302)

  @vApp.get("/admin/dashboard", include_in_schema=False)
  @vApp.get("/admin/dashboard/", include_in_schema=False)
  async def fAdminDashboard(pRequest: Request):
    return RedirectResponse("/admin/dashboard/overview/" + fQueryPart(pRequest), status_code=302)

  @vApp.get("/user/dashboard/{pTab}", include_in_schema=False)
  @vApp.get("/user/dashboard/{pTab}/", include_in_schema=False)
  async def fUserTab(pTab: str, pRequest: Request):
    if pTab not in lUserTabs:
      raise HTTPException(status_code=404, detail="not_found")
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] == "admin":
      # Administrators work in their own dashboard, with the same tab.
      return RedirectResponse("/admin/dashboard/" + pTab + "/" + fQueryPart(pRequest), status_code=302)
    return fPage(pRequest)

  @vApp.get("/admin/dashboard/{pTab}", include_in_schema=False)
  @vApp.get("/admin/dashboard/{pTab}/", include_in_schema=False)
  async def fAdminTab(pTab: str, pRequest: Request):
    if pTab not in lAdminTabs:
      raise HTTPException(status_code=404, detail="not_found")
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] != "admin":
      vTarget = "/user/dashboard/" + pTab + "/" if pTab in lUserTabs else "/user/dashboard/overview/"
      return RedirectResponse(vTarget + fQueryPart(pRequest), status_code=302)
    if pTab == "users":
      return RedirectResponse("/admin/dashboard/users/" + lUserSections[0] + "/" + fQueryPart(pRequest), status_code=302)
    if pTab == "modules":
      return RedirectResponse("/admin/dashboard/modules/" + lModuleSections[0] + "/" + fQueryPart(pRequest), status_code=302)
    if pTab == "channels":
      return RedirectResponse("/admin/dashboard/channels/" + lChannelSections[0] + "/" + fQueryPart(pRequest), status_code=302)
    return fPage(pRequest)

  @vApp.get("/admin/dashboard/users/{pSection}", include_in_schema=False)
  @vApp.get("/admin/dashboard/users/{pSection}/", include_in_schema=False)
  async def fAdminUsersSection(pSection: str, pRequest: Request):
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] != "admin":
      return RedirectResponse("/user/dashboard/overview/", status_code=302)
    if pSection not in lUserSections:
      raise HTTPException(status_code=404, detail="not_found")
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    return fPage(pRequest)

  @vApp.get("/admin/dashboard/channels/{pSection}", include_in_schema=False)
  @vApp.get("/admin/dashboard/channels/{pSection}/", include_in_schema=False)
  async def fAdminChannelsSection(pSection: str, pRequest: Request):
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] != "admin":
      return RedirectResponse("/user/dashboard/overview/", status_code=302)
    if pSection not in lChannelSections:
      raise HTTPException(status_code=404, detail="not_found")
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    return fPage(pRequest)

  @vApp.get("/admin/dashboards/{pPath:path}", include_in_schema=False)
  async def fAdminDashboards(pPath: str, pRequest: Request):
    return RedirectResponse("/admin/dashboard/" + pPath + fQueryPart(pRequest), status_code=301)

  @vApp.get("/admin/dashboard/modules/{pSection}", include_in_schema=False)
  @vApp.get("/admin/dashboard/modules/{pSection}/", include_in_schema=False)
  async def fAdminModulesSection(pSection: str, pRequest: Request):
    # The session is checked first: without one nobody learns which modules
    # are installed.
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] != "admin":
      return RedirectResponse("/user/dashboard/modules/" + fQueryPart(pRequest), status_code=302)
    if pSection not in lModuleSections:
      # The older URL of the page of a module.
      if vContext.mManifest(pSection) is None:
        raise HTTPException(status_code=404, detail="not_found")
      return RedirectResponse("/admin/dashboard/modules/" + lModuleSections[0] + "/" + pSection + "/" + fQueryPart(pRequest), status_code=301)
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    return fPage(pRequest)

  @vApp.get("/admin/dashboard/modules/installed/{pName}", include_in_schema=False)
  @vApp.get("/admin/dashboard/modules/installed/{pName}/", include_in_schema=False)
  async def fAdminModule(pName: str, pRequest: Request):
    # The session is checked first: without one nobody learns which modules
    # are installed.
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return fLoginRedirect(pRequest)
    if dSession["role"] != "admin":
      return RedirectResponse("/user/dashboard/modules/" + fQueryPart(pRequest), status_code=302)
    if vContext.mManifest(pName) is None:
      raise HTTPException(status_code=404, detail="not_found")
    if not pRequest.url.path.endswith("/"):
      return RedirectResponse(pRequest.url.path + "/" + fQueryPart(pRequest), status_code=301)
    return fPage(pRequest)

  # Authentication

  def fSessionCookie(pResponse: Response, pToken: str) -> None:
    pResponse.set_cookie(
      cSessionCookie, pToken, max_age=int(float(vContext.dSettings.get("session_hours", 8)) * 3600),
      httponly=True, secure=True, samesite="lax", path="/"
    )

  def fPublicUser(pSession: dict) -> dict:
    return {
      "id": pSession["id"], "username": pSession["username"], "full_name": pSession["full_name"], "role": pSession["role"],
      "language": pSession["language"], "totp_enabled": bool(pSession["totp_enabled_at"]),
      "must_change_password": bool(pSession["must_change_password"])
    }

  @vApp.get("/api/auth/session", tags=["auth"], summary="Current session")
  async def fGetSession(pRequest: Request):
    """authenticated, the user (username, role, language...), the CSRF token for writes and whether two-step verification is on."""
    dSession = await asyncio.to_thread(vContext.mSession, pRequest)
    if dSession is None:
      return {"authenticated": False, "mfa_enabled": bool(vContext.dSettings.get("mfa_enabled", False)), "version": cVersion}
    return {
      "authenticated": True, "user": fPublicUser(dSession), "csrf": dSession["csrf_token"],
      "mfa_enabled": bool(vContext.dSettings.get("mfa_enabled", False)), "version": cVersion,
      "host": vContext.dSettings.get("host", "")
    }

  @vApp.post("/api/auth/login", tags=["auth"], summary="Sign in, first step: username and password")
  async def fLogin(pRequest: Request, pUsername: str = Body(alias="username", max_length=128), pPassword: str = Body(alias="password", max_length=1024)):
    """Answers step=totp (send the code to /api/auth/totp), step=enroll (set up the authenticator app with secret/qr, then send its first code) or step=done (two-step verification off). Locked for a while after several failures (429)."""
    if pRequest.headers.get("origin") and not fIsSameOrigin(pRequest):
      raise HTTPException(status_code=403, detail="csrf_failed")
    vIp = vContext.mClientIp(pRequest)
    vAgent = pRequest.headers.get("user-agent", "")
    vAccounts = vContext.vAccounts
    if await asyncio.to_thread(vAccounts.mIsBlocked, pUsername, vIp):
      await asyncio.to_thread(vAccounts.mRecordLogin, pUsername, "password", "failed", "login_blocked", vIp, vAgent)
      raise HTTPException(status_code=429, detail="login_blocked")
    dUser = await asyncio.to_thread(vAccounts.mCheckPassword, pUsername, pPassword)
    await asyncio.to_thread(vAccounts.mRecordAttempt, pUsername, vIp, dUser is not None)
    if dUser is None:
      await asyncio.to_thread(vAccounts.mRecordLogin, pUsername, "password", "failed", "invalid_credentials", vIp, vAgent)
      raise HTTPException(status_code=401, detail="invalid_credentials")
    if not vContext.dSettings.get("mfa_enabled", False):
      vToken, vCsrf = await asyncio.to_thread(vAccounts.mCreateSession, dUser["id"], vIp, vAgent)
      await asyncio.to_thread(vAccounts.mRecordLogin, dUser["username"], "password", "ok", "", vIp, vAgent)
      vResponse = JSONResponse({"step": "done", "csrf": vCsrf})
      fSessionCookie(vResponse, vToken)
      return vResponse
    if dUser["totp_enabled_at"]:
      return {"step": "totp", "challenge": vAccounts.mChallenge(dUser, "totp")}
    dSetup = await asyncio.to_thread(vAccounts.mStartEnrollment, dUser)
    return {"step": "enroll", "challenge": vAccounts.mChallenge(dUser, "enroll"), **dSetup}

  @vApp.post("/api/auth/totp", tags=["auth"], summary="Sign in, second step: the code of the authenticator app")
  async def fLoginTotp(pRequest: Request, pChallenge: str = Body(alias="challenge", max_length=4096), pCode: str = Body(alias="code", max_length=20)):
    """Opens the session (cookie) and answers its CSRF token. A code is only valid once."""
    if pRequest.headers.get("origin") and not fIsSameOrigin(pRequest):
      raise HTTPException(status_code=403, detail="csrf_failed")
    vIp = vContext.mClientIp(pRequest)
    vAgent = pRequest.headers.get("user-agent", "")
    vAccounts = vContext.vAccounts
    vRead = await asyncio.to_thread(vAccounts.mReadChallenge, pChallenge)
    if vRead is None:
      await asyncio.to_thread(vAccounts.mRecordLogin, "", "password_totp", "failed", "challenge_expired", vIp, vAgent)
      raise HTTPException(status_code=401, detail="challenge_expired")
    dUser, vStage = vRead
    if await asyncio.to_thread(vAccounts.mIsBlocked, dUser["username"], vIp):
      await asyncio.to_thread(vAccounts.mRecordLogin, dUser["username"], "password_totp", "failed", "login_blocked", vIp, vAgent)
      raise HTTPException(status_code=429, detail="login_blocked")
    vValid = await asyncio.to_thread(vAccounts.mVerifyTotp, dUser, vStage, pCode)
    await asyncio.to_thread(vAccounts.mRecordAttempt, dUser["username"], vIp, vValid)
    if not vValid:
      await asyncio.to_thread(vAccounts.mRecordLogin, dUser["username"], "password_totp", "failed", "invalid_code", vIp, vAgent)
      raise HTTPException(status_code=401, detail="invalid_code")
    vToken, vCsrf = await asyncio.to_thread(vAccounts.mCreateSession, dUser["id"], vIp, vAgent)
    await asyncio.to_thread(vAccounts.mRecordLogin, dUser["username"], "password_totp", "ok", "", vIp, vAgent)
    vResponse = JSONResponse({"step": "done", "csrf": vCsrf})
    fSessionCookie(vResponse, vToken)
    return vResponse

  def fSafeNext(pValue: str) -> str:
    # Only a path of this site: never another origin, never the sign-in pages.
    vValue = str(pValue or "")
    if not vValue.startswith("/") or vValue.startswith("//") or vValue.startswith("/\\") or vValue.startswith("/auth/"):
      return ""
    return vValue

  @vApp.get("/auth/login/auto", include_in_schema=False)
  @vApp.get("/auth/login/auto/", include_in_schema=False)
  async def fLoginWithToken(pRequest: Request):
    # Direct sign-in of an analyst: /auth/login/auto?token=TOKEN (or ?TOKEN),
    # with an access token created in Users › Access tokens. It opens the
    # session and goes to the overview (or to next=<path of this site>);
    # without a valid token, to /auth/login/?error=<reason>.
    vToken = pRequest.query_params.get("token", "")
    if not vToken and pRequest.url.query and "=" not in pRequest.url.query:
      vToken = pRequest.url.query
    vIp = vContext.mClientIp(pRequest)
    vAgent = pRequest.headers.get("user-agent", "")
    vAccounts = vContext.vAccounts
    dNoStore = {"cache-control": "no-store"}
    if await asyncio.to_thread(vAccounts.mIsBlocked, cTokenAttempt, vIp):
      await asyncio.to_thread(vAccounts.mRecordLogin, "", "token", "failed", "login_blocked", vIp, vAgent)
      return RedirectResponse("/auth/login/?error=login_blocked", status_code=302, headers=dNoStore)
    dUser, dToken, vReason = await asyncio.to_thread(vAccounts.mCheckAccessToken, vToken)
    await asyncio.to_thread(vAccounts.mRecordAttempt, cTokenAttempt, vIp, dUser is not None)
    if dUser is None:
      vUsername = ""
      if dToken is not None:
        dOwner = await asyncio.to_thread(vAccounts.mGetUser, dToken["user_id"])
        vUsername = dOwner["username"] if dOwner else ""
      await asyncio.to_thread(vAccounts.mRecordLogin, vUsername, "token", "failed", vReason, vIp, vAgent, dToken["id"] if dToken else None)
      return RedirectResponse("/auth/login/?error=" + vReason, status_code=302, headers=dNoStore)
    vSession, _ = await asyncio.to_thread(vAccounts.mCreateSession, dUser["id"], vIp, vAgent, "token")
    await asyncio.to_thread(vAccounts.mMarkAccessTokenUsed, dToken["id"], vIp)
    await asyncio.to_thread(vAccounts.mRecordLogin, dUser["username"], "token", "ok", "", vIp, vAgent, dToken["id"])
    vResponse = RedirectResponse(fSafeNext(pRequest.query_params.get("next", "")) or "/user/dashboard/overview/", status_code=302, headers=dNoStore)
    fSessionCookie(vResponse, vSession)
    return vResponse

  @vApp.post("/api/auth/logout", tags=["auth"], summary="Sign out")
  async def fLogout(pRequest: Request):
    await asyncio.to_thread(vContext.vAccounts.mDeleteSession, pRequest.cookies.get(cSessionCookie, ""))
    vResponse = JSONResponse({"ok": True})
    vResponse.delete_cookie(cSessionCookie, path="/", secure=True, httponly=True, samesite="lax")
    return vResponse

  # Account

  @vApp.get("/api/account", tags=["account"], summary="The signed-in account")
  async def fGetAccount(pRequest: Request):
    dSession = await asyncio.to_thread(vContext.mRequireSession, pRequest)
    return fPublicUser(dSession)

  @vApp.patch("/api/account", tags=["account"], summary="Change the language or the name of the account")
  async def fPatchAccount(pRequest: Request, pChanges: dict = Body(...)):
    dSession = await asyncio.to_thread(vContext.mRequireWrite, pRequest)
    dAllowed = {}
    if "language" in pChanges:
      if pChanges["language"] not in lLanguages:
        raise HTTPException(status_code=422, detail="invalid_language")
      dAllowed["language"] = pChanges["language"]
    if "full_name" in pChanges:
      dAllowed["full_name"] = str(pChanges["full_name"] or "")[:120]
    await asyncio.to_thread(vContext.vAccounts.mUpdateUser, dSession["id"], dAllowed)
    return {"ok": True}

  @vApp.post("/api/account/password", tags=["account"], summary="Change the password of the account")
  async def fChangePassword(pRequest: Request, pCurrent: str = Body(alias="current", max_length=1024), pNew: str = Body(alias="new", max_length=1024)):
    """Needs the current password. Other sessions of the account are closed."""
    dSession = await asyncio.to_thread(vContext.mRequireWrite, pRequest)
    dUser = await asyncio.to_thread(vContext.vAccounts.mCheckPassword, dSession["username"], pCurrent)
    if dUser is None:
      raise HTTPException(status_code=401, detail="invalid_credentials")
    try:
      await asyncio.to_thread(vContext.vAccounts.mSetPassword, dSession["id"], pNew, False, dSession["session_id"])
    except ValueError as vError:
      raise HTTPException(status_code=422, detail=str(vError)) from None
    return {"ok": True}

  @vApp.post("/api/account/totp/reset", tags=["account"], summary="Set up the authenticator app again")
  async def fResetOwnTotp(pRequest: Request, pPassword: str = Body(alias="password", embed=True, max_length=1024)):
    """Needs the password. The session closes and the next sign-in shows a new QR code."""
    dSession = await asyncio.to_thread(vContext.mRequireWrite, pRequest)
    dUser = await asyncio.to_thread(vContext.vAccounts.mCheckPassword, dSession["username"], pPassword)
    if dUser is None:
      raise HTTPException(status_code=401, detail="invalid_credentials")
    await asyncio.to_thread(vContext.vAccounts.mResetTotp, dSession["id"])
    vResponse = JSONResponse({"ok": True})
    vResponse.delete_cookie(cSessionCookie, path="/", secure=True, httponly=True, samesite="lax")
    return vResponse

  from backend.web.api_admin import fRegisterAdmin
  from backend.web.api_modules import fRegisterModules
  from backend.web.api_search import fRegisterSearch
  fRegisterSearch(vApp, vContext)
  fRegisterModules(vApp, vContext)
  fRegisterAdmin(vApp, vContext)

  @vApp.api_route("/api/{pPath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
  async def fApiNotFound(pPath: str):
    raise HTTPException(status_code=404, detail="not_found")

  return GuardMiddleware(vApp, vContext), vApp, vContext
