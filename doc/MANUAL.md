# localSIEM user manual

This MANUAL is also available in:\
[en-GB](MANUAL.en-GB.md), en-US, [es-AR](MANUAL.es-AR.md), [es-ES](MANUAL.es-ES.md)

[Installation](../README.md) · [Code reference](CODE.md)

## Contents

1. [What localSIEM does](#what)
2. [Installation](#installation)
3. [Apache and ModSecurity requirements](#requirements)
4. [The doctor](#doctor)
5. [Connecting with the SOC](#soc)
6. [Signing in and accounts](#signin)
7. [The two dashboards](#dashboards)
8. [Overview](#overview)
9. [Searching](#search)
10. [The request card and pivots](#card)
11. [Live view](#live)
12. [Alerts](#alerts)
13. [Modules](#modules)
14. [Administration](#administration)
15. [Health warnings and what to do](#health)
16. [Retention and disk](#retention)
17. [Command line](#cli)

<a id="what"></a>
## 1. What localSIEM does

localSIEM watches the services of the server it is installed on through **modules**, one per service. It only reads the logs of that server: it receives no logs from other machines. The **Apache + ModSecurity** module watches the Apache web: for every request it joins three records, the line of `access.log`, the lines of `error.log` and the record of the ModSecurity audit log, using the `UNIQUE_ID` of the request. Everything is stored for searching. Then localSIEM decides what has to go to the SOC.

**Only what nobody has resolved yet goes to the SOC.**

| Situation | Goes to the SOC? |
|---|---|
| ModSecurity blocked the request in phases 1–2 (before the application received it) | **No.** It stays in localSIEM, searchable, and appears as a count in the next alert of that IP. |
| ModSecurity blocked the response in phases 3–4 (the application had already run the request) | Yes |
| Rule matches with ModSecurity in `DetectionOnly` (nothing is blocked) | Yes |
| Rule matches below the blocking threshold | Yes, with severity `low` |
| Signals of the localSIEM rules (brute force, web shell, sensitive file, enumeration, database error) | Yes |
| Health problems and possible trace deletion | Yes |

**Severity of what goes to the SOC**

| Situation | Severity |
|---|---|
| Rule matches not blocked, answer 3xx, 4xx or 5xx | medium |
| Rule matches not blocked, answer 2xx | high |
| Blocked in phases 3–4 | high |
| Signs of success: data-leakage or web-shell rule (950–955) not blocked, SQL error right after, POST with 2xx to a new `.php` | critical |
| Below the blocking threshold (often false positives of the application) | low (configurable in Settings) |

**Grouping.** One alert per module, vhost, IP, category and severity in a 10-minute window. A critical alert leaves at once; the others wait 60 seconds to gather the burst and leave with the count. A scanner that sends thousands of requests produces a few alerts, not thousands. If the severity rises (for example, the same attack now gets 200 answers), that is another alert.

**What never goes to the SOC:** request or response bodies, cookies, `Authorization` headers, passwords or tokens — not even masked — and what was already blocked in phases 1–2 (only as a count). localSIEM masks sensitive values (`password`, `pass`, `pwd`, `passwd`, `token`, `secret`, `api_key`, `apikey`, `auth`, `session` and the headers `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`) with `***` before storing anything.

**Modules.** The core of localSIEM (storage, search, rules, grouping, delivery to the SOC, health) is the same for every service; each module adds what is specific to one service. The Apache + ModSecurity module (`apache2`) comes from the repository `localSIEM-modules` (GitHub) and is installed, updated and uninstalled only from the web, never by the installer of localSIEM; installing it never installs Apache or ModSecurity. Every module is installed, updated and uninstalled the same way, from the web. Section 13 explains how to install and update them, see their state, turn them on and off and configure them.

<a id="installation"></a>
## 2. Installation

Installation has two steps: the core of localSIEM, and then its modules (step 2 below). Run as root, straight from GitHub:

```bash
# Debian 13
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --install --allow-from 203.0.113.10 --soc-token TOKEN
# Alpine 3.24 (first: apk add bash curl)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-alpine.sh | bash -s -- --install --allow-from 203.0.113.10 --soc-token TOKEN
```

The localSIEM web always listens on **port 10443 with HTTPS**: the installer checks the port is free and stops if another service uses it. The action and the options go after `bash -s --`. The installer checks what it needs (Python 3.13 with `venv`, OpenSSL, the CA certificates, the ACL tools, logrotate, curl, tar) and installs what is missing. Piped like this, it downloads the branch `main` of `https://github.com/PYMEHackers/localSIEM`; run from a copy of the project (`bash deploy/install-update-reinstall-debian.sh --install`), it installs that copy.

**The action.** The installer always needs one action; without one it stops and lists them:

| Action | Use |
|---|---|
| `--install` | Installs localSIEM on a server that does not have it. If it finds anything of localSIEM (`/opt/localsiem`, its services or its `localsiem` user, also of an installation that failed halfway), it stops and points to `--update` and `--reinstall`. |
| `--update` | Updates the installed localSIEM: it keeps its data, accounts, settings, modules and the options given before (below). |
| `--reinstall [--yes]` | Deletes the installed localSIEM with all its data, as `--uninstall` does (below), and installs it again from zero, with new passwords. It asks you to type `yes` first (`--yes` does not ask; it is needed without a terminal) and deletes nothing until the new copy is downloaded and the options are checked. The options of the previous installation are not kept: give them again. |
| `--uninstall [--yes]` | Deletes localSIEM and all its data from the server (below). It goes alone. |

`--update` and `--reinstall` stop when localSIEM is not installed: use `--install`.

Options of `--install`, `--update` and `--reinstall`:

| Option | Use |
|---|---|
| `--allow-from LIST` | IPs and CIDR allowed to open the web, separated by commas: the SOC and your administrators |
| `--soc-url URL` | Default `https://soc.pymehackers.com` |
| `--soc-token TOKEN` | Ingestion token of this client in the SOC. Optional: without a SOC, localSIEM works on its own (section 5) |
| `--soc-ca-file PATH` | Only for a SOC with a private certificate (test servers) |
| `--domain NAME` | Name of the server, for the certificate and the SIEM address (default: its host name) |
| `--certificate PATH --private-key PATH` | Certificate to use. Without them localSIEM copies the Let's Encrypt certificate of `--domain` if there is one (and copies it again at every renewal), or creates a self-signed one. |
| `--retention-days N`, `--max-disk SIZE` | Retention (section 16) |
| `--enable-mfa`, `--disable-mfa` | Two-step verification on (mandatory for every account) or off. Without them, a new installation has it off and an update keeps what was chosen in Administration › Settings (section 14). |
| `--rotate-credentials` | Creates a new JWT signing secret and writes it in `/root/webapp-credentials.txt` |
| `--ref REF` | Branch or tag of localSIEM to download (default `main`) |
| `--source-url URL` | Archive (`.tar.gz`) of localSIEM to install instead of the one of GitHub (a mirror) |
| `--modules-repository URL`, `--modules-ref REF` | Repository (or `.tar.gz` archive) and branch or tag the web installs and updates modules from (section 13). Default: `https://github.com/PYMEHackers/localSIEM-modules`, branch `main`. |

**Always the last version.** GitHub keeps the files of `raw.githubusercontent.com` in a cache for up to 5 minutes after each change, so the commands above read the installer through the GitHub API, which has no cache; the installer then asks that API which commit the branch is and downloads exactly that commit, and it asks every server on the way not to answer with a cached copy. Without a token GitHub allows 60 API requests per hour from each IP address: if it refuses, the command fails with `403` (wait and run it again); if only the question of the installer fails, the installer warns and downloads the branch.

The options are remembered: `--update` without options keeps them. To update:

```bash
# Debian 13 (Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --update
```

The installer log is `/root/webapp-install.log` and the passwords it creates are in `/root/webapp-credentials.txt` (both mode 600). At the end it runs the doctor of every enabled module (section 4) and prints the SIEM address to give to the SOC.

**Uninstall.** `--uninstall` deletes localSIEM from the server: it stops and removes its services and deletes `/opt/localsiem` (code, settings, the database with every event and alert, certificates and modules), the `localsiem` user, the read access to the logs that `setup-modules` gave, the Apache configuration of `--configure-apache` (`localsiem.conf`, with a configtest and a reload of Apache), the logrotate file, the Let's Encrypt hook and the localSIEM entries of `/root/webapp-credentials.txt` (the file is deleted when nothing else is left in it). It asks you to type `yes` first (`--yes` does not ask; it is needed without a terminal). The installer log, the packages the installer added, `mod_unique_id` (Debian) and the logs of Apache stay, also the `localsiem_access.log` of `--configure-apache` and `modsec_audit.log`: localSIEM never changes nor deletes a log of Apache. To uninstall:

```bash
# Debian 13 (Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --uninstall
```

**Reinstall.** To start from zero in one step, `--reinstall` deletes everything in the same way and installs localSIEM again (give the options again):

```bash
# Debian 13 (Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --reinstall --allow-from 203.0.113.10 --soc-token TOKEN
```

**2. The modules.** The installer of localSIEM installs **no module**: it leaves localSIEM ready for them, and an update keeps the ones already installed (and the read access to their logs). Modules are installed **only from the web**: Modules › Installable (section 13), which lists the modules of the repository `localSIEM-modules` that are not installed yet; that repository has no installer of its own. localSIEM downloads the module from it, copies its folder (`mod-<name>/` there) to `/opt/localsiem/modules/<name>/` (the `tests/` folders are not copied; a module installed again gets back the settings it had) and restarts the collector. Modules are updated and uninstalled from the web too: **Update**, when the repository has a newer version, and **Uninstall**, both in Modules › Installed (section 13).

Reading the logs of a module needs root, so, once the module is installed, the web shows in a dialog the command to run as root on the server:

```bash
/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py setup-modules
```

It gives the `localsiem` user read access to the log folders each installed module declares (`/var/log/apache2` for the Apache module; section 3.7), also to the files of the next rotations, restarts localSIEM and runs the doctor as `localsiem`. Add the setup option the web suggests (`--configure-apache` for the Apache module, section 3) to also apply the requirements of the module to its service. It can be run again at any time. The installer of localSIEM refuses `--configure-apache`: that option only goes to this command.

**Installing a module never installs the software it watches.** A new module starts turned on or off as its author decided, except when the server lacks what it needs (for the Apache module: Apache and ModSecurity 2): then it is installed **turned off**, the web says what is missing and its switch stays locked until **Reconfigure** finds it (section 13). Its state is in **Modules › Installed** (section 13).

<a id="requirements"></a>
## 3. Apache and ModSecurity requirements

These are the requirements of the Apache + ModSecurity module. Apache and ModSecurity 2 themselves must be installed first: without them the module cannot be turned on (section 13). localSIEM never changes the Apache configuration by itself. The doctor of the module (section 4) checks each requirement and shows the exact snippet for each one that is missing. With `--configure-apache`, added to the command for root of section 2 (`manage.py setup-modules --configure-apache`), the Apache module applies them for you: it writes one file of its own (`/etc/apache2/conf-available/localsiem.conf` on Debian, `/etc/apache2/conf.d/localsiem.conf` on Alpine), enables `mod_unique_id`, runs `apache2ctl configtest` and **undoes everything if it fails**; if it works, it reloads Apache (never restarts it). To undo it later, delete that file (Debian: `a2disconf localsiem`) and reload Apache.

1. **ModSecurity 2 with OWASP CRS**, with `SecRuleEngine On` or `DetectionOnly`. Both work: with `DetectionOnly` nothing is blocked, so every match goes to the SOC.
2. **`mod_unique_id`**, which ModSecurity 2 needs to work at all (without it, it inspects nothing; Alpine does not load it by default) and which joins the three records of each request.
3. **An access log**. The ones Apache writes by default are enough (`combined`, `vhost_combined`, `common`, or any `LogFormat` of the configuration): each line is joined to its request by client IP, method, URI, status and time («weak correlation»), and the vhost comes from `%v` or, without it, from the Host header and port of the audit record. Optionally, for milliseconds, duration and joining by `UNIQUE_ID`, this format:

   ```apache
   LogFormat "%a %l %u [%{%d/%b/%Y:%H:%M:%S}t.%{msec_frac}t %{%z}t] \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %v %D %{UNIQUE_ID}e" localsiem_combined
   GlobalLog ${APACHE_LOG_DIR}/localsiem_access.log localsiem_combined
   ```

   `GlobalLog` writes it for every vhost, without touching their own logs. `%a` is the real client IP when `mod_remoteip` is used.
4. **`mod_remoteip`** if the web is behind a proxy or a load balancer; without it every request seems to come from the proxy:

   ```apache
   RemoteIPHeader X-Forwarded-For
   RemoteIPInternalProxy 10.0.0.1
   ```
5. **The ModSecurity audit log**, serial and preferably JSON:

   ```apache
   SecAuditEngine RelevantOnly
   SecAuditLogRelevantStatus "^(?:5|4(?!04))"
   SecAuditLogType Serial
   SecAuditLogFormat JSON
   SecAuditLogParts ABIJFHKZ
   SecAuditLog /var/log/apache2/modsec_audit.log
   ```

   Part `E` (response body) is not logged: it is bulky, sensitive and not needed. Part `K` lists the full text of every rule run and makes each record large on the server's disk; localSIEM does not need it and does not store it, so you may remove it. If your ModSecurity does not support JSON, use the native format: localSIEM reads both.
6. **Masking at the source**, so the audit log on disk does not keep passwords either:

   ```apache
   SecAction "id:77001,phase:5,nolog,pass,sanitiseArg:password,sanitiseArg:pass,sanitiseArg:pwd,sanitiseArg:passwd,sanitiseArg:token,sanitiseArg:secret,sanitiseArg:api_key,sanitiseArg:apikey,sanitiseArg:auth,sanitiseArg:session,sanitiseRequestHeader:Authorization,sanitiseRequestHeader:Cookie,sanitiseRequestHeader:Proxy-Authorization,sanitiseRequestHeader:X-Api-Key,sanitiseResponseHeader:Set-Cookie"
   ```
7. **Read access for the `localsiem` user** to the logs. The command for root of section 2 (`manage.py setup-modules`) does it for the folders the installed modules declare (`/var/log/apache2` for the Apache module), and the installer of localSIEM does it again at every update: on Debian it adds `localsiem` to the `adm` group and, as on Alpine, gives `localsiem` read access to those folders through ACLs, including a default ACL so the files of the next rotations are readable too. Logs you add by hand in another folder (section 13) need that access too, for example `setfacl -m g:localsiem:rx /srv/logs`, `setfacl -d -m g:localsiem:r /srv/logs` and `setfacl -m g:localsiem:r /srv/logs/*.log`. localSIEM only reads the logs: it never writes in them, nor rotates, truncates, moves or deletes them. When it starts following a log (at the first start, after installing or turning on a module, or once root gives it read access) it starts at its end: what the log already had is history and is never alerted; only the log of a vhost created later is read from its beginning (when it is up to 5 MB).

<a id="doctor"></a>
## 4. The doctor

Each module has its own doctor. The doctor of the Apache module checks every requirement of section 3, lists the sources found (and those it cannot read, such as piped logs) and shows the snippet that fixes each missing item. It runs at the end of every installation of localSIEM and of the command for root of section 2, appears in the page of each module (**Modules › Installed › Configure**, section 13, with the button «Discover again and run the doctor»), and can be run at any time for every enabled module:

```bash
runuser -u localsiem -- /opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py doctor   # Debian
su -s /bin/sh localsiem -c "/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py doctor"   # Alpine
```

`[ OK ]` is fine, `[WARN]` works with limits, `[FAIL]` must be fixed, `[INFO]` only applies in some situations. A module that cannot be loaded is shown first as `[FAIL] Module <name> not loaded: <reason>`. A module that is turned off has no doctor: if it has requirements (section 13), the doctor shows them instead, so you know whether it can be turned on.

<a id="soc"></a>
## 5. Connecting with the SOC

Connecting localSIEM to a SOC is optional. Without a SOC (no token, or **Send alerts to the SOC** turned off), localSIEM works on its own: it keeps every alert in the **Alerts** tab as «Not sent» and never sends those later, not even when a SOC is configured afterwards: from then on only the new alerts go to it. The channels (Telegram) work with or without a SOC.

The administrator of the SOC:

1. Creates an ingestion token for the client (it is shown only once) and gives it to you. Set it with `--soc-token` or in **Administration › SOC**.
2. Sets as **SIEM address** of the client `https://<server>:<port of localSIEM>` (shown by the installer and in Administration › SOC). The analyst who owns an alert uses that link to come and investigate.
3. Gives you the outgoing IPs of the SOC: add them to the allowed IPs (`--allow-from` or Administration › Settings) and **open the port in the firewall only to them and to your administrators**.

localSIEM sends a **heartbeat** every 5 minutes. If the SOC receives neither alerts nor heartbeats for a while (60 minutes by default), it warns its team. Alerts wait in a persistent queue: a network cut or a restart loses none, and sending one again never duplicates it in the SOC. If the SOC answers that the client has used all its alert numbers, localSIEM stops sending, keeps the queue and shows it in Administration › SOC.

Each alert carries a stable rule name, a description with the exact query to paste in the localSIEM search, and details: vhost, client IP, method, URI (masked), answer, user agent, the ModSecurity data (engine, action, phase, score, threshold, rules, matched data), the group (count, first and last time, sample `UNIQUE_ID`s) and the **context** of the IP: requests and blocked requests in the last hour, blocked rules and the first time it was seen.

<a id="signin"></a>
## 6. Signing in and accounts

Open `https://<server>:10443/`: the sign-in page is only the form, with the logo, the username, the password, **Continue** and, under it, the language and the theme. Accounts are created by an administrator; there is no open registration. Passwords have at least 8 characters. **Two-step verification** is off by default; when an administrator turns it on (Administration › Settings, section 14) it is mandatory for every account: at the next sign-in, scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP...; it shows as «PYMEHackers localSIEM») and type its code, and from then on every sign-in asks for the code of the app. After several failed attempts sign-in is locked for a few minutes.

**Direct access with a token.** An administrator can give an analyst an access URL, `https://<server>:10443/auth/login/auto?token=...` (Users › Access tokens, section 14). Opening it from an allowed address signs in at once, without password nor second factor, and opens the Overview of the user dashboard; add `&next=/user/dashboard/search/?q=...` to open another page of the site. If the token does not work, the sign-in page says why: unknown, expired or revoked token, or the account is disabled or is no longer an analyst. Keep the URL like a password: whoever has it can sign in with that account until it expires or is revoked. Every sign-in, with password or with a token, and every failed attempt is recorded (Sign-ins, section 14).

After signing in you land on the **Overview** of your dashboard (section 7). A link to a search (for example from the SOC) opens the sign-in page if needed and then **the same search with its parameters**.

Roles: **analyst** (works in the user dashboard: overview, search, live view, alerts, the state of the modules and the account) and **administrator** (works in the administrator dashboard: the same plus the configuration of the modules and the administration). The language (en-GB, en-US, es-AR, es-ES), the theme (system, light or dark) and the UTC clock are in the title bar of every page of the dashboards; the sign-in page has them under **Continue** and starts with the ones last chosen in this browser (without a choice, those of the browser and of the system). The language shown when you press **Continue** becomes the language of your account: the dashboards keep it, in any browser, until you change it. Times are always UTC in the native format `2026/10/29@13:59:59.723`. The files localSIEM writes (the exports, `/root/webapp-credentials.txt`, the installer log) and the alerts it sends to the SOC use the storage format `2026-10-29@13-59-59.723`, also in UTC.

<a id="dashboards"></a>
## 7. The two dashboards

Each role has its own dashboard; its address says which one you are in. The sidebar has the logo on top, the tabs (a line between each group) and, at the bottom, **Sign out**.

| | Administrator dashboard | User dashboard |
|---|---|---|
| Who | Administrators | Analysts |
| Address | `/admin/dashboard/<tab>/` | `/user/dashboard/<tab>/` |
| Tabs | Overview, Search, Live, Alerts; Modules (Installed and Installable), Users (Accounts and Access tokens), SOC, Channels (General and Telegram), Settings, Search audit, Sign-ins; Account | Overview, Search, Live, Alerts, Modules (state only), Account |

Every tab has its own address (for example `/admin/dashboard/logins/`), and `/admin/dashboard/` or `/user/dashboard/` open the Overview. The sections of a tab have theirs too: `/admin/dashboard/users/` opens `/admin/dashboard/users/accounts/` and the access tokens are in `/admin/dashboard/users/tokens/`; `/admin/dashboard/modules/` opens `/admin/dashboard/modules/installed/` and the installable modules are in `/admin/dashboard/modules/installable/`. An address of the other dashboard takes you to the same tab of yours: an administrator who opens a link to `/user/dashboard/search/?q=...` (the usual link of the SOC) gets the same search in `/admin/dashboard/search/`; an analyst who opens an administration tab gets the Overview of the user dashboard.

**What analysts see.** Everything needed to investigate: the overview, the searches with their request cards, the live view, the alerts and the state of each module (on or off, working or not, and its counters). They cannot turn modules on or off, configure them, see their doctor or rules, nor manage users, access tokens, the SOC connection, the settings, the search audit or the record of the sign-ins.

<a id="overview"></a>
## 8. Overview

The first tab of both dashboards. It refreshes every 15 seconds and shows:

- **Events (24 h)**, with how many of them raised an alert; **Blocked (24 h)**, what ModSecurity already resolved (kept, no alert); **Alerts (24 h)**, with how many are waiting for the SOC; and **Modules working**, the enabled modules that are «On and working» out of the enabled ones (green when all of them work).
- **Activity of the last 24 hours**: events per hour; the blue part of each bar is what ModSecurity blocked. Click an hour to open the search of its events.
- **State of the modules**: each module with its state (section 13) and what it is reading; «See the modules» opens the Modules tab.
- **System**: whether the collector is running (and its version), since when, the state of the connection with the SOC, the last heartbeat, the alerts waiting for the SOC, the free disk and the size of the database against its maximum.
- **Latest alerts**: the six most recent ones (severity, rule, IP, count, status, last time); «See all the alerts» opens the Alerts tab.

<a id="search"></a>
## 9. Searching

The **Search** tab has one search field and a time range (last 15 minutes, hour, 24 hours, 7 days, 30 days, or a custom range in the native format).

| Syntax | Meaning |
|---|---|
| `word` | Full-text search in the original (masked) text, also URL-decoded |
| `"exact phrase"` | Phrase |
| `field:value` | Field equal to a value (text fields ignore case) |
| `field:*part*` | Wildcards |
| `status:>=500`, `status:400..499`, `status:4xx` | Comparisons and ranges on numeric fields |
| `a b` / `a AND b`, `a OR b`, `NOT a` / `-a`, `( )` | Operators and parentheses |

| Group | Fields |
|---|---|
| Network | `ip`, `vhost`, `host` |
| Request | `method`, `uri`, `path`, `query`, `status`, `bytes`, `duration` (microseconds), `ua`, `referer` |
| Origin | `uid` (UNIQUE_ID), `module`, `source` (`access`/`error`/`audit`) |
| ModSecurity | `rule` (CRS id, or `localsiem:<rule>`), `category`, `phase`, `score`, `engine` (`on`/`detection-only`) |
| Alerts | `severity`, `action` (`blocked`/`none`), `alert` (SOC code), `sent` (`yes`/`no`) |
| Quality | `parse` (`ok`/`partial`/`unparsed`) |

Examples:

- `ip:203.0.113.7` — everything from one IP
- `rule:942100` — requests that matched that CRS rule
- `status:200 action:none category:sqli` — SQL injections that were not blocked and got a 200
- `uri:*wp-login*`
- `"union select"`
- `uid:ZTx1kH8AAQEAAB2gTkAAAAAB` — one request
- `alert:c00007a0001F` — the requests of one SOC alert
- `(category:sqli OR category:xss) sent:no -status:404`

Categories: `sqli`, `xss`, `lfi`, `rfi`, `rce`, `php`, `java`, `fixation`, `generic`, `protocol`, `multipart`, `scanner`, `method`, `data-leakage`, `webshell`, and those of the localSIEM rules: `bruteforce`, `enumeration`, `sensitive-file`, `db-error`, plus `health-*`.

A syntax error is shown under the field with the position of the mistake. A search that takes longer than its limit (5 s) asks you to narrow the range.

The results page shows:

- **The histogram** over time; the blue part of each bar is what ModSecurity blocked. Drag over the bars (or click one) to narrow the range.
- **Summaries** of the query: IPs with most requests, most requested paths, HTTP codes and most frequent rules. Click a value to add it to the query.
- **The results table** (TIME, SOURCE, IP, METHOD, URI, CODE, ACTION, RULES, ALERT), newest first, with «Load more».
- **Export** to CSV or JSON (masked data, up to 10 000 rows, times in the storage format `2026-10-29@13-59-59.723`) and **Copy link** (with absolute times). The link format is `/user/dashboard/search/?q=<query>&from=<native time>&to=<native time>` (`/admin/dashboard/search/...` when copied by an administrator); a link of either dashboard works for both roles.

Every search and export is recorded (who, what, when) and visible to administrators: the logs hold personal data.

<a id="card"></a>
## 10. The request card and pivots

Click a row to open the card of the request: time, vhost, client IP, method, URI, code, size, duration, user agent, `UNIQUE_ID`, correlation, action taken, ModSecurity engine, phase, score and threshold, category, severity and alerts; and, for each record, its parsed content: the rules matched with their message and data, the request headers and the masked body, the response headers, the error lines, and the original line. The module of each record adds what it knows how to show (the Apache module rebuilds the headers and the body from the audit record).

Notes in the card: a 403 without any trace of ModSecurity is marked as **doubtful** (it is not counted as a block); **weak correlation** means the access line was joined to its request by client IP, method, URI, status and time, because the access log has no `UNIQUE_ID`; a **database error** appeared for the request.

Pivots: **This IP** (all its activity), **±5 min** (the timeline around the request), **Rule …** (each rule matched), **This category**, **This UNIQUE_ID**.

<a id="live"></a>
## 11. Live view

The **Live** tab shows the new events as soon as the collector stores them (after the 5-second correlation window), newest on top. The filter uses the search syntax. **Pause** stops the updates; when resumed it continues from the newest event.

<a id="alerts"></a>
## 12. Alerts

The **Alerts** tab lists the alerts generated by localSIEM: SOC code, severity, rule, IP, vhost, count, first and last time, and status:

| Status | Meaning |
|---|---|
| In buffer | Gathering the burst (60 s) before leaving |
| Queued | Waiting for the SOC (network down, SOC not answering) |
| Sent | Accepted by the SOC; its code is shown |
| Rejected | The SOC refused that alert; the rest of the queue goes on. It can be queued again from Administration › SOC. |
| Not sent | There was no SOC configured, or sending to it was turned off: the alert stays in localSIEM and is never sent later (the SOC is optional, section 5) |

Click a row to see the description, the window, the `external_id` and the exact alert sent to the SOC. **Search** opens the search of the group.

<a id="modules"></a>
## 13. Modules

In the administrator dashboard the **Modules** tab has two sections, each with its own address: **Installed** (`/admin/dashboard/modules/installed/`), which opens by default (`/admin/dashboard/modules/` goes there), and **Installable** (`/admin/dashboard/modules/installable/`), where modules are installed (below). Analysts only have the list of the installed modules, without sections (`/user/dashboard/modules/`).

**Installed** lists the installed modules, one row each, the whole width, laid out like the header of the page of the module: at the top the name, the id and the version and, below, its **state**, a summary, the reasons for its state and, if it is on, its counters: sources being read, lines of the last hour, last data, events and blocked requests of the last 24 hours and the result of its doctor. Administrators also see the switch to the right of the name and, at the bottom of the row, its buttons. The page refreshes every 10 seconds. With no module installed it says «Install modules from the Installable tab.» (to analysts: «No modules installed. An administrator installs them in Modules › Installable.»).

| State | Meaning |
|---|---|
| On and working | On, loaded by the collector and reading its sources. Warnings of the doctor are listed as notes and do not change it. |
| On, with warnings | On, but without sources, with a source that does not exist yet, or installed after the collector started (restart the `localsiem` service). |
| Error | It does not load (the reason is shown), its doctor reports an error, or a source cannot be read (permissions of the `localsiem` user, section 3.7). |
| Applying the change… | Just turned on or off; the collector is applying it (a few seconds). |
| Off | Turned off: localSIEM does not read its logs nor send its alerts. What is already stored stays. With the reason «This server lacks what it needs: …», it was installed without its requirements and cannot be turned on yet (see Requirements and Reconfigure, below). |
| Unknown | The collector is not running (service `localsiem`): nobody is reading anything. |

**Analysts** only see this list. **Administrators** also have, in each row:

- **The switch** of each module, to turn it on or off. Turning it off asks for confirmation. The change applies at once, without restarting anything. While the server lacks what a module needs, its switch is locked («Off: requirements missing»).
- **Configure**, which opens the page of the module (`/admin/dashboard/modules/installed/<name>/`; the older address `/admin/dashboard/modules/<name>/` takes you there):
  - the header with the state, the folder where the module is installed, the switch, «Back to the installed modules» (it returns to Installed) and «Discover again and run the doctor»; for a module with requirements, also the button «Reconfigure» and, while the module is off or one is missing, its **Requirements** (below);
  - **Settings**: the form of the module's own settings; «Save the settings» applies them at once;
  - **Sources**: the logs it reads (kind, path, vhost, lines and unparsed lines of the last hour, last data, state) and, below, the logs it found but does not read, with the reason;
  - **Doctor**: its requirement checks, with the snippet that fixes each missing one and a «Copy» button; for a module with a setup option, also the command for root that applies it (`manage.py setup-modules --configure-apache` for the Apache module);
  - **Rules**: each rule of the module with its switch («On»), severity, threshold and window (threshold and window only for threshold and sequence rules); «Save the rules» applies them at once.
- **Update**, when the repository `localSIEM-modules` has a newer version of the module. Each time you open Installed, localSIEM checks the repository: meanwhile it says «Checking the repository for newer versions…» and, if the check fails, «The repository could not be checked for newer versions: <error>», and the list works as usual. So that the repository is not downloaded at every visit, the browser reuses its answer for 10 minutes; «Check the repository», in Installable, always downloads it again, and installing, updating or uninstalling a module discards the answer kept. The refresh every 10 seconds never downloads it. A module with a newer version shows, in its row, the notice «The repository has version X (the installed one is Y).» with the button **Update**. If that version needs a newer localSIEM, the notice has no button and says so: «The repository has version X, but it needs localSIEM Z or newer: update localSIEM to install it.» **Update** asks for confirmation («Update the module»): localSIEM downloads the new version from the repository, swaps it for the installed one and restarts the collector; its settings are kept, and the module stays on or off as it was. While it runs, the button says «Updating…»; at the end a message says «<module> updated to version X.» A dialog, «<module> updated», only opens when there is something else to do: if the new version reads other logs or has another setup option, it shows the command for root (`manage.py setup-modules`, section 2, with «Copy» and, for a module with a setup option, the hint to add it to the command); if the collector did not answer, it asks you to restart the `localsiem` service.
- **Uninstall**, on the row of each installed module (also of one that does not load) and on its page. After confirming, localSIEM deletes `/opt/localsiem/modules/<name>/` and restarts the collector without it: it stops reading its logs and sending its alerts. The events and alerts already stored can still be searched, and its settings (and the changes of its rules) stay in `settings.json`, so they come back if you install it again. The read access that root gave `localsiem` to its logs is not taken back; if no other module reads that folder, you can remove it by hand, for example `setfacl -R -x g:localsiem /var/log/apache2` and `setfacl -d -x g:localsiem /var/log/apache2`.

**Installable** (administrators only) has the card «Installable modules»: the modules of the repository `localSIEM-modules` (by default `https://github.com/PYMEHackers/localSIEM-modules`, branch `main`; the installer options `--modules-repository` and `--modules-ref` change it) that are not installed on this server yet. «Check the repository» downloads it and lists those modules, each with its name, id, version and summary and its button or note:

| Button or note | Meaning |
|---|---|
| Install | Installs the module |
| Needs localSIEM X or newer | It cannot be installed: update localSIEM first |
| The module of the repository is not valid | It cannot be installed |

If every module of the repository is already installed, it says so («Every module of the repository is already installed.»). The modules already installed never appear in this list: they are updated in Installed (**Update**, above). The web neither reinstalls a module nor installs an older version of it: to reinstall one, uninstall it and install it again here (its settings are kept).

This list is the only way to install modules. localSIEM downloads the module, checks its `module.json`, copies its folder (`mod-<name>/` in the repository) to `/opt/localsiem/modules/<name>/` (without its `tests/` folder; a module installed again gets back the settings it had) and restarts the collector, which loads it within a few seconds. The module leaves the list and a dialog, «<module> installed», says what comes next:

- Letting `localsiem` read the logs of the module needs root, so the dialog shows **the command to run as root** on the server, with a «Copy» button: `manage.py setup-modules` (section 2), which gives the read access and restarts localSIEM. For a module with a setup option, it also suggests adding that option to the command (`--configure-apache` for the Apache module) to apply its requirements too. Until the command is run, the module may show «Error» because its logs cannot be read.
- If, on its first installation, the server lacks what the module needs, the module is installed turned off and the dialog lists what is missing instead of the command, with the hint to open the module in Installed (**Configure**) and press **Reconfigure** once it is there (below).

The dialog has two buttons: «Close» and «See the installed modules», which opens Installed. The server needs to reach GitHub (HTTPS) for this list and for the check of newer versions in Installed.

**Requirements and Reconfigure.** Installing a module never installs the software it watches. A module can declare what the server must have before it can be turned on: the Apache module needs Apache (its configuration: `apache2.conf`, `httpd.conf` or the file of the setting **Apache configuration file**) and ModSecurity 2 loaded (`mod_security2`; ModSecurity 3 does not count). If they are missing on its first installation, the module is installed **turned off** («Off», with the reason «This server lacks what it needs: …») and its switch is **locked**. Its page lists its requirements like the doctor (title, detail and the command that installs what is missing, with «Copy»), also while it is off. Once you have installed what is missing (and, if Apache is in a non-standard place, set **Apache configuration file** and saved the settings), press **Reconfigure**: localSIEM looks for it again with the saved settings.

- If it finds everything, it unlocks the switch but does not turn the module on: you turn it on with its switch. It also shows the command for root of section 2, with the setup option as a suggestion (`--configure-apache`): run it, because the logs created after the module was installed (`/var/log/apache2`) can only be read with the read access that root gives.
- If something is still missing, the requirements show it again.
- If the module is already on, Reconfigure also discovers its sources again and runs its doctor.

A module that is on and later loses its requirements (someone uninstalls ModSecurity) stays on: its doctor and the health warning «ModSecurity is no longer loaded» (section 15) report it, and turning it off would silence that very warning. The collector checks the requirements when it starts and when its settings change, never periodically; `manage.py modules` and `manage.py doctor` show them too (section 17).

**Turning the Apache module off and on.** In **Modules › Installed**, use the switch of «Apache + ModSecurity» and confirm. While it is off, localSIEM does not read the Apache logs, does not run its doctor nor its rules and sends no alerts from it; the events already stored can still be searched. Turn the switch on again to resume (only possible while Apache and ModSecurity are there): the collector goes on from the position where it stopped in each log (following the rotations made meanwhile), so it also reads what Apache wrote while the module was off and sends any alerts it calls for.

**Settings of the Apache module** (Modules › Installed › Apache + ModSecurity › Configure):

| Setting | Use |
|---|---|
| Only the sources below | Do not discover the logs from the Apache configuration: read only the sources added by hand |
| Sources added by hand | Logs to read besides the discovered ones (see below) |
| Apache configuration file | Empty: found automatically (`/etc/apache2/apache2.conf` on Debian, `/etc/apache2/httpd.conf` on Alpine). Reconfigure looks for Apache there too |
| Discovery interval (seconds) | How often the Apache configuration is read again to find new vhosts and logs (default 3600) |
| Blocking threshold of ModSecurity | 0: read from the CRS configuration (`tx.inbound_anomaly_score_threshold`), 5 if it is not there |
| Learning days for new PHP files | During the first days a PHP file never seen before is not reported as new (rule `apache-webshell`; default 3) |

**Adding a log by hand.** In **Sources added by hand**, press «Add source» and fill in **Kind** (access.log, error.log or ModSecurity audit log), **Path** (absolute) and, if needed, **Vhost**, **LogFormat** (for an access log in a format of its own), **Audit log type** (Serial or Concurrent) and **Audit storage folder** (for a concurrent audit log). «Remove» deletes a source. Press «Save the settings»: the collector discovers the sources again at once and the new log appears in **Sources**. If it shows as unreadable, give `localsiem` read access to its folder (section 3.7).

**From the module `apache` to `apache2`.** Up to localSIEM 2.1 the Apache module was called `apache`; it is now `apache2` (folder `mod-apache2/` in the repository, installed in `/opt/localsiem/modules/apache2/`, page `/admin/dashboard/modules/installed/apache2/`). On a server that had `apache`, installing `apache2` leaves both loaded: the old one keeps the Apache logs (both find the same sources), `apache2` shows no sources until the old one is uninstalled, and the settings of `apache` do not move by themselves. To migrate:

1. Write down the settings you changed in the page of the module `apache` (Configure): sources added by hand, Apache configuration file, discovery interval, blocking threshold, learning days.
2. Install `apache2` in Modules › Installable.
3. Uninstall the module `apache`: **Uninstall**, on its row in Modules › Installed or on its page. The collector restarts and `apache2` reads the Apache logs from then on.
4. Open the page of `apache2`, enter those settings again and save them. (Instead, as root, you can copy in `/opt/localsiem/config/settings.json`, inside `"modules"`, what is under `"apache"` to `"apache2"`, and then restart localSIEM.)

The rules keep their ids (`apache-bruteforce`…) and their changes, and the positions read in each log and the memory of the health warnings are kept: `apache2` goes on where `apache` stopped, without reading anything twice. The events stored by the module `apache` stay searchable (`module:apache`).

<a id="administration"></a>
## 14. Administration

These tabs are only in the administrator dashboard:

- **Modules** (section 13), in two sections: **Installed** (`/admin/dashboard/modules/installed/`), the list with the switch of each module, **Configure** (requirements and Reconfigure, settings, sources, doctor and rules of the module), **Update** (when the repository has a newer version) and **Uninstall**; and **Installable** (`/admin/dashboard/modules/installable/`), the modules of the repository not installed yet, with **Install**. Modules are installed, updated and uninstalled only there.
- **Users › Accounts** (`/admin/dashboard/users/accounts/`): create accounts (a password is generated and shown once; it must be changed at the first sign-in), reset the password or the two-step verification, enable or disable, change the role, delete. There is always at least one active administrator.
- **Users › Access tokens** (`/admin/dashboard/users/tokens/`): **Create token** for an active analyst account (administrators always sign in with their password, and with the second factor when two-step verification is on), with an optional label and a validity of 7, 30, 90 (default), 180 or 365 days. The access URL, `https://<server>:10443/auth/login/auto?token=...`, is shown **only once**, with a «Copy» button: give it to the analyst (section 6). The list shows each token's account and label, its last 4 characters, its state (Active, Expired, Revoked, or Unusable when the account is disabled or no longer an analyst), when and by whom it was created, when it expires and its last use (time and IP). **Revoke** stops it at once; the sessions it already opened end when they expire. A session opened with a token asks for neither the second factor nor a password change. Failed attempts count for the temporary lockout of the sign-in.
- **SOC**: URL, token (never shown whole), optional CA file, **Test the connection** (sends a heartbeat), delivery state, last heartbeat, last error, queue (waiting, sent, rejected) and **Send the queue now**. Also the SIEM address to give to the SOC. The SOC is optional (section 5).
- **Channels** (`/admin/dashboard/channels/`), in two sections, **General** (it opens by default) and **Telegram**: the messages localSIEM sends to you, besides the alerts it delivers to the SOC (below).
- **Settings**: retention, maximum disk, allowed IPs (your own address must be in the list), two-step verification (off by default; turning it on makes it mandatory for every account and signs out at once the accounts that have not set it up yet, yours included, which set it up at their next sign-in; turning it off keeps the authenticator apps already set up for when it is turned on again), search time limit, export limit, grouping window and buffer, correlation window and severity below the threshold. Changes apply at once. The rules are no longer here: they are configured in each module (Modules › Installed › Configure).
- **Search audit**: who searched what and when.
- **Sign-ins** (`/admin/dashboard/logins/`): every sign-in to localSIEM and every failed attempt, newest first: time, account, method (Password, Password and second factor, or Access token), result (Signed in or Failed), the reason of a failure (wrong username or password, wrong second-factor code, locked after several failures, sign-in took too long, unknown, expired or revoked token, account disabled, account is not an analyst), IP and browser. Filter by result; **Load more** loads older ones. They are kept as long as the alerts (365 days by default).

The state of the collector, of the disk and of the database is in the Overview (section 8).

### Channels: messages to you (Telegram)

Besides delivering every alert to the SOC, localSIEM can send you the most important ones through a **channel**. For now the channel is **Telegram**.

**General** (`/admin/dashboard/channels/general/`):

- **Send messages through the channels**: turns all the channels on or off at once.
- **Minimum severity**: the alerts of this severity or above are sent (default: High).
- **Language of the messages**: en-GB, en-US, es-AR or es-ES (default en-US). The rule and the description of the alert stay as localSIEM wrote them.
- A table with each channel: its state (Off, Not configured, Working or Error), the messages sent, the last one and the last error.

**Telegram** (`/admin/dashboard/channels/telegram/`):

1. In Telegram, open **@BotFather**, send `/newbot` and follow its steps. It gives you the **token of the bot** (`123456789:AA...`; the number before the colon is the id of the bot).
2. Open the chat with your bot and press **Start** (or add the bot to the group, or as an administrator of the channel, that will receive the messages): a bot cannot write to anyone who has not spoken to it first.
3. Find the **chat id**: send any message to the bot and open `https://api.telegram.org/bot<token>/getUpdates` in a browser; the id is the number after `"chat":{"id":`. The id of a group starts with `-` and the one of a channel with `-100`; a public channel or group can also be given as `@username`.
4. Write the token and the chat id, tick **Send the messages through Telegram** and press **Save and send a test message**. If Telegram refuses it, the notice says why (for example `Unauthorized`: wrong token; `Bad Request: chat not found`: wrong chat id, or nobody pressed Start).

The token is kept on the server in `/opt/localsiem/config/telegram-bot-token` (mode 600) and is never shown whole; **Remove the token** deletes it and turns Telegram off. The server needs to reach `https://api.telegram.org` (outgoing port 443).

Each message says the severity, the rule, the description, the module, the number of events, the first and the last time (UTC) and the search that shows them. localSIEM sends at most one message per second. If Telegram does not answer, it tries again a few times; if Telegram refuses a message (wrong token, unknown chat, bot blocked), it drops it and shows the error. The messages waiting are lost if localSIEM restarts: the channels are a notice for you, and the SOC still gets every alert.

<a id="health"></a>
## 15. Health warnings and what to do

These also go to the SOC (rules `localSIEM health: …`), grouped so they do not repeat:

| Warning | Severity | What to do |
|---|---|---|
| Log truncated, disappeared or replaced outside a rotation | high | Someone may be deleting traces. Check who had access to the server at that time and its other logs. |
| ModSecurity no longer loaded, or engine turned Off | high | If nobody did it on purpose, the protection was disabled: check the Apache configuration and its recent changes. |
| Log source not readable | medium | Usually permissions after a rotation: run as root the command of section 2 again (`manage.py setup-modules`) or give `localsiem` read access (section 3.7). |
| Log source silent for a long time (24 h) | medium | Check that Apache still writes that file (logging changes, disk full). |
| Real client IP missing | medium | Almost all requests come from one private address: the web is behind a proxy; configure `mod_remoteip`. |
| Many lines not parsed (more than 5 %) | low | The log format changed: look at the doctor of the module (Modules › Installed › Configure) and, if needed, use `localsiem_combined`. |
| Little free disk, or retention trimmed for lack of space | medium | Free space or raise the maximum disk size. localSIEM stores less detail meanwhile. |

<a id="retention"></a>
## 16. Retention and disk

Events are kept 90 days and alerts 365 days. The database never grows beyond its maximum (default: the lesser of 15 % of the disk and 10 GB): the oldest events are deleted first, in small batches, and the space goes back to the disk. With little free disk localSIEM stops storing the bulky detail (headers and bodies of the audit records); with almost none, it stores only the events that take part in an alert, and it warns the SOC. Change the values with `--retention-days` and `--max-disk` (for example `--max-disk 5G`) or in Administration › Settings.

<a id="cli"></a>
## 17. Command line

As root, `/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py`:

| Command | Use |
|---|---|
| `list-users` | Accounts and their two-step verification |
| `create-user NAME --role admin\|analyst --credentials /root/webapp-credentials.txt` | New account with a generated password |
| `reset-password NAME --credentials /root/webapp-credentials.txt` | New password (to change at the next sign-in) |
| `reset-mfa NAME` | Two-step verification set up again at the next sign-in |
| `doctor` (`--json`) | Requirements and sources of every enabled module and, for a module that is off and has requirements, what it needs before it can be turned on (run it as `localsiem`, section 4) |
| `modules` | Installed modules: name, version, enabled, disabled or not loaded, folder, and below a module the requirements the server lacks for it; and the modules that cannot be loaded, with the reason |
| `read-paths` | Folders the installed modules read (`setup-modules` and the installer give `localsiem` read access to them) |
| `soc-test` | Sends a heartbeat to the SOC |
| `configure-apache` | Prints the file that `--configure-apache` would write (needs the module `apache2`) |
| `setup-modules [OPTION...]` | As root, the command the web shows after installing a module, after an update that changes the logs the module reads or its setup option, and with Reconfigure: read access for `localsiem` to the folders of the installed modules (ACLs, also for the next rotations; the `adm` group on Debian), the setup options given (`setup-modules --configure-apache`), a restart of localSIEM and the doctor as `localsiem`. With `--no-restart` (what the installer uses) it only gives the read access and applies the options. |
| `apply-setup -- OPTION` | Applies only the setup option of an installed module (`apply-setup -- --configure-apache`), as root, without restarting anything |

Modules are installed, updated and uninstalled only from the web (section 13): there is no command for it.

Services: `systemctl restart localsiem localsiem-web` (Debian) or `rc-service localsiem restart; rc-service localsiem-web restart` (Alpine); restart both after copying or deleting a module by hand in `/opt/localsiem/modules/` (the web does it by itself when it installs, updates or uninstalls one). Logs: `journalctl -u localsiem -u localsiem-web` (Debian) or `/opt/localsiem/log/` (Alpine); at start the collector logs the line `Modules: ...` with each module, its version and whether it is on or off, and `Module <name>: requirements missing: ...` for a module whose requirements are missing.
