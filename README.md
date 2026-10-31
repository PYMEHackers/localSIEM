# localSIEM

This README is also available in:\
[en-GB](doc/README.en-GB.md), en-US, [es-AR](doc/README.es-AR.md), [es-ES](doc/README.es-ES.md)

localSIEM is a lightweight SIEM for a small business server. It runs on the same Debian or Alpine server it protects, next to its Apache web, and watches only the logs of that server: it never receives logs from other machines. On that server, localSIEM:

- reads the Apache access and error logs and the **ModSecurity** audit log, joins the three records of each request and keeps them searchable;
- keeps what is already resolved (a request ModSecurity blocked before it reached the application) and sends to the **PYMEHackers SOC** what nobody has resolved yet, grouped so a scanner never floods the analysts;
- can also send you the most important alerts through **Telegram** (the Channels tab), with the minimum severity and the language you choose;
- gives the analyst of the SOC a **search tool** (one search field and a time range) to investigate those alerts;
- never lets passwords, cookies, tokens or request bodies leave the server;
- uses little memory (about 100 MB in normal use, about 200 MB at peak) and never fills the disk.

**Modular.** localSIEM is a generic core (storage, search, rules, grouping, SOC delivery, health) plus **modules**, one per service of the server. The installer of localSIEM installs the core only; the modules, such as Apache + ModSecurity (`apache2`), live in the repository [localSIEM-modules](https://github.com/PYMEHackers/localSIEM-modules) and are installed, updated and uninstalled only from the localSIEM web. Installing a module never installs the software it watches: if the server lacks it (Apache and ModSecurity, for `apache2`), the module is installed turned off, and once it is there the web reconfigures the module to find it. Modules can be turned on and off, and configured, from the web without restarting anything.

**Two dashboards.** Administrators work in `/admin/dashboard/` (overview, search, live view, alerts, modules, users and access tokens, SOC, channels (Telegram), settings, search audit, sign-ins, account); analysts work in `/user/dashboard/` (overview, search, live view, alerts, the state of the modules, account). An administrator can give an analyst an access URL, `https://<server>:10443/auth/login/auto?token=...`, that opens their dashboard without password; every sign-in is recorded.

[User manual](doc/MANUAL.md) · [Code reference](doc/CODE.md)

## Requirements

- Debian 13 (systemd) or Alpine Linux 3.24 or newer (OpenRC), with Python 3.13 or newer. Installation runs as root (no `sudo` needed).
- For the Apache module (`apache2`): Apache with **ModSecurity 2 (mod_security2) and the OWASP Core Rule Set** already active. On Debian: `apt-get install libapache2-mod-security2 modsecurity-crs`. Alpine has no ModSecurity package for Apache; it must be built from source. Neither localSIEM nor the module installs them: without them the module is installed turned off and its page in the web lists what is missing; once they are installed, **Reconfigure** finds them and you can turn the module on.
- TCP port 10443 free: the localSIEM web always listens there, with HTTPS (a self-signed certificate if there is no other). localSIEM never uses ports 80 or 443 and never touches the web of the server.
- Optional: an ingestion token of the SOC for this client (created by an administrator of the SOC). Without a SOC, localSIEM works on its own and keeps its alerts.

The installer installs what else it needs (Python's `venv`, OpenSSL, the ACL tools, logrotate...) when it is missing. On Alpine install Bash and curl first (`apk add bash curl`): the installer is a Bash script.

## Install or update

**1. The core.** Straight from GitHub, as root, on the server:

```bash
# Debian
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --install --allow-from 203.0.113.10,198.51.100.0/24 --soc-token TOKEN
# Alpine
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-alpine.sh | bash -s -- --install --allow-from 203.0.113.10,198.51.100.0/24 --soc-token TOKEN
```

- `--allow-from`: IPs and networks allowed to open the localSIEM web: the outgoing IPs of the SOC and your administrators. Without it the web is open to any address and the installer warns about it.
- `--soc-token`: the ingestion token, optional. It can also be set later in Administration › SOC; only the alerts after that are sent to the SOC.

The installer always needs one action, and without one it stops: `--install` (a server without localSIEM; it stops if it finds one), `--update` (it updates the installed localSIEM and keeps its data, accounts, settings, modules and options), `--reinstall` (it deletes the installed localSIEM with all its data and installs it again from zero; it asks first, and the options must be given again) or `--uninstall` (it deletes localSIEM and all its data from the server; it asks first).

The installer downloads the branch `main` of this repository (`--ref TAG` for a tag or another branch). Run from a copy of the project (`bash deploy/install-update-reinstall-debian.sh --install`), it installs that copy. Other options: `--domain`, `--certificate` and `--private-key`, `--soc-url`, `--retention-days`, `--max-disk`, `--modules-repository` and `--modules-ref` (where the web installs and updates modules from), `--enable-mfa` (two-step verification mandatory for every account; off by default). Run the installer with `--help` for the full list.

**2. The modules.** The installer of localSIEM installs no module: localSIEM is left ready for them. Modules are installed **only from the web**: as an administrator, open **Modules › Installable**, press **Check the repository** (it lists the modules not installed yet) and **Install** the module; localSIEM downloads it from [localSIEM-modules](https://github.com/PYMEHackers/localSIEM-modules). Reading the logs of a module needs root, so the web then shows, in a dialog, the command to run as root on the server:

```bash
/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py setup-modules
```

It gives the `localsiem` user read access to the logs of the installed modules, also to the files of the next rotations, and restarts localSIEM. Add `--configure-apache` to it to make the Apache module apply its Apache requirements (one file of its own, undone if `configtest` fails). If the server lacks what a module needs (Apache or ModSecurity, for the Apache module), the module is installed turned off and the web says what is missing: install it, press **Reconfigure** on the page of the module (Modules › Installed › Configure) and, once it finds it, turn the module on and run the command it shows. When the repository has a newer version of an installed module, its row in **Modules › Installed** says so and offers **Update**: localSIEM downloads the new version and swaps it for the installed one, keeping its settings and leaving the module on or off as it was (the command for root is only needed again when the new version reads other logs or has another setup option, and then the web shows it). To remove a module, press **Uninstall** on its row in **Modules › Installed** or on its page. Servers that had the earlier module `apache`: the [user manual](doc/MANUAL.md#modules) explains how to move to `apache2`.

To update, run the same command with `--update` instead of `--install` (the options can be left out); it can be run again and again. It remembers its options in `/opt/localsiem/config/install.env` and keeps the modules already installed, and their read access. It writes its log to `/root/webapp-install.log` and the generated passwords to `/root/webapp-credentials.txt`, both with mode 600. When it finishes it runs the doctor of every enabled module and prints the **SIEM address** to give to the SOC (`https://server:10443`).

## Run

localSIEM runs as two services of the system user `localsiem`:

```bash
# Debian
systemctl status localsiem localsiem-web
# Alpine
rc-service localsiem status; rc-service localsiem-web status
```

Open `https://<server>:10443/` from an allowed address and sign in as `admin` with the password of `/root/webapp-credentials.txt`. You will be asked to choose a new password. Two-step verification is off by default: an administrator can make it mandatory for every account in Administration › Settings, and then each account sets it up with an authenticator app (it shows as «PYMEHackers localSIEM»). The **Overview** of your dashboard opens; **Modules** shows whether each module is on and working.

## Files on the server

| Path | Content |
|---|---|
| `/opt/localsiem/webapp/` | Code of the core |
| `/opt/localsiem/modules/` | Installed modules, one folder each (`apache2/`), installed by the web from `localSIEM-modules` |
| `/opt/localsiem/venv/` | Python dependencies (separate from the system's) |
| `/opt/localsiem/config/` | Settings, SOC token, secrets (mode 600) |
| `/opt/localsiem/db/` | Databases |
| `/opt/localsiem/certificates/` | Certificate of the web |
| `/opt/localsiem/log/`, `/opt/localsiem/run/` | Logs (Alpine) and runtime files |

The [user manual](doc/MANUAL.md) explains the two dashboards, the modules, the Apache requirements, the connection with the SOC, what goes to the SOC and what stays, the search syntax and the health warnings.
