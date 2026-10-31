#!/bin/bash

set -euo pipefail

# localSIEM installer, updater and reinstaller for Debian 13 (systemd).
# It installs the core of localSIEM only, never a module: the modules are
# installed from the web only (Modules › Installable), and then, as
# root, manage.py setup-modules lets localsiem read their logs. Straight
# from GitHub, on a server with nothing else:
#   curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --install
#   curl -fsSL ...same URL... | bash -s -- --install --allow-from 203.0.113.10 --soc-token TOKEN
#   curl -fsSL ...same URL... | bash -s -- --update
# It always needs one action, and without one it stops: --install (a server
# without localSIEM), --update (an installed localSIEM: it keeps everything),
# --reinstall (it deletes the installed localSIEM with all its data and
# installs it again from zero) or --uninstall. Run from a complete copy of
# the project it installs that copy; piped, run alone, or with --ref or
# --source-url, it downloads the archive of the repository. It installs what
# it needs (python3, python3-venv, openssl...) when it is missing. --update
# can be run again and again; the options given once are remembered in
# /opt/localsiem/config/install.env.

cRepository='https://github.com/PYMEHackers/localSIEM'
cRepositoryApi='https://api.github.com/repos/PYMEHackers/localSIEM'
# Sent with every download: neither GitHub nor a proxy on the way may answer
# with a copy kept from before.
aNoCache=(-H 'Cache-Control: no-cache' -H 'Pragma: no-cache')
cDestination='/opt/localsiem/webapp'
cVenv='/opt/localsiem/venv'
cInstallLog='/root/webapp-install.log'
cCredentials='/root/webapp-credentials.txt'
cOldInstallLog='/root/app-web-install.log'
cOldCredentials='/root/app-web-credentials.txt'
aPackages=(python3 python3-venv openssl ca-certificates acl logrotate curl tar gzip)
vSourcePath=''
vTemporaryPath=''
vDownloadPath=''
vRef=''
vSourceUrl=''
# install, update, reinstall or uninstall: always exactly one.
vAction=''
vYes=''
# Set by fConfirmRemoval when the administrator agrees to delete localSIEM.
vConfirmed=''

fCleanup() {
  if [ -n "$vTemporaryPath" ]; then
    case "$vTemporaryPath" in
      "$vSourcePath"/_/temp/install.*)
        rm -rf -- "$vTemporaryPath"
        ;;
    esac
  fi
  if [ -n "$vDownloadPath" ]; then
    case "$vDownloadPath" in
      /tmp/localsiem-install.*)
        rm -rf -- "$vDownloadPath"
        ;;
    esac
  fi
}

trap fCleanup EXIT

fGetTimestamp() {
  local vNow
  vNow="${EPOCHREALTIME/,/.}"
  TZ=UTC0 printf '%(%Y-%m-%d@%H-%M-%S)T.%s\n' "${vNow%.*}" "${vNow:(-6):3}"
}

fShowHelp() {
  printf '%s\n' \
    'Usage: bash deploy/install-update-reinstall-debian.sh ACTION [options]' \
    "       curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- ACTION [options]" \
    '' \
    'ACTION, always exactly one:' \
    '  --install                install localSIEM on a server that does not have it' \
    '  --update                 update the installed localSIEM: it keeps its data, accounts, settings, modules' \
    '                           and the options given before' \
    '  --reinstall [--yes]      delete the installed localSIEM with all its data and install it again from zero,' \
    '                           with new passwords (asks first; --yes does not ask). The options given before are' \
    '                           not kept: give them again' \
    '  --uninstall [--yes]      delete localSIEM and all its data from this server (asks first; --yes does not ask)' \
    '' \
    'Options of --install, --update and --reinstall:' \
    '  (the web always listens with HTTPS on port 10443; self-signed certificate if there is no other)' \
    '  --allow-from LIST        IPs and CIDR allowed to reach the web, separated by commas' \
    '  --soc-url URL            SOC (default https://soc.pymehackers.com)' \
    '  --soc-token TOKEN        ingestion token of this client in the SOC (optional: without a SOC localSIEM works on its own)' \
    '  --soc-ca-file PATH       CA of a SOC with a private certificate (test servers)' \
    '  --domain NAME            name of this server (certificate and SIEM address)' \
    '  --certificate PATH --private-key PATH   certificate to use' \
    '  --retention-days N       days of events (default 90)' \
    '  --max-disk SIZE          maximum database size (2G, 500M; default auto: lesser of 15 % and 10 GB)' \
    '  --enable-mfa             two-step verification mandatory for every account; --disable-mfa turns it off' \
    '                           (default: off on a new installation; an update keeps the setting of the web)' \
    '  --rotate-credentials     new JWT secret' \
    '  --ref REF                branch or tag of localSIEM to download (default main)' \
    '  --source-url URL         archive (.tar.gz) of localSIEM to install instead of GitHub' \
    '  --modules-repository URL repository (or .tar.gz archive) the web installs modules from' \
    '                           (default https://github.com/PYMEHackers/localSIEM-modules)' \
    '  --modules-ref REF        its branch or tag (default main)' \
    '' \
    'Modules are not installed here: install them from the web (Modules › Installable).'
}

fIsCompleteCopy() {
  [ -f "$1/deploy/configure.py" ] && [ -f "$1/backend/server.py" ] && [ -f "$1/backend/collector.py" ] && [ -f "$1/frontend/index.html" ] && [ -f "$1/backend/requirements.txt" ]
}

fIsInstalled() {
  # Any trace of localSIEM on this server, also of an installation that
  # failed halfway: its folder, its services or its user (with the home of
  # localSIEM). --install needs none; --update and --reinstall need one.
  local vAccountHome
  if [ -e /opt/localsiem ] || [ -L /opt/localsiem ] || [ -f /etc/systemd/system/localsiem.service ] || [ -f /etc/systemd/system/localsiem-web.service ]; then
    return 0
  fi
  if getent passwd localsiem >/dev/null; then
    vAccountHome="$(getent passwd localsiem | cut -d: -f6)"
    if [ "$vAccountHome" = '/opt/localsiem' ] || [ "$vAccountHome" = '/opt/localsiem/' ]; then
      return 0
    fi
  fi
  return 1
}

fEnsurePackages() {
  # Only what is missing is installed; apt-get update runs only then.
  local vPackage
  local vStatus
  local aMissing=()
  for vPackage in "${aPackages[@]}"; do
    vStatus="$(dpkg-query -W -f='${Status}' "$vPackage" 2>/dev/null || true)"
    case "$vStatus" in
      *'ok installed')
        ;;
      *)
        aMissing+=("$vPackage")
        ;;
    esac
  done
  if [ "${#aMissing[@]}" -eq 0 ]; then
    printf '%s\n' "Dependencies already installed: ${aPackages[*]}."
    return 0
  fi
  printf '%s\n' "Installing the missing dependencies: ${aMissing[*]}."
  apt-get update < /dev/null || return 1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${aMissing[@]}" < /dev/null || return 1
}

fResolveRef() {
  # GitHub keeps what it serves of a branch in its cache for a few minutes
  # after a push, so a download right after it could bring the version
  # before. Its API (which is not cached) is asked for the commit of the
  # branch or tag, and the archive of that commit, which never changes, is
  # the one downloaded. Prints the commit; fails when the API does not
  # answer (without a token it allows 60 requests per hour from each IP
  # address).
  local pRef="$1"
  local vCommit
  if [[ "$pRef" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s\n' "$pRef"
    return 0
  fi
  vCommit="$(curl -fsS --retry 3 --connect-timeout 20 "${aNoCache[@]}" -H 'Accept: application/vnd.github.sha' "$cRepositoryApi/commits/$pRef" < /dev/null)" || return 1
  if [[ ! "$vCommit" =~ ^[0-9a-f]{40}$ ]]; then
    return 1
  fi
  printf '%s\n' "$vCommit"
}

fGetSource() {
  # The complete copy the installer runs from; piped (curl ... | bash, where
  # BASH_SOURCE is "main"), run alone, or with --ref or --source-url: the
  # archive of the repository, downloaded and unpacked in a temporary folder.
  local vScript="${BASH_SOURCE[0]:-}"
  local vCandidate
  local vUrl
  local vCommit
  local vEntry
  local aTop=()
  if [ -z "$vRef" ] && [ -z "$vSourceUrl" ] && [ -n "$vScript" ] && [ "$vScript" != 'main' ] && [ -f "$vScript" ]; then
    vCandidate="$(cd -- "$(dirname -- "$vScript")/.." && pwd -P)" || return 1
    if [ "$vAction" = 'reinstall' ] && [[ "$vCandidate/" == /opt/localsiem/* ]]; then
      # The installed copy goes with the rest of /opt/localsiem.
      printf '%s\n' "--reinstall deletes $vCandidate before installing, so it does not install from there: it downloads localSIEM."
    elif fIsCompleteCopy "$vCandidate"; then
      vSourcePath="$vCandidate"
      printf '%s\n' "Installing localSIEM from $vSourcePath."
      return 0
    fi
  fi
  if [ -n "$vSourceUrl" ]; then
    vUrl="$vSourceUrl"
  elif vCommit="$(fResolveRef "${vRef:-main}")"; then
    printf '%s\n' "${vRef:-main} is the commit $vCommit of $cRepository."
    vUrl="$cRepository/archive/$vCommit.tar.gz"
  else
    printf '%s\n' "Warning: the GitHub API did not say which commit ${vRef:-main} is; downloading the archive of ${vRef:-main}, which GitHub may still serve from its cache for a few minutes after a change."
    vUrl="$cRepository/archive/${vRef:-main}.tar.gz"
  fi
  vDownloadPath="$(mktemp -d /tmp/localsiem-install.XXXXXX)" || return 1
  printf '%s\n' "Downloading localSIEM from $vUrl."
  curl -fsSL --retry 3 --connect-timeout 20 "${aNoCache[@]}" -o "$vDownloadPath/localSIEM.tar.gz" "$vUrl" < /dev/null || return 1
  mkdir "$vDownloadPath/source" || return 1
  tar -C "$vDownloadPath/source" --no-same-owner -xzf "$vDownloadPath/localSIEM.tar.gz" || return 1
  # GitHub puts everything in one folder: localSIEM-<commit, branch or tag>/.
  for vEntry in "$vDownloadPath/source"/*; do
    if [ -e "$vEntry" ]; then
      aTop+=("$vEntry")
    fi
  done
  if [ "${#aTop[@]}" -eq 1 ] && [ -d "${aTop[0]}" ]; then
    vSourcePath="${aTop[0]}"
  else
    vSourcePath="$vDownloadPath/source"
  fi
  if ! fIsCompleteCopy "$vSourcePath"; then
    printf '%s\n' "$vUrl is not a complete copy of localSIEM."
    return 1
  fi
}

fGrantLogAccess() {
  # localsiem reads the logs of the folders its installed modules declare
  # (read_paths of each module.json; /var/log/apache2 for the apache2
  # module), so the modules installed before an update keep their access:
  # through the adm group (Debian creates them root:adm 640) and, for files
  # created with another group, through ACLs, also for the files of the next
  # rotations (default ACL). manage.py setup-modules does it, the same
  # command the web shows after installing a module; --no-restart: the
  # services are restarted below. Without modules there is nothing to do.
  PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/backend/manage.py" setup-modules --no-restart < /dev/null || return 1
}

fRemoveReadAccess() {
  # The read access manage.py setup-modules gave localsiem (ACLs and default
  # ACLs): the folders of the installed modules and /var/log/apache2, where
  # the apache2 module reads (a module uninstalled from the web keeps the
  # access it was given). The adm group goes with the user. Before the group
  # is deleted: setfacl needs its name.
  local vFolder
  local aFolders=(/var/log/apache2)
  if ! getent group localsiem >/dev/null || ! command -v setfacl >/dev/null; then
    return 0
  fi
  if [ -x "$cVenv/bin/python" ] && [ -f "$cDestination/backend/manage.py" ]; then
    while IFS= read -r vFolder; do
      if [ -n "$vFolder" ] && [ "$vFolder" != '/var/log/apache2' ]; then
        aFolders+=("$vFolder")
      fi
    done < <(PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/backend/manage.py" read-paths < /dev/null 2>/dev/null || true)
  fi
  for vFolder in "${aFolders[@]}"; do
    if [ ! -d "$vFolder" ]; then
      continue
    fi
    if setfacl -R -x g:localsiem,d:g:localsiem -- "$vFolder" 2>/dev/null; then
      printf '%s\n' "Read access of localsiem removed from $vFolder."
    else
      printf '%s\n' "Warning: the read access of localsiem could not be removed from all of $vFolder (getfacl -R $vFolder shows it)."
    fi
  done
}

fRemoveApacheSetup() {
  # What --configure-apache of the apache2 module added to Apache: its own
  # file (which says: remove this file to undo it). Apache is reloaded, never
  # restarted, and only if its configtest passes. mod_unique_id stays enabled:
  # ModSecurity uses it too. localSIEM only reads the logs of Apache, never
  # changes nor deletes them: the localsiem_access.log that file made Apache
  # write stays, like modsec_audit.log.
  local vChanged=''
  local vLog
  if [ -L /etc/apache2/conf-enabled/localsiem.conf ] || [ -e /etc/apache2/conf-enabled/localsiem.conf ]; then
    # a2disconf also updates the state of Debian's apache2 scripts; a link
    # left without its file is removed by hand.
    if ! command -v a2disconf >/dev/null || ! a2disconf -q localsiem < /dev/null; then
      rm -f -- /etc/apache2/conf-enabled/localsiem.conf || return 1
    fi
    vChanged='yes'
  fi
  if [ -f /etc/apache2/conf-available/localsiem.conf ]; then
    rm -f -- /etc/apache2/conf-available/localsiem.conf || return 1
    vChanged='yes'
  fi
  if [ -n "$vChanged" ]; then
    printf '%s\n' 'Apache configuration of localSIEM removed (/etc/apache2/conf-available/localsiem.conf).'
    if command -v apache2ctl >/dev/null && systemctl is-active --quiet apache2; then
      if apache2ctl configtest < /dev/null; then
        if systemctl reload apache2; then
          printf '%s\n' 'Apache reloaded.'
        else
          printf '%s\n' 'Warning: Apache could not be reloaded: systemctl reload apache2.'
        fi
      else
        printf '%s\n' 'Warning: the Apache configtest fails, so Apache was not reloaded: apache2ctl configtest.'
      fi
    fi
  fi
  for vLog in /var/log/apache2/localsiem_access.log*; do
    if [ -f "$vLog" ]; then
      printf '%s\n' "$vLog stays: localSIEM never changes nor deletes a log of Apache (delete it by hand if you do not want it)."
    fi
  done
}

fRemoveCredentials() {
  # The blocks localSIEM appended to the credentials file (each one starts
  # with a line «localSIEM ...»). What other applications wrote there stays;
  # a file left empty is deleted.
  local vFile
  if ! command -v python3 >/dev/null; then
    printf '%s\n' "Warning: without python3, $cCredentials was not cleaned: remove the localSIEM entries by hand."
    return 0
  fi
  for vFile in "$cCredentials" "$cOldCredentials"; do
    if [ ! -f "$vFile" ] || [ -L "$vFile" ]; then
      continue
    fi
    python3 -I -c '
import re
import sys
from pathlib import Path
vPath = Path(sys.argv[1])
lBlocks = [vBlock.strip("\n") for vBlock in re.split(r"\n[ \t]*\n", vPath.read_text(encoding="utf-8")) if vBlock.strip()]
lKept = [vBlock for vBlock in lBlocks if not vBlock.lstrip().startswith("localSIEM ")]
if lKept:
  with open(vPath, "r+", encoding="utf-8") as vHandle:
    vHandle.seek(0)
    vHandle.write("\n" + "\n\n".join(lKept) + "\n")
    vHandle.truncate()
  print(f"{vPath}: the localSIEM entries were removed; the entries of other applications stay.")
else:
  vPath.unlink()
  print(f"{vPath} removed.")
' "$vFile" < /dev/null || return 1
  done
}

fConfirmRemoval() {
  # --uninstall and --reinstall delete localSIEM with all its data: what goes
  # is shown and, without --yes, the administrator types yes on the terminal
  # (never on the standard input, which is this script with curl ... | bash).
  # Sets vConfirmed; cancelling is not an error.
  local pAction="$1"
  local vAnswer=''
  local vQuestion='Type yes to delete it: '
  vConfirmed=''
  printf '%s\n' \
    'This deletes localSIEM from this server: its services, /opt/localsiem (code, settings,' \
    'accounts, database with every event and alert, certificates, modules), the user localsiem,' \
    'the read access to the logs it was given, the Apache configuration of --configure-apache' \
    "and the localSIEM entries of $cCredentials. It cannot be undone."
  if [ "$pAction" = 'reinstall' ]; then
    printf '%s\n' \
      'Then it installs localSIEM again from zero, with new passwords. The options of the' \
      'current installation are not kept: give them with --reinstall (--allow-from, --soc-token...).'
    vQuestion='Type yes to delete it and install it again: '
  fi
  if [ -z "$vYes" ]; then
    printf '%s' "$vQuestion"
    if ! read -r vAnswer 2>/dev/null < /dev/tty; then
      printf '\n%s\n' "There is no terminal to ask on: run it again with --$pAction --yes." >&2
      return 1
    fi
    if [ "$vAnswer" != 'yes' ]; then
      printf '%s\n' 'Cancelled: nothing was deleted.'
      return 0
    fi
  fi
  vConfirmed='yes'
}

fRemoveInstallation() {
  # Everything of localSIEM on this server, with all its data (--uninstall,
  # and --reinstall before it installs again). Every step looks at what is
  # there first, so it can be run again. The packages the installer added
  # stay: other services of the server may use them.
  local vAccountHome
  local vFile
  local vPath
  local vUnit
  for vUnit in localsiem-web.service localsiem.service; do
    if [ -f "/etc/systemd/system/$vUnit" ]; then
      systemctl disable --now "$vUnit" < /dev/null || return 1
      rm -f -- "/etc/systemd/system/$vUnit" || return 1
      printf '%s\n' "Service $vUnit stopped and removed."
    fi
  done
  systemctl daemon-reload || return 1
  systemctl reset-failed localsiem.service localsiem-web.service 2>/dev/null || true
  # Nothing of localsiem may keep running: userdel refuses a user with
  # processes.
  if getent passwd localsiem >/dev/null && pgrep -u localsiem >/dev/null; then
    pkill -u localsiem || true
    sleep 2
    if pgrep -u localsiem >/dev/null; then
      pkill -9 -u localsiem || true
      sleep 1
    fi
  fi
  fRemoveReadAccess || return 1
  fRemoveApacheSetup || return 1
  for vFile in /etc/logrotate.d/localsiem /etc/letsencrypt/renewal-hooks/deploy/localsiem.sh /etc/letsencrypt/renewal-hooks/deploy/.localsiem.sh.tmp; do
    if [ -e "$vFile" ] || [ -L "$vFile" ]; then
      rm -f -- "$vFile" || return 1
      printf '%s\n' "$vFile removed."
    fi
  done
  if getent passwd localsiem >/dev/null; then
    vAccountHome="$(getent passwd localsiem | cut -d: -f6)" || return 1
    if [ "$vAccountHome" = '/opt/localsiem' ] || [ "$vAccountHome" = '/opt/localsiem/' ]; then
      userdel localsiem || return 1
      printf '%s\n' 'User localsiem removed.'
    else
      printf '%s\n' "Warning: the user localsiem has the home $vAccountHome: it is not the one of localSIEM and it stays."
    fi
  fi
  if getent group localsiem >/dev/null && ! getent passwd localsiem >/dev/null; then
    groupdel localsiem || return 1
    printf '%s\n' 'Group localsiem removed.'
  fi
  if [ -d /opt/localsiem ] && [ ! -L /opt/localsiem ]; then
    rm -rf -- /opt/localsiem || return 1
    printf '%s\n' '/opt/localsiem removed.'
  fi
  # Copies left by earlier runs; the one this run downloaded (--reinstall)
  # stays until it is installed.
  for vPath in /tmp/localsiem-install.*; do
    if [ -d "$vPath" ] && [ "$vPath" != "$vDownloadPath" ]; then
      rm -rf -- "$vPath" || return 1
    fi
  done
  fRemoveCredentials || return 1
}

fUninstall() {
  # --uninstall: localSIEM leaves this server with all its data.
  fConfirmRemoval 'uninstall' || return 1
  if [ -z "$vConfirmed" ]; then
    return 0
  fi
  touch "$cInstallLog" || return 1
  chown root:root "$cInstallLog" || return 1
  chmod 600 "$cInstallLog" || return 1
  exec > >(tee -a "$cInstallLog") 2>&1
  printf '\n%s\n' 'Starting localSIEM uninstallation.'
  fGetTimestamp || return 1
  if [ ! -f /etc/debian_version ] || [ ! -d /run/systemd/system ]; then
    printf '%s\n' 'Debian with systemd is required.'
    return 1
  fi
  fRemoveInstallation || return 1
  printf '\n%s\n' 'localSIEM uninstalled.' \
    "Kept: $cInstallLog (with this record) and the packages the installer added (other services may use them)." \
    'To install it again, run this installer with --install.'
  fGetTimestamp || return 1
}

fMain() {
  local vArgument
  local vAccountHome
  local vDocument
  local vMovedFile
  local vObsoleteFile
  local vOldDirectory
  local vOptional
  local vPort
  local vExpect=''
  local vStarting=''
  local vFinished=''
  local aCopy=()
  # The options for configure.py: every argument but the action and --yes.
  local aArguments=()

  for vArgument in "$@"; do
    case "$vExpect" in
      ref)
        vRef="$vArgument"
        vExpect=''
        aArguments+=("$vArgument")
        continue
        ;;
      source-url)
        vSourceUrl="$vArgument"
        vExpect=''
        aArguments+=("$vArgument")
        continue
        ;;
    esac
    case "$vArgument" in
      --help|-h)
        fShowHelp
        return 0
        ;;
      --install|--update|--reinstall|--uninstall)
        if [ -n "$vAction" ] && [ "$vAction" != "${vArgument#--}" ]; then
          printf '%s\n' "Give only one action: --$vAction and $vArgument do not go together." >&2
          return 1
        fi
        vAction="${vArgument#--}"
        continue
        ;;
      --yes)
        vYes='yes'
        continue
        ;;
      --ref)
        vExpect='ref'
        ;;
      --ref=*)
        vRef="${vArgument#--ref=}"
        ;;
      --source-url)
        vExpect='source-url'
        ;;
      --source-url=*)
        vSourceUrl="${vArgument#--source-url=}"
        ;;
      --port|--port=*)
        printf '%s\n' 'The localSIEM web always listens with HTTPS on port 10443: --port is not an option any more.' >&2
        return 1
        ;;
      --configure-*)
        # The setup option of a module (--configure-apache of the apache2
        # module) goes only to manage.py setup-modules, once the module is
        # installed: this installer installs the core only.
        printf '%s\n' "$vArgument is not an option of this installer, which installs the core only. Install the module from the web (Modules › Installable) and then, as root:" "  $cVenv/bin/python $cDestination/backend/manage.py setup-modules $vArgument" >&2
        return 1
        ;;
      --modules-from|--modules-from=*)
        printf '%s\n' "$vArgument is not an option any more: modules are installed from the web only (Modules › Installable)." >&2
        return 1
        ;;
    esac
    aArguments+=("$vArgument")
  done
  if [ -z "$vAction" ]; then
    printf '%s\n' \
      'Say what to do, with one action:' \
      '  --install     install localSIEM on a server that does not have it' \
      '  --update      update the installed localSIEM (it keeps everything)' \
      '  --reinstall   delete the installed localSIEM with all its data and install it again from zero' \
      '  --uninstall   delete localSIEM and all its data from this server' \
      '--help shows every option.' >&2
    return 1
  fi
  if [ "$vAction" = 'uninstall' ] && [ "${#aArguments[@]}" -gt 0 ]; then
    printf '%s\n' '--uninstall goes alone (or with --yes): it takes no other option.' >&2
    return 1
  fi
  if [ -n "$vYes" ] && [ "$vAction" != 'uninstall' ] && [ "$vAction" != 'reinstall' ]; then
    printf '%s\n' '--yes only goes with --reinstall or --uninstall.' >&2
    return 1
  fi
  if [ -n "$vRef" ] && { [[ ! "$vRef" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || [[ "$vRef" == *..* ]]; }; then
    printf '%s\n' 'Invalid --ref (a branch or a tag).' >&2
    return 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Run this installer as root.' >&2
    return 1
  fi
  umask 077
  if [ "$vAction" = 'uninstall' ]; then
    fUninstall || return 1
    return 0
  fi
  if [ "$vAction" = 'install' ] && fIsInstalled; then
    printf '%s\n' \
      'localSIEM is already installed on this server (/opt/localsiem, its services or its user), so --install stops. Use:' \
      '  --update      to update it, keeping its data, accounts, settings, modules and options' \
      '  --reinstall   to delete it with all its data and install it again from zero' >&2
    return 1
  fi
  if [ "$vAction" != 'install' ] && ! fIsInstalled; then
    printf '%s\n' "localSIEM is not installed on this server, so there is nothing to $vAction: use --install." >&2
    return 1
  fi
  case "$vAction" in
    install)
      vStarting='Starting localSIEM installation.'
      vFinished='Installation finished.'
      ;;
    update)
      vStarting='Starting localSIEM update.'
      vFinished='Update finished.'
      ;;
    reinstall)
      vStarting='Starting localSIEM reinstallation.'
      vFinished='Reinstallation finished.'
      # Asked before anything changes; what is deleted, only once the new
      # copy is downloaded and its options are checked (below).
      fConfirmRemoval 'reinstall' || return 1
      if [ -z "$vConfirmed" ]; then
        return 0
      fi
      ;;
  esac
  if [ -f "$cOldInstallLog" ] && [ ! -e "$cInstallLog" ]; then
    mv -- "$cOldInstallLog" "$cInstallLog" || return 1
  fi
  if [ -f "$cOldCredentials" ] && [ ! -e "$cCredentials" ]; then
    mv -- "$cOldCredentials" "$cCredentials" || return 1
  fi
  touch "$cInstallLog" "$cCredentials" || return 1
  chown root:root "$cInstallLog" "$cCredentials" || return 1
  chmod 600 "$cInstallLog" "$cCredentials" || return 1
  # Nothing prints the SOC token, so it never reaches the installation log.
  exec > >(tee -a "$cInstallLog") 2>&1
  printf '\n%s\n' "$vStarting"
  fGetTimestamp || return 1
  if [ ! -f /etc/debian_version ] || [ ! -d /run/systemd/system ]; then
    printf '%s\n' 'Debian with systemd and Python 3.13 or newer is required.'
    return 1
  fi
  fEnsurePackages || return 1
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else "Python 3.13 or newer is required; use Debian 13 or newer.")' || return 1
  fGetSource || return 1
  mkdir -p "$vSourcePath/_/temp" || return 1
  vTemporaryPath="$(mktemp -d "$vSourcePath/_/temp/install.XXXXXX")" || return 1
  PYTHONDONTWRITEBYTECODE=1 python3 "$vSourcePath/deploy/configure.py" --check-arguments "${aArguments[@]}" || return 1
  if [ "$vAction" = 'reinstall' ]; then
    # Only now, with the new copy downloaded and its options checked: a
    # failed download or a wrong option leaves the installation as it was.
    printf '\n%s\n' 'Deleting the installed localSIEM with all its data.'
    fRemoveInstallation || return 1
    # The credentials file goes when it only had localSIEM entries.
    touch "$cCredentials" || return 1
    chown root:root "$cCredentials" || return 1
    chmod 600 "$cCredentials" || return 1
    printf '%s\n' 'Installed localSIEM deleted: installing it again from zero.'
  fi

  if getent passwd localsiem >/dev/null; then
    vAccountHome="$(getent passwd localsiem | cut -d: -f6)" || return 1
    if [ "$vAccountHome" != '/opt/localsiem' ] && [ "$vAccountHome" != '/opt/localsiem/' ]; then
      printf '%s\n' 'Existing user localsiem has a different home. Installation stopped.'
      return 1
    fi
    if [ "$(id -gn localsiem)" != 'localsiem' ]; then
      printf '%s\n' 'Existing user localsiem must have primary group localsiem.'
      return 1
    fi
  else
    useradd --system --user-group --home-dir /opt/localsiem --create-home --shell /usr/sbin/nologin localsiem || return 1
  fi
  # modules/: the modules the web installs later (Modules › Installable);
  # an update keeps the ones already there.
  install -d -m 700 -o localsiem -g localsiem /opt/localsiem "$cDestination" /opt/localsiem/config /opt/localsiem/db /opt/localsiem/certificates /opt/localsiem/run /opt/localsiem/log /opt/localsiem/modules || return 1
  # Files that only exist in a working copy (they are not published on
  # GitHub) are copied when they are there.
  aCopy=(backend frontend deploy README.md doc)
  for vOptional in AGENTS.md CLAUDE.md RulesForThisProjectOnly.md Rules .gitignore; do
    if [ -e "$vSourcePath/$vOptional" ]; then
      aCopy+=("$vOptional")
    fi
  done
  tar -C "$vSourcePath" -cf "$vTemporaryPath/source.tar" "${aCopy[@]}" || return 1
  if systemctl is-active --quiet localsiem-web.service; then
    systemctl stop localsiem-web.service || return 1
  fi
  if systemctl is-active --quiet localsiem.service; then
    systemctl stop localsiem.service || return 1
  fi
  # The code is replaced as a whole: files of older versions do not stay.
  rm -rf -- "$cDestination/backend" "$cDestination/frontend" || return 1
  tar -C "$cDestination" -xf "$vTemporaryPath/source.tar" || return 1
  for vMovedFile in backend/server.py backend/security.py backend/requirements.txt frontend/index.html frontend/assets/app.css frontend/assets/app.js frontend/locales/en-GB.json frontend/locales/en-US.json frontend/locales/es-AR.json frontend/locales/es-ES.json; do
    if [ -f "$cDestination/$vMovedFile" ]; then
      rm -f -- "$cDestination/${vMovedFile#*/}" || return 1
    fi
  done
  for vObsoleteFile in InstallUpdateReinstall-Debian.sh install_reinstall_update.sh deploy/install_reinstall_update.sh agent.py; do
    rm -f -- "$cDestination/$vObsoleteFile" || return 1
  done
  for vOldDirectory in assets locales; do
    if [ -d "$cDestination/$vOldDirectory" ] && [ ! -L "$cDestination/$vOldDirectory" ]; then
      rmdir --ignore-fail-on-non-empty -- "$cDestination/$vOldDirectory" || return 1
    fi
  done
  for vDocument in CODE.md CODE.es-ES.md CODE.es-AR.md MANUAL.md MANUAL.es-ES.md MANUAL.es-AR.md README.es-ES.md README.es-AR.md; do
    if [ -f "$cDestination/doc/$vDocument" ]; then
      rm -f -- "$cDestination/$vDocument" || return 1
    fi
  done
  # Dependencies in a virtual environment of its own: pip never touches the
  # Python packages of the distribution that the client's services use.
  if [ ! -x "$cVenv/bin/python" ] || ! "$cVenv/bin/python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else 1)' 2>/dev/null; then
    rm -rf -- "$cVenv" || return 1
    python3 -m venv "$cVenv" || return 1
  fi
  (umask 022 && TMPDIR="$vTemporaryPath" "$cVenv/bin/python" -m pip install --upgrade --no-cache-dir --disable-pip-version-check -r "$cDestination/backend/requirements.txt" < /dev/null) || return 1
  PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/deploy/configure.py" "${aArguments[@]}" || return 1
  fGrantLogAccess || return 1
  chown -R localsiem:localsiem /opt/localsiem || return 1
  chmod 700 "$cDestination/backend/server.py" "$cDestination/backend/collector.py" "$cDestination/backend/manage.py" "$cDestination/deploy/install-update-reinstall-debian.sh" "$cDestination/deploy/install-update-reinstall-alpine.sh" "$cDestination/deploy/configure.py" || return 1
  install -m 644 "$cDestination/deploy/localsiem.service" /etc/systemd/system/localsiem.service || return 1
  install -m 644 "$cDestination/deploy/localsiem-web.service" /etc/systemd/system/localsiem-web.service || return 1
  install -m 644 "$cDestination/deploy/localsiem.logrotate" /etc/logrotate.d/localsiem || return 1
  systemctl daemon-reload || return 1
  systemctl enable localsiem.service localsiem-web.service || return 1
  systemctl restart localsiem.service || return 1
  systemctl restart localsiem-web.service || return 1
  sleep 5
  systemctl --no-pager --lines=0 status localsiem.service localsiem-web.service || true
  printf '\n%s\n' 'Installed modules:'
  runuser -u localsiem -- env PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/backend/manage.py" modules || true
  printf '\n%s\n' 'localSIEM doctor (as the localsiem user):'
  runuser -u localsiem -- env PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/backend/manage.py" doctor || true
  printf '\n%s\n' 'SOC:'
  if [ -s /opt/localsiem/config/soc-token ]; then
    if runuser -u localsiem -- env PYTHONDONTWRITEBYTECODE=1 "$cVenv/bin/python" "$cDestination/backend/manage.py" soc-test; then
      printf '%s\n' 'The SOC answered the first heartbeat.'
    else
      printf '%s\n' 'Warning: the SOC did not accept the heartbeat. Check --soc-url, --soc-token and the network.'
    fi
  else
    printf '%s\n' 'No SOC (it is optional): localSIEM works on its own and keeps its alerts as not sent. To connect it to a SOC: --soc-token, or Administration › SOC; only the alerts after that are sent.'
  fi
  vPort="$(sed -n 's/^LOCALSIEM_INSTALL_PORT=//p' /opt/localsiem/config/install.env)"
  printf '\n%s\n' "$vFinished" \
    "SIEM address for the SOC: https://$(sed -n 's/^LOCALSIEM_INSTALL_DOMAIN=//p' /opt/localsiem/config/install.env):$vPort" \
    'Credentials: /root/webapp-credentials.txt (mode 600). Log: /root/webapp-install.log (mode 600).'
  printf '\n%s\n' 'localSIEM is ready for its modules: install them from the web (Modules › Installable). After installing one, the web shows the command to run as root so that localSIEM can read its logs.'
  fGetTimestamp || return 1
}

if ! fMain "$@"; then
  printf '%s\n' 'localSIEM installation, update, reinstallation or uninstallation failed. Read /root/webapp-install.log.' >&2
  exit 1
fi
