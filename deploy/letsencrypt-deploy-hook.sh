#!/bin/bash

set -euo pipefail

# certbot deploy hook installed by localSIEM: after every renewal of the
# certificate of @DOMAIN@ (the client's own web), localSIEM gets a copy and
# localsiem-web restarts to use it.

cDomain='@DOMAIN@'
cTarget='/opt/localsiem/certificates'
vTemporary=''

fCleanup() {
  if [ -n "$vTemporary" ] && [ -d "$vTemporary" ]; then
    rm -rf -- "$vTemporary"
  fi
}

trap fCleanup EXIT

fMain() {
  local vLineage="${RENEWED_LINEAGE:-/etc/letsencrypt/live/$cDomain}"
  case " ${RENEWED_DOMAINS:-$cDomain} " in
    *" $cDomain "*)
      ;;
    *)
      return 0
      ;;
  esac
  if [ ! -f "$vLineage/fullchain.pem" ] || [ ! -f "$vLineage/privkey.pem" ] || [ ! -d "$cTarget" ]; then
    return 0
  fi
  vTemporary="$(mktemp -d "$cTarget/.renew.XXXXXX")"
  install -m 600 -o localsiem -g localsiem "$vLineage/fullchain.pem" "$vTemporary/fullchain.pem"
  install -m 600 -o localsiem -g localsiem "$vLineage/privkey.pem" "$vTemporary/privkey.pem"
  mv -f -- "$vTemporary/fullchain.pem" "$cTarget/fullchain.pem"
  mv -f -- "$vTemporary/privkey.pem" "$cTarget/privkey.pem"
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl try-restart localsiem-web.service
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service localsiem-web --ifstarted restart
  fi
}

if ! fMain; then
  echo "localSIEM: the renewed certificate could not be copied." >&2
  exit 1
fi
