#!/usr/bin/env bash
# Installs the web part of the release mirror (C1e, ADR-227): the nginx container
# that serves the mirror directory on 127.0.0.1:18089 with a rate limit. Run it
# after scripts/mirror/install.sh, as root, from a checkout (or a copy of
# scripts/mirror/).
#
#   sudo scripts/mirror/install-web.sh [--dry-run]
#
# It installs /etc/urmqtt-mirror/nginx.conf, checks the configuration with the
# pinned image (`nginx -t`), installs and starts urmqtt-mirror-web.service and
# says what Caddy needs (scripts/mirror/caddy-apply.py). It does not touch the
# web server's configuration.
set -euo pipefail

DRY=0
[[ ${1:-} == --dry-run ]] && DRY=1
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ETC=/etc/urmqtt-mirror
UNIT=/etc/systemd/system/urmqtt-mirror-web.service
IMAGE=$(sed -n 's/^Environment=IMAGE=//p' "$HERE/urmqtt-mirror-web.service")

run() { printf '+ %s\n' "$*"; if ((!DRY)); then "$@"; fi; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

((DRY)) || [[ $(id -u) -eq 0 ]] || die "run as root"
command -v docker >/dev/null || die "docker is needed (the web server is a container)"
[[ -d /var/www/aldotech.io/urmqtt/releases ]] || die "run scripts/mirror/install.sh first (the mirror directory is missing)"

run install -d -m 0755 -o root -g root "$ETC"
run install -m 0644 -o root -g root "$HERE/nginx.conf" "$ETC/nginx.conf"
run docker pull "$IMAGE"
# The same image and the same file the service will use: a bad configuration stops here.
run docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    -v "$ETC/nginx.conf:/etc/nginx/nginx.conf:ro" -v /var/www/aldotech.io/urmqtt/releases:/srv/mirror:ro \
    "$IMAGE" nginx -t
run install -m 0644 -o root -g root "$HERE/urmqtt-mirror-web.service" "$UNIT"
run systemctl daemon-reload
run systemctl enable --now urmqtt-mirror-web.service
printf 'done. Try: curl -s -o /dev/null -w "%%{http_code}\\n" http://127.0.0.1:18089/releases.json\n'
echo "Caddy: python3 scripts/mirror/caddy-apply.py /etc/caddy/Caddyfile, then caddy validate and systemctl reload caddy."
