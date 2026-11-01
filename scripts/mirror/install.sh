#!/usr/bin/env bash
# Installs the urMQTT release mirror on a Linux server with systemd
# (docs/PLAN.md, "Amendment: releases are mirrored on aldo.tech").
#
#   sudo scripts/mirror/install.sh [--dry-run]
#
# Run it from a checkout of the repository, as root. Every step prints what it
# does, and running it again changes nothing that is already in place:
#
#   user         urmqtt-mirror, a system user without login or home directory
#   directories  /var/www/aldotech.io/urmqtt/releases   (owned by that user, world
#                readable: the web server serves it as /urmqtt/releases/)
#                /usr/local/lib/urmqtt-mirror, /etc/urmqtt-mirror   (root)
#   script       /usr/local/lib/urmqtt-mirror/mirror-releases.py
#   public key   /etc/urmqtt-mirror/minisign.pub, copied from this checkout's
#                minisign.pub (the release key, docs/SECURITY.md)
#   units        /etc/systemd/system/urmqtt-mirror.service and .timer
#   systemd      daemon-reload, enable --now urmqtt-mirror.timer
#
# It never installs packages. minisign and python3 (3.10 or newer) must be there;
# if they are not it says what to install and stops before changing anything.
# --dry-run prints every step and changes nothing (it can run as a normal user).
set -euo pipefail

USER_NAME=urmqtt-mirror
WEB_ROOT=/var/www/aldotech.io/urmqtt/releases
LIB_DIR=/usr/local/lib/urmqtt-mirror
ETC_DIR=/etc/urmqtt-mirror
UNIT_DIR=/etc/systemd/system

usage() {
    echo "usage: sudo $0 [--dry-run]" >&2
    exit 2
}

DRY=0
if [[ $# -eq 1 && $1 == --dry-run ]]; then
    DRY=1
elif [[ $# -ne 0 ]]; then
    usage
fi

# Print a command the way a shell would need it, and run it unless --dry-run.
run() {
    if ((DRY)); then
        printf '[dry-run] %q' "$1"
    else
        printf '+ %q' "$1"
    fi
    printf ' %q' "${@:2}"
    printf '\n'
    if ((!DRY)); then "$@"; fi
}

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# A problem that must stop a real install; a dry run only reports it.
need() {
    if ((DRY)); then warn "$*"; else die "$*"; fi
}

# ---------------------------------------------------------------------------
# Checks, before anything is changed

if ((!DRY)) && [[ $(id -u) -ne 0 ]]; then
    die "run as root (sudo $0)"
fi

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
for f in "$REPO/scripts/mirror-releases.py" "$REPO/minisign.pub" "$HERE/urmqtt-mirror.service" "$HERE/urmqtt-mirror.timer"; do
    [[ -f $f ]] || die "$f is missing: run this from a checkout of the repository"
done

if ! command -v minisign >/dev/null 2>&1; then
    need "minisign is not installed; install it first (Debian/Ubuntu: apt install minisign) and run this again"
fi
# The service runs /usr/bin/python3 (urmqtt-mirror.service), so that is the one that counts.
if [[ ! -x /usr/bin/python3 ]] || ! /usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    need "/usr/bin/python3 3.10 or newer is needed (Debian/Ubuntu: apt install python3)"
fi
if ! command -v systemctl >/dev/null 2>&1; then
    need "systemctl not found: this installer needs a systemd host"
fi

# ---------------------------------------------------------------------------
# Helpers that only act when something differs

# ensure_dir MODE OWNER GROUP DIR
ensure_dir() {
    local mode=$1 owner=$2 group=$3 dir=$4 now
    now=$(stat -c '%a %U:%G' "$dir" 2>/dev/null || true)
    if [[ $now == "${mode#0} $owner:$group" ]]; then
        say "ok: $dir ($now)"
    else
        run install -d -m "$mode" -o "$owner" -g "$group" "$dir"
    fi
}

# install_file MODE SOURCE DESTINATION (owned by root)
install_file() {
    local mode=$1 src=$2 dst=$3
    if [[ -f $dst ]] && cmp -s "$src" "$dst" && [[ $(stat -c '%a %U:%G' "$dst") == "${mode#0} root:root" ]]; then
        say "ok: $dst is up to date"
    else
        run install -m "$mode" -o root -g root "$src" "$dst"
    fi
}

# ---------------------------------------------------------------------------
# Installation

if id -u "$USER_NAME" >/dev/null 2>&1; then
    say "ok: user $USER_NAME exists"
else
    run useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "urMQTT release mirror" "$USER_NAME"
fi

# The site's own directory may belong to someone else (the site publisher): only create it.
parent=$(dirname "$WEB_ROOT")
[[ -d $parent ]] || run install -d -m 0755 -o root -g root "$parent"
ensure_dir 0755 "$USER_NAME" "$USER_NAME" "$WEB_ROOT"
if [[ -d $WEB_ROOT ]] && [[ -n $(find "$WEB_ROOT" -maxdepth 2 ! -user "$USER_NAME" -print -quit 2>/dev/null || true) ]]; then
    warn "$WEB_ROOT holds entries that $USER_NAME does not own, so the mirror cannot update them" \
        "(chown -R $USER_NAME:$USER_NAME $WEB_ROOT)"
fi
ensure_dir 0755 root root "$LIB_DIR"
ensure_dir 0755 root root "$ETC_DIR"

install_file 0755 "$REPO/scripts/mirror-releases.py" "$LIB_DIR/mirror-releases.py"

# The release key is the trust anchor of the mirror: say loudly when it changes.
if [[ -f $ETC_DIR/minisign.pub ]] && ! cmp -s "$REPO/minisign.pub" "$ETC_DIR/minisign.pub"; then
    warn "replacing the installed release key"
    warn "  installed: $(head -n 1 "$ETC_DIR/minisign.pub")"
    warn "  new:       $(head -n 1 "$REPO/minisign.pub")"
fi
install_file 0644 "$REPO/minisign.pub" "$ETC_DIR/minisign.pub"
say "key: $(head -n 1 "$REPO/minisign.pub")  (compare the id with docs/SECURITY.md)"

install_file 0644 "$HERE/urmqtt-mirror.service" "$UNIT_DIR/urmqtt-mirror.service"
install_file 0644 "$HERE/urmqtt-mirror.timer" "$UNIT_DIR/urmqtt-mirror.timer"
run systemctl daemon-reload
run systemctl enable --now urmqtt-mirror.timer

say ""
if ((DRY)); then
    say "dry run: nothing was changed."
    exit 0
fi
say "done. Next runs:        systemctl list-timers urmqtt-mirror.timer"
say "Sync now (first run):   systemctl start urmqtt-mirror.service"
say "Log:                    journalctl -u urmqtt-mirror -e"
say "The web server must serve $WEB_ROOT as /urmqtt/releases/, and the site's publish step must leave it alone."
