#!/usr/bin/env bash
# Puts the urMQTT builder into the aldo.tech site generator (C1e, ADR-227).
#
#   scripts/deploy-builder-site.sh [--host HOST] [--site-dir DIR] [--chown USER:GROUP] [--dry-run]
#
# What it does, in this order, and nothing else:
#   1. checks that build/builder/ exists (make builder) and that the texts of all
#      15 site languages are in it;
#   2. copies tools/builder/site/{products.py,products_i18n.py,apply_products.py}
#      to DIR on HOST (default: build, /opt/aldotech-site/site);
#   3. copies build/builder/ (without its standalone index.html) to DIR/urmqtt-builder/
#      (the generator copies it into the published tree as /urmqtt/builder/);
#   4. runs apply_products.py on DIR/build.py: a build.py it does not recognise is
#      refused, one that already has the pages is left alone.
# It does not run the generator and does not publish: that is `publish.sh` on the
# server (as the site's publisher, which also leaves /urmqtt/releases/ alone).
# Use --site-dir with a scratch copy to try it first.
set -euo pipefail

HOST=build
SITE_DIR=/opt/aldotech-site/site
OWNER=
DRY=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --host) HOST=$2; shift 2 ;;
        --site-dir) SITE_DIR=$2; shift 2 ;;
        --chown) OWNER=$2; shift 2 ;;
        --dry-run) DRY=1; shift ;;
        *) echo "usage: $0 [--host HOST] [--site-dir DIR] [--chown USER:GROUP] [--dry-run]" >&2; exit 2 ;;
    esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP=$ROOT/build/builder
[[ -f $APP/app.js && -f $APP/manifest.json ]] || { echo "error: run 'make builder' first ($APP is not built)" >&2; exit 1; }
for lang in hr en de nl fr it es pt hu cs sk pl sl sr ru; do
    [[ -f $APP/i18n/$lang.json ]] || { echo "error: $APP/i18n/$lang.json is missing" >&2; exit 1; }
done

run() { printf '+ %s\n' "$*"; if ((!DRY)); then "$@"; fi; }
SSH=(ssh -o BatchMode=yes "$HOST")

run rsync -a "$ROOT/tools/builder/site/products.py" "$ROOT/tools/builder/site/products_i18n.py" "$ROOT/tools/builder/site/apply_products.py" "$HOST:$SITE_DIR/"
# The standalone test page (index.html) is not part of the site: the site has its own pages around the application.
run rsync -a --delete --delete-excluded --exclude=/index.html "$APP/" "$HOST:$SITE_DIR/urmqtt-builder/"
# The files should belong to the site's own user (macOS's rsync has no --chown, so it is done on the server).
if [[ -n $OWNER ]]; then
    run "${SSH[@]}" chown -R "$OWNER" "$SITE_DIR/products.py" "$SITE_DIR/products_i18n.py" "$SITE_DIR/apply_products.py" "$SITE_DIR/urmqtt-builder"
fi
if ((DRY)); then
    echo "+ ssh $HOST python3 $SITE_DIR/apply_products.py --check $SITE_DIR/build.py"
    "${SSH[@]}" python3 "$SITE_DIR/apply_products.py" --check "$SITE_DIR/build.py" || true
else
    "${SSH[@]}" python3 "$SITE_DIR/apply_products.py" "$SITE_DIR/build.py"
fi
echo "done. Publish on the server with /opt/aldotech-site/publish.sh (as its publisher) to make the pages live."
