#!/usr/bin/env bash
# Puts the urMQTT builder into the aldo.tech site generator (C1e, ADR-227).
#
#   scripts/deploy-builder-site.sh [--host HOST] [--site-dir DIR] [--chown USER:GROUP] [--with-demo] [--dry-run]
#
# What it does, in this order, and nothing else:
#   1. checks that build/builder/ exists (make builder), that the texts of all
#      15 site languages are in it, and that the page was built with the release
#      key (scripts/check-release-key.sh; never with the placeholder minisign.pub);
#   2. copies tools/builder/site/{products.py,products_i18n.py,apply_products.py}
#      to DIR on HOST (default: build, /opt/aldotech-site/site);
#   3. copies build/builder/ (without its standalone index.html) to DIR/urmqtt-builder/
#      (the generator copies it into the published tree as /urmqtt/builder/);
#   4. runs apply_products.py on DIR/build.py: a build.py it does not recognise is
#      refused, one that already has the pages is left alone.
#   --with-demo (D1b) also copies build/demo/ (make demo-page) and demo.py, apply_demo.py to the site and patches
#   build.py with apply_demo.py (after apply_products.py): the page "Try urMQTT live", unlisted until
#   URMQTT_DEMO_LISTED=1 is set for the build.
# It does not run the generator and does not publish: that is `publish.sh` on the
# server (as the site's publisher, which also leaves /urmqtt/releases/ alone).
# Use --site-dir with a scratch copy to try it first.
set -euo pipefail

HOST=build
SITE_DIR=/opt/aldotech-site/site
OWNER=
DRY=0
DEMO=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --host) HOST=$2; shift 2 ;;
        --site-dir) SITE_DIR=$2; shift 2 ;;
        --chown) OWNER=$2; shift 2 ;;
        --with-demo) DEMO=1; shift ;;
        --dry-run) DRY=1; shift ;;
        *) echo "usage: $0 [--host HOST] [--site-dir DIR] [--chown USER:GROUP] [--with-demo] [--dry-run]" >&2; exit 2 ;;
    esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP=$ROOT/build/builder
[[ -f $APP/app.js && -f $APP/manifest.json ]] || { echo "error: run 'make builder' first ($APP is not built)" >&2; exit 1; }
for lang in hr en de nl fr it es pt hu cs sk pl sl sr ru; do
    [[ -f $APP/i18n/$lang.json ]] || { echo "error: $APP/i18n/$lang.json is missing" >&2; exit 1; }
done

# The page verifies releases with the keys built into it (keys/release-keys.json): never deploy one
# that was built while minisign.pub was the placeholder (it would trust only the former test key).
"$ROOT/scripts/check-release-key.sh" >/dev/null || { echo "error: the release key is not set (scripts/check-release-key.sh); not deploying" >&2; exit 1; }
python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if m.get("release_key") else 1)' "$APP/manifest.json" \
    || { echo "error: $APP was built without the release key (minisign.pub was the placeholder): run make builder again" >&2; exit 1; }

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
if ((DEMO)); then
    DEMO_APP=$ROOT/build/demo
    [[ -f $DEMO_APP/app.js && -f $DEMO_APP/certs/demo-certs.zip ]] || { echo "error: run scripts/demo-certs.sh and 'make demo-page' first ($DEMO_APP lacks app.js or certs/demo-certs.zip)" >&2; exit 1; }
    run rsync -a "$ROOT/tools/builder/site/demo.py" "$ROOT/tools/builder/site/apply_demo.py" "$HOST:$SITE_DIR/"
    run rsync -a --delete --exclude=/index.html "$DEMO_APP/" "$HOST:$SITE_DIR/urmqtt-demo/"
    if [[ -n $OWNER ]]; then
        run "${SSH[@]}" chown -R "$OWNER" "$SITE_DIR/demo.py" "$SITE_DIR/apply_demo.py" "$SITE_DIR/urmqtt-demo"
    fi
    if ((DRY)); then
        echo "+ ssh $HOST python3 $SITE_DIR/apply_demo.py --check $SITE_DIR/build.py"
        "${SSH[@]}" python3 "$SITE_DIR/apply_demo.py" --check "$SITE_DIR/build.py" || true
    else
        "${SSH[@]}" python3 "$SITE_DIR/apply_demo.py" "$SITE_DIR/build.py"
    fi
fi
echo "done. Publish on the server with /opt/aldotech-site/publish.sh (as its publisher) to make the pages live."
