#!/usr/bin/env bash
# Packs the public demo broker's configuration (deploy/demo/config.toml, D1) into a copy of a template ISO.
#
#   scripts/demo-pack.sh --template ISO --out ISO --bridge CIDR [--static ADDRESS/PREFIX GATEWAY] [--tool PATH]
#
#   --bridge CIDR     the ONLY source allowed on the plaintext port, normally the bridge host as a /32
#                     (203.0.113.7/32). Required: the placeholder in the file is a network that exists nowhere.
#   --static A/P GW   a fixed address instead of DHCP (a VPS usually needs it)
#   --template ISO    urmqtt-template-<version>-universal.iso of a release (or `make template`)
#   --tool PATH       urmqtt-config (default target/debug/urmqtt-config, built if missing)
#
# Needs deploy/demo/pki/ from scripts/demo-certs.sh. Prints the configuration fingerprint (the kernel prints the
# same one at every boot). The ISO is not a release ISO: it has its own SHA-256.
set -euo pipefail

cd "$(dirname "$0")/.."
TEMPLATE="" OUT="" BRIDGE="" ADDR="" GW="" TOOL=target/debug/urmqtt-config PKI=deploy/demo/pki
while [[ $# -gt 0 ]]; do
    case $1 in
        --template) TEMPLATE=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --bridge) BRIDGE=$2; shift 2 ;;
        --static) ADDR=$2; GW=$3; shift 3 ;;
        --tool) TOOL=$2; shift 2 ;;
        --pki) PKI=$2; shift 2 ;;
        *) echo "usage: $0 --template ISO --out ISO --bridge CIDR [--static ADDRESS/PREFIX GATEWAY] [--tool PATH]" >&2; exit 2 ;;
    esac
done
[[ -n $TEMPLATE && -n $OUT && -n $BRIDGE ]] || { echo "error: --template, --out and --bridge are required" >&2; exit 2; }
[[ $BRIDGE =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || { echo "error: --bridge must be a.b.c.d/len" >&2; exit 2; }
[[ $BRIDGE != 0.0.0.0/* ]] || { echo "error: --bridge must not be 0.0.0.0/..." >&2; exit 2; }
[[ -f $TEMPLATE ]] || { echo "error: template '$TEMPLATE' not found" >&2; exit 1; }
for f in ca.pem server.pem server.key; do
    [[ -f $PKI/$f ]] || { echo "error: $PKI/$f missing (run scripts/demo-certs.sh)" >&2; exit 1; }
done
if [[ ! -x $TOOL ]]; then
    [[ $TOOL == target/debug/urmqtt-config ]] || { echo "error: $TOOL not found" >&2; exit 1; }
    cargo build -q --locked -p urmqtt-config-tool
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Two exact line replacements; anything else in the file stays as reviewed.
BRIDGE="$BRIDGE" ADDR="$ADDR" GW="$GW" python3 -I - deploy/demo/config.toml "$WORK/config.toml" <<'PY'
import os, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text, n = re.subn(r'^allow_from = \["10\.0\.0\.0/24"\].*$', 'allow_from = ["%s"]' % os.environ["BRIDGE"], text, flags=re.M)
assert n == 1, "allow_from placeholder not found"
if os.environ["ADDR"]:
    text, n = re.subn(r'^mode = "dhcp".*$', 'mode = "static"\naddress = "%s"\ngateway = "%s"' % (os.environ["ADDR"], os.environ["GW"]), text, count=1, flags=re.M)
    assert n == 1, "network.mode line not found"
open(sys.argv[2], "w", encoding="utf-8").write(text)
PY
"$TOOL" pack "$WORK/config.toml" --root "$PKI" --iso "$TEMPLATE" --out "$OUT"
"$TOOL" verify "$OUT"
"$TOOL" show "$OUT"
echo "demo image: $OUT (plaintext allowed only from $BRIDGE${ADDR:+, static $ADDR via $GW})"
