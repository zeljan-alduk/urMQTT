#!/usr/bin/env bash
# shellcheck disable=SC2015 # `cond && ok ... || bad ...` is intended: ok and bad only print, never fail
# Host test of scripts/pki.sh (ROADMAP NOW-3, docs/PKI.md). Smoke-style but it
# boots nothing: it makes a PKI in a temp directory (CA and control keys under a
# test passphrase), issues devices and services (also from a device's own CSR),
# revokes one, adds a second CA, runs `pki.sh check`, and then packs a
# configuration made of its output with `urmqtt-config pack` into the template
# ISO and the raw image of `make dist ENV=release` / `make template` when they
# are in build/ (else into a slot only), and reads it back with `show`/`verify`.
#
#   scripts/test-pki.sh            (TEMPLATE=path.iso RAW=path.img to choose the images)
#
# Every key here is a THROWAWAY key in a temp directory.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PKI=$ROOT/scripts/pki.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export URMQTT_CA_PASSPHRASE=throwaway-test-passphrase
fails=0
ok() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails + 1)); }
must() { local what=$1; shift; if out=$("$@" 2>&1); then ok "$what"; else bad "$what"; printf '    %s\n' "$out"; fi; }
mustnot() { local what=$1; shift; if out=$("$@" 2>&1); then bad "$what (it succeeded)"; printf '    %s\n' "$out"; else ok "$what"; fi; }
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

(cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool --bin urmqtt-config)
TOOL=${URMQTT_CONFIG:-$ROOT/target/debug/urmqtt-config}
export URMQTT_CONFIG=$TOOL
OPENSSL=${OPENSSL:-}
if [[ -z $OPENSSL ]]; then
    for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
        if command -v "$c" >/dev/null 2>&1 && "$c" version | grep -q '^OpenSSL [3-9]'; then OPENSSL=$c; break; fi
    done
fi

P=$TMP/pki
must "init: CA, server (DNS + IP), control key" "$PKI" init "$P" --org "Example Fleet" --dns mqtt.example.org --ip 203.0.113.10
mustnot "init refuses a directory that is not empty" "$PKI" init "$P" --dns x.example.org
for f in offline/ca.key offline/control.key deploy/server.key; do
    [[ $(mode "$P/$f") == 600 ]] && ok "$f is 0600" || bad "$f is $(mode "$P/$f"), not 0600"
done
grep -q 'ENCRYPTED PRIVATE KEY' "$P/offline/ca.key" && ok "the CA key is passphrase-protected" || bad "the CA key is not encrypted"
grep -q 'ENCRYPTED' "$P/deploy/server.key" && bad "the server key is encrypted (the VM cannot decrypt it)" || ok "the server key is not encrypted"
"$OPENSSL" x509 -in "$P/deploy/server.pem" -noout -ext subjectAltName | grep -q 'DNS:mqtt.example.org, IP Address:203.0.113.10' \
    && ok "server SAN: DNS and IP" || bad "server SAN"

must "device certificate" "$PKI" device "$P" device-001
mustnot "an existing device is not overwritten" "$PKI" device "$P" device-001
mustnot "an identity with a / is refused" "$PKI" device "$P" "a/b"
mustnot "an identity starting with \$ is refused" "$PKI" device "$P" "\$SYS"
must "service certificate (backend)" "$PKI" service "$P" backend
must "service certificate (operator)" "$PKI" service "$P" operator
[[ $(mode "$P/devices/device-001.key") == 600 ]] && ok "device key is 0600" || bad "device key mode"
subj=$("$OPENSSL" x509 -in "$P/devices/device-001.pem" -noout -subject -nameopt RFC2253)
san=$("$OPENSSL" x509 -in "$P/devices/device-001.pem" -noout -ext subjectAltName)
[[ $subj == *"CN=device-001"* && $san == *"URI:urn:urmqtt:device:device-001"* ]] && ok "device identity: CN and SAN URI" || bad "device identity: $subj / $san"
"$OPENSSL" x509 -in "$P/services/operator.pem" -noout -ext subjectAltName | grep -q 'URI:urn:urmqtt:service:operator' \
    && ok "service identity: SAN URI urn:urmqtt:service:" || bad "service SAN"

# A key born on the device: only its CSR comes to the CA.
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/dev42.key" 2>/dev/null
"$OPENSSL" req -new -key "$TMP/dev42.key" -subj "/CN=device-042" -out "$TMP/dev42.csr"
must "sign-csr: a device's own CSR" "$PKI" sign-csr "$P" "$TMP/dev42.csr"
[[ -f $P/devices/device-042.pem && ! -e $P/devices/device-042.key ]] && ok "sign-csr leaves the key on the device" || bad "sign-csr files"
"$OPENSSL" genpkey -algorithm ed25519 -out "$TMP/ed.key" 2>/dev/null
"$OPENSSL" req -new -key "$TMP/ed.key" -subj "/CN=device-043" -out "$TMP/ed.csr"
mustnot "sign-csr refuses a key that is not P-256" "$PKI" sign-csr "$P" "$TMP/ed.csr"
"$OPENSSL" req -new -key "$TMP/dev42.key" -subj "/CN=dev#1" -out "$TMP/badcn.csr"
mustnot "sign-csr refuses an unusable CN" "$PKI" sign-csr "$P" "$TMP/badcn.csr"

must "revoke a device" "$PKI" revoke "$P" "$P/devices/device-042.pem"
serial=$("$OPENSSL" x509 -in "$P/devices/device-042.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
grep -qx "$serial" "$P/deploy/revoked.txt" && ok "its serial is in revoked.txt" || bad "revoked.txt"
"$PKI" revoke "$P" --serial "$serial" | grep -q "already revoked" && ok "revoking twice is a no-op" || bad "revoke twice"
must "a second operational CA (rotation)" "$PKI" ca "$P" ca-2
[[ $(wc -l <"$P/issued.tsv") -eq 5 ]] && ok "issued.tsv lists the 5 leaf certificates (server, 3 devices and services by key, 1 by CSR)" || bad "issued.tsv: $(wc -l <"$P/issued.tsv") lines"

# A deploy/prod/ made of the output, with the ACL that names the identities.
D=$TMP/prod
mkdir -p "$D"
cp "$P"/deploy/{ca.pem,ca-2.pem,server.pem,server.key,control.pub,revoked.txt} "$D/"
{
    sed 's/^operational = \["ca.pem"\]/operational = ["ca.pem", "ca-2.pem"]/' "$P/deploy/config-snippet.toml"
    printf '\n[acl]\nservice_ids = ["backend"]\noperator_ids = ["operator"]\n'
} >"$D/config.toml"
must "check: the deploy directory with its config.toml" "$PKI" check "$D"
must "check: the PKI directory itself (its deploy/)" "$PKI" check "$P"
cp "$P/offline/ca.key" "$D/"
mustnot "check: a CA private key in the deploy directory fails" "$PKI" check "$D"
rm "$D/ca.key"
cp "$P/deploy/server.key" "$TMP/server.key.good"
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$D/server.key" 2>/dev/null
mustnot "check: a server key that does not belong to the certificate fails" "$PKI" check "$D"
cp "$TMP/server.key.good" "$D/server.key"

# The kernel's own rules, through pack: a server certificate that expires within
# tls.min_server_cert_days (60) is refused, by `check` too.
must "init with a 30-day server certificate" "$PKI" init "$TMP/short" --dns short.example.org --server-days 30 --no-passphrase
mustnot "check: a server certificate valid for 30 days is refused (min_server_cert_days)" "$PKI" check "$TMP/short"
reason=$("$PKI" check "$TMP/short" 2>&1 || true)
[[ $reason == *"fewer than the required 60"* ]] && ok "... with pack's reason" || bad "pack's reason not shown"

# Pack the configuration into the release images (no QEMU boot here).
v=$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo unknown)
TEMPLATE=${TEMPLATE:-$ROOT/build/urmqtt-template-$v-universal.iso}
RAW=${RAW:-$ROOT/build/urmqtt-template-$v-universal.img}
must "pack into a slot" "$TOOL" pack "$D/config.toml" --env prod --out-slot "$TMP/slot"
if [[ -f $TEMPLATE ]]; then
    must "pack --iso into the template" "$TOOL" pack "$D/config.toml" --env prod --iso "$TEMPLATE" --out "$TMP/mine.iso"
    must "verify the configured ISO as a release kernel would" "$TOOL" verify "$TMP/mine.iso"
    "$TOOL" show "$TMP/mine.iso" | grep -q 'mqtt.example.org' && ok "show: the server certificate is in the image" || bad "show"
else
    echo "skip: no template ISO at $TEMPLATE (make template or make dist ENV=release)"
fi
if [[ -f $RAW ]]; then
    must "pack --image into the raw disk image" "$TOOL" pack "$D/config.toml" --env prod --image "$RAW" --out "$TMP/mine.img"
    must "verify the configured raw image" "$TOOL" verify "$TMP/mine.img"
else
    echo "skip: no raw image at $RAW (make dist ENV=release)"
fi

if ((fails)); then echo "test-pki: $fails failure(s)"; exit 1; fi
echo "test-pki: all passed"
