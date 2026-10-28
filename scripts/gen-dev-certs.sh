#!/usr/bin/env bash
# Generates DEVELOPMENT certificates for urMQTT into deploy/dev/.
#
#   deploy/dev/ca.pem, ca.key            dev CA (ECDSA P-256)
#   deploy/dev/server.pem, server.key    broker certificate (localhost, 127.0.0.1)
#   deploy/dev/devices/device-00{1,2,3}.{pem,key}   valid device certificates
#   deploy/dev/negative/                 certificates that MUST be rejected:
#     rogue-ca.pem, rogue-device.{pem,key}   device signed by an unknown CA
#     expired-device.{pem,key}               valid chain, notAfter in the past
#
# Never use these for anything but local testing. They are git-ignored (ADR-004).
# Usage: scripts/gen-dev-certs.sh [--force]
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=deploy/dev
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if [[ -f "$OUT/ca.pem" && $FORCE -eq 0 ]]; then
    echo "dev certificates already exist in $OUT (use --force to regenerate)"
    exit 0
fi

command -v openssl >/dev/null || { echo "error: openssl not found" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT/devices" "$OUT/negative"
umask 077

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# ca <name> <subject> <out-prefix>
ca() {
    key "$3.key"
    openssl req -x509 -new -key "$3.key" -sha256 -days 3650 -subj "$2" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$3.pem"
}

# leaf <ca-prefix> <out-prefix> <cn> <extfile> [extra x509 args...]
leaf() {
    local ca=$1 out=$2 cn=$3 ext=$4
    shift 4
    key "$out.key"
    openssl req -new -key "$out.key" -subj "/O=urMQTT dev/CN=$cn" -out "$TMP/req.csr"
    openssl x509 -req -in "$TMP/req.csr" -CA "$ca.pem" -CAkey "$ca.key" \
        -set_serial "0x$(openssl rand -hex 16)" -sha256 -extfile "$ext" "$@" -out "$out.pem" 2>/dev/null
}

cat > "$TMP/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:urmqtt.local,IP:127.0.0.1
authorityKeyIdentifier=keyid
EOF

device_ext() {
    cat > "$TMP/device.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:urmqtt:device:$1
authorityKeyIdentifier=keyid
EOF
    echo "$TMP/device.ext"
}

echo "generating dev CA"
ca dev "/O=urMQTT dev/CN=urMQTT Dev CA" "$OUT/ca"

echo "generating server certificate"
leaf "$OUT/ca" "$OUT/server" "localhost" "$TMP/server.ext" -days 825

for id in device-001 device-002 device-003; do
    echo "generating $id"
    leaf "$OUT/ca" "$OUT/devices/$id" "$id" "$(device_ext "$id")" -days 825
done

echo "generating negative-test certificates"
ca rogue "/O=urMQTT rogue/CN=Rogue CA" "$TMP/rogue-ca"
cp "$TMP/rogue-ca.pem" "$OUT/negative/rogue-ca.pem"
leaf "$TMP/rogue-ca" "$OUT/negative/rogue-device" "device-001" "$(device_ext device-001)" -days 825
leaf "$OUT/ca" "$OUT/negative/expired-device" "device-002" "$(device_ext device-002)" \
    -not_before 20200101000000Z -not_after 20210101000000Z

# Sanity checks: the chain verifies, the negatives fail as intended.
openssl verify -CAfile "$OUT/ca.pem" "$OUT/server.pem" "$OUT"/devices/*.pem >/dev/null
if openssl verify -CAfile "$OUT/ca.pem" "$OUT/negative/rogue-device.pem" >/dev/null 2>&1; then
    echo "error: rogue device unexpectedly verifies" >&2; exit 1
fi
if openssl verify -CAfile "$OUT/ca.pem" "$OUT/negative/expired-device.pem" >/dev/null 2>&1; then
    echo "error: expired device unexpectedly verifies" >&2; exit 1
fi

echo "done: dev certificates in $OUT (verified)"
