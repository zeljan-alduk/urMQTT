#!/usr/bin/env bash
# Generates DEVELOPMENT certificates for urMQTT into deploy/dev/.
#
#   deploy/dev/ca.pem, ca.key            dev CA (ECDSA P-256)
#   deploy/dev/server.pem, server.key    broker certificate (localhost, 127.0.0.1)
#   deploy/dev/devices/device-00{1,2,3}.{pem,key}   valid device certificates
#   deploy/dev/negative/                 certificates that MUST be rejected:
#     rogue-ca.pem, rogue-device.{pem,key}   device signed by an unknown CA
#     expired-device.{pem,key}               valid chain, notAfter in the past
#     revoked-device.{pem,key}               valid, but its serial is in revoked.txt
#   deploy/dev/services/backend.{pem,key}  service identity "backend"
#   deploy/dev/revoked.txt                 revoked serials (tls.revocation_list)
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

# OpenSSL >= 3 is required. LibreSSL (macOS /usr/bin/openssl) cannot verify
# URI SANs of the form urn:..., so prefer Homebrew's OpenSSL when present.
is_openssl3() { command -v "$1" >/dev/null 2>&1 && "$1" version | grep -q '^OpenSSL [3-9]'; }
if [[ -n "${OPENSSL:-}" ]]; then
    is_openssl3 "$OPENSSL" || { echo "error: OPENSSL=$OPENSSL is not OpenSSL >= 3" >&2; exit 1; }
else
    OPENSSL=
    for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
        if is_openssl3 "$c"; then
            OPENSSL=$c
            break
        fi
    done
fi
if [[ -z "$OPENSSL" ]]; then
    echo "error: OpenSSL >= 3 not found (LibreSSL is not supported); install it or set OPENSSL=/path/to/openssl" >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT/devices" "$OUT/negative" "$OUT/services"
umask 077

key() { "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# ca <name> <subject> <out-prefix>
ca() {
    key "$3.key"
    "$OPENSSL" req -x509 -new -key "$3.key" -sha256 -days 3650 -subj "$2" \
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
    "$OPENSSL" req -new -key "$out.key" -subj "/O=urMQTT dev/CN=$cn" -out "$TMP/req.csr"
    "$OPENSSL" x509 -req -in "$TMP/req.csr" -CA "$ca.pem" -CAkey "$ca.key" \
        -set_serial "0x$("$OPENSSL" rand -hex 16)" -sha256 -extfile "$ext" "$@" -out "$out.pem" \
        2>"$TMP/x509.log" || { cat "$TMP/x509.log" >&2; return 1; }
}

# expired_leaf <ca-prefix> <out-prefix> <cn> <extfile>
# Uses `openssl ca`: `x509 -not_before/-not_after` only exist in OpenSSL >= 3.4,
# while CI runners ship OpenSSL 3.0 (Ubuntu) and LibreSSL (macOS).
expired_leaf() {
    local ca=$1 out=$2 cn=$3 ext=$4 db="$TMP/cadb"
    mkdir -p "$db/new"
    : > "$db/index.txt"
    "$OPENSSL" rand -hex 16 > "$db/serial"
    cat > "$db/ca.cnf" <<CNF
[ca]
default_ca = dev
[dev]
database = $db/index.txt
new_certs_dir = $db/new
serial = $db/serial
default_md = sha256
policy = any
unique_subject = no
[any]
organizationName = optional
commonName = supplied
CNF
    key "$out.key"
    "$OPENSSL" req -new -key "$out.key" -subj "/O=urMQTT dev/CN=$cn" -out "$TMP/req.csr"
    "$OPENSSL" ca -batch -config "$db/ca.cnf" -cert "$ca.pem" -keyfile "$ca.key" \
        -startdate 20200101000000Z -enddate 20210101000000Z \
        -extfile "$ext" -notext -in "$TMP/req.csr" -out "$out.pem" \
        2>"$TMP/ca.log" || { cat "$TMP/ca.log" >&2; return 1; }
}

cat > "$TMP/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:urmqtt.local,IP:127.0.0.1
authorityKeyIdentifier=keyid
EOF

service_ext() {
    cat > "$TMP/service.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:urmqtt:service:$1
authorityKeyIdentifier=keyid
EOF
    echo "$TMP/service.ext"
}

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

echo "generating service certificate (backend)"
leaf "$OUT/ca" "$OUT/services/backend" "backend" "$(service_ext backend)" -days 825

echo "generating negative-test certificates"
ca rogue "/O=urMQTT rogue/CN=Rogue CA" "$TMP/rogue-ca"
cp "$TMP/rogue-ca.pem" "$OUT/negative/rogue-ca.pem"
leaf "$TMP/rogue-ca" "$OUT/negative/rogue-device" "device-001" "$(device_ext device-001)" -days 825
expired_leaf "$OUT/ca" "$OUT/negative/expired-device" "device-002" "$(device_ext device-002)"
leaf "$OUT/ca" "$OUT/negative/revoked-device" "device-004" "$(device_ext device-004)" -days 825
"$OPENSSL" x509 -in "$OUT/negative/revoked-device.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' > "$OUT/revoked.txt"

echo "verifying with $("$OPENSSL" version)"
# Sanity checks: the chain verifies, the negatives fail as intended.
"$OPENSSL" verify -CAfile "$OUT/ca.pem" "$OUT/server.pem" "$OUT"/devices/*.pem "$OUT/services/backend.pem" >/dev/null
if "$OPENSSL" verify -CAfile "$OUT/ca.pem" "$OUT/negative/rogue-device.pem" >/dev/null 2>&1; then
    echo "error: rogue device unexpectedly verifies" >&2; exit 1
fi
if "$OPENSSL" verify -CAfile "$OUT/ca.pem" "$OUT/negative/expired-device.pem" >/dev/null 2>&1; then
    echo "error: expired device unexpectedly verifies" >&2; exit 1
fi

echo "done: dev certificates in $OUT (verified)"
