#!/usr/bin/env bash
# Issues an operator client certificate (O1, O2, docs/OPERATE.md) from the
# operational CA in a deploy directory. The identity must be listed in
# `acl.operator_ids` of that directory's config.toml.
#
#   scripts/gen-operator-cert.sh deploy/prod            -> services/operator.{pem,key}
#   scripts/gen-operator-cert.sh deploy/prod alice 365  -> services/alice.{pem,key}, 365 days
#
# Needs <dir>/ca.pem and <dir>/ca.key (for production, use a CA you keep
# offline and copy the result; never commit the key: services/ is git-ignored).
# The certificate carries the identity as its subject CN and as
# `URI:urn:urmqtt:service:<id>`, like the development operator and the
# production device-001.
set -euo pipefail

DIR=${1:?usage: gen-operator-cert.sh DIR [IDENTITY] [DAYS]}
ID=${2:-operator}
DAYS=${3:-825}
[[ $ID =~ ^[A-Za-z0-9._:-]+$ ]] || { echo "error: identity must match [A-Za-z0-9._:-]+" >&2; exit 2; }
[[ -f "$DIR/ca.pem" && -f "$DIR/ca.key" ]] || { echo "error: $DIR/ca.pem and ca.key are required" >&2; exit 1; }

# OpenSSL >= 3 (LibreSSL cannot verify urn: URI SANs); prefer Homebrew's.
is_openssl3() { command -v "$1" >/dev/null 2>&1 && "$1" version | grep -q '^OpenSSL [3-9]'; }
OPENSSL=${OPENSSL:-}
if [[ -z "$OPENSSL" ]]; then
    for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
        if is_openssl3 "$c"; then OPENSSL=$c; break; fi
    done
fi
is_openssl3 "${OPENSSL:-none}" || { echo "error: OpenSSL >= 3 not found (set OPENSSL=)" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
umask 077
mkdir -p "$DIR/services"
OUT="$DIR/services/$ID"
[[ ! -e "$OUT.pem" && ! -e "$OUT.key" ]] || { echo "error: $OUT.pem/.key exist; remove them first" >&2; exit 1; }

cat > "$TMP/ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:urmqtt:service:$ID
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT.key" 2>/dev/null
SUBJ_O=$("$OPENSSL" x509 -in "$DIR/ca.pem" -noout -subject -nameopt multiline | sed -n 's/^ *organizationName *= *//p' | head -1)
"$OPENSSL" req -new -key "$OUT.key" -subj "/O=${SUBJ_O:-urMQTT}/CN=$ID" -out "$TMP/req.csr"
# A random 127-bit serial (top bit clear, so it stays positive).
SERIAL=$("$OPENSSL" rand -hex 16 | sed 's/^./7/')
"$OPENSSL" x509 -req -in "$TMP/req.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -set_serial "0x$SERIAL" \
    -sha256 -extfile "$TMP/ext" -days "$DAYS" -out "$OUT.pem" 2>/dev/null
"$OPENSSL" verify -CAfile "$DIR/ca.pem" "$OUT.pem" >/dev/null
echo "operator identity '$ID': $OUT.pem, $OUT.key ($DAYS days, serial $SERIAL)"
echo "list it in acl.operator_ids of $DIR/config.toml and rebuild the image"
