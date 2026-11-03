#!/usr/bin/env bash
# Generates the certificates of the PUBLIC DEMO broker (D1) into deploy/demo/pki/ (git-ignored).
#
#   scripts/demo-certs.sh [--out DIR] [--host NAME] [--count N] [--force]
#
#   ca.pem, ca.key              client CA. Its PRIVATE KEY IS PUBLISHED ON PURPOSE (see below).
#   server-ca.pem               CA that signed the broker's certificate; its private key is DELETED after use,
#                               so nobody can mint a broker certificate that clients trusting server-ca.pem accept
#   server.pem, server.key      the broker's certificate (SAN: --host, default demo-mqtt.aldo.tech) and key.
#                               NEVER published; it goes into the image only
#   clients/web.{pem,key}       the identity of the browser page ("web"): talk to the page's topics with mosquitto
#   clients/demo-001..N.{pem,key}   N downloadable client certificates (CN = id; rights: demo/<id>/#)
#   download/demo-certs.zip     what the page offers: README, ca.pem, server-ca.pem, ca.key and every client pair
#   download/                   plus each file on its own
#
# WHY THE CLIENT CA KEY IS PUBLIC. The demo broker is a toy that anyone may use. A public CA key means anyone can
# mint any client certificate: mutual TLS here shows how a device connects, it authenticates nobody. What keeps the
# toy harmless is the broker's configuration (deploy/demo/config.toml): the ACL demo/{id}/# and no service, operator
# or control rights for any identity, small limits, RAM only. The key is generated for this one deployment and for
# nothing else: NEVER reuse the CA, the files or the ids anywhere (not on a real broker, not in a test fleet).
#
# The broker certificate is signed by a SEPARATE CA whose key is deleted, so a client that trusts server-ca.pem
# (mosquitto --cafile server-ca.pem) really talks to this broker, not to someone who downloaded ca.key.
#
# Needs OpenSSL >= 3 (not LibreSSL), python3 for the zip. Run again with --force to start over (new CAs, so the
# image must be re-packed and the download replaced).
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=deploy/demo/pki
HOST=demo-mqtt.aldo.tech
COUNT=20
FORCE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --out) OUT=$2; shift 2 ;;
        --host) HOST=$2; shift 2 ;;
        --count) COUNT=$2; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) echo "usage: $0 [--out DIR] [--host NAME] [--count N] [--force]" >&2; exit 2 ;;
    esac
done
[[ $COUNT =~ ^[0-9]+$ && $COUNT -ge 1 && $COUNT -le 999 ]] || { echo "error: --count must be 1..999" >&2; exit 2; }
[[ $HOST =~ ^[A-Za-z0-9.-]+$ ]] || { echo "error: --host must be a DNS name" >&2; exit 2; }

if [[ -f $OUT/ca.pem && $FORCE -eq 0 ]]; then
    echo "demo certificates already exist in $OUT (use --force to start over)"
    exit 0
fi

is_openssl3() { command -v "$1" >/dev/null 2>&1 && "$1" version | grep -q '^OpenSSL [3-9]'; }
if [[ -n "${OPENSSL:-}" ]]; then
    is_openssl3 "$OPENSSL" || { echo "error: OPENSSL=$OPENSSL is not OpenSSL >= 3" >&2; exit 1; }
else
    OPENSSL=
    for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
        if is_openssl3 "$c"; then OPENSSL=$c; break; fi
    done
fi
[[ -n $OPENSSL ]] || { echo "error: OpenSSL >= 3 not found (set OPENSSL=/path/to/openssl)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "error: python3 is needed for the zip" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
rm -rf "$OUT"
mkdir -p "$OUT/clients" "$OUT/download"
umask 077

key() { "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# A CA valid for two years (the packer wants at least 365 days); the leaves are valid for one year.
ca() { # ca <subject> <out-prefix>
    key "$2.key"
    "$OPENSSL" req -x509 -new -key "$2.key" -sha256 -days 730 -subj "$1" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" -out "$2.pem"
}
leaf() { # leaf <ca-prefix> <out-prefix> <cn> <extfile>
    key "$2.key"
    "$OPENSSL" req -new -key "$2.key" -subj "/O=urMQTT public demo/CN=$3" -out "$TMP/req.csr"
    "$OPENSSL" x509 -req -in "$TMP/req.csr" -CA "$1.pem" -CAkey "$1.key" \
        -set_serial "0x$("$OPENSSL" rand -hex 16)" -sha256 -extfile "$4" -days 365 -out "$2.pem" 2>"$TMP/x509.log" \
        || { cat "$TMP/x509.log" >&2; return 1; }
}

echo "generating the client CA (key published) and the broker CA (key deleted after use)"
ca "/O=urMQTT public demo/CN=urMQTT PUBLIC DEMO client CA (key is public)" "$OUT/ca"
ca "/O=urMQTT public demo/CN=urMQTT public demo broker CA" "$TMP/server-ca"

cat > "$TMP/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HOST
authorityKeyIdentifier=keyid
EOF
leaf "$TMP/server-ca" "$OUT/server" "$HOST" "$TMP/server.ext"
cp "$TMP/server-ca.pem" "$OUT/server-ca.pem"
# the broker CA's private key lives in $TMP only and goes with it

client_ext() {
    cat > "$TMP/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:urmqtt:device:$1
authorityKeyIdentifier=keyid
EOF
    echo "$TMP/client.ext"
}
ids=(web)
for ((i = 1; i <= COUNT; i++)); do ids+=("$(printf 'demo-%03d' "$i")"); done
for id in "${ids[@]}"; do
    leaf "$OUT/ca" "$OUT/clients/$id" "$id" "$(client_ext "$id")"
done

echo "verifying with $("$OPENSSL" version)"
"$OPENSSL" verify -CAfile "$OUT/server-ca.pem" "$OUT/server.pem" >/dev/null
for id in "${ids[@]}"; do "$OPENSSL" verify -CAfile "$OUT/ca.pem" "$OUT/clients/$id.pem" >/dev/null; done
if "$OPENSSL" verify -CAfile "$OUT/ca.pem" "$OUT/server.pem" >/dev/null 2>&1; then
    echo "error: the broker certificate must not verify against the client CA" >&2; exit 1
fi
if "$OPENSSL" verify -CAfile "$OUT/server-ca.pem" "$OUT/clients/${ids[1]}.pem" >/dev/null 2>&1; then
    echo "error: a client certificate must not verify against the broker CA" >&2; exit 1
fi

# The download: everything a visitor needs, and nothing of the broker's.
cat > "$OUT/download/README.txt" <<EOF
urMQTT PUBLIC DEMO: certificates
================================

This is a toy. The broker is $HOST:8883 (MQTT over TLS 1.3, mutual TLS).

  server-ca.pem        trust this to check the broker (mosquitto: --cafile server-ca.pem)
  clients/<id>.pem/.key    a client certificate; its CN is its id, and it may publish and subscribe only to
                       demo/<id>/#. The id "web" is the one the web page uses ("Try urMQTT live"), so
                       with clients/web.* you can talk to the page's topics.
  ca.pem, ca.key       the CLIENT CA, WITH ITS PRIVATE KEY. The key is public on purpose: anyone can mint a
                       client certificate, so a certificate here proves nothing. Do not rely on it, do not
                       reuse this CA, these certificates or these ids anywhere else, and send nothing private:
                       anyone can read the topics of any id they care to mint.

Example:
  mosquitto_pub -h $HOST -p 8883 --cafile server-ca.pem --cert clients/demo-001.pem --key clients/demo-001.key \\
                -i demo-001 -t demo/demo-001/hello -m hi

The client id must equal the certificate's id. Limits are small and the machine is reset without notice
(it runs from RAM). No uptime promise. Source: https://github.com/zeljan-alduk/urMQTT
EOF
cp "$OUT/ca.pem" "$OUT/ca.key" "$OUT/server-ca.pem" "$OUT/download/"
mkdir -p "$OUT/download/clients"
cp "$OUT/clients/"* "$OUT/download/clients/"
python3 -I - "$OUT/download" <<'PY'
import os, sys, zipfile
root = sys.argv[1]
names = sorted(n for n in (os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs) if not n.endswith(".zip"))
with zipfile.ZipFile(os.path.join(root, "demo-certs.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for n in names:
        info = zipfile.ZipInfo(os.path.join("urmqtt-demo", os.path.relpath(n, root)), (2026, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        with open(n, "rb") as fh:
            z.writestr(info, fh.read(), zipfile.ZIP_DEFLATED)
PY
chmod -R go+rX "$OUT/download"
echo "done: $((COUNT + 1)) client certificates (web, demo-001..$(printf '%03d' "$COUNT")) in $OUT"
echo "      published download: $OUT/download/ (the zip includes ca.key, on purpose)"
echo "      NOT to publish: $OUT/server.key"
