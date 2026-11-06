#!/usr/bin/env bash
# A production PKI for urMQTT with OpenSSL (ROADMAP NOW-3, docs/PKI.md): the
# operational CA, the server certificate, device and service (operator)
# certificates, the control key pair and the revocation list, in the forms the
# kernel and `urmqtt-config pack` accept.
#
#   scripts/pki.sh init DIR --dns NAME... | --ip ADDR...  [--org NAME] [--ca-days N]
#                  [--server-days N] [--no-passphrase] [--no-control-key]
#       a new PKI in DIR (which must not exist or be empty):
#         DIR/offline/ca.key, control.key   KEEP OFFLINE (never on the build machine,
#                                           never in deploy/); passphrase-protected
#         DIR/deploy/ca.pem, server.pem, server.key, control.pub, revoked.txt,
#                     config-snippet.toml   what goes into deploy/prod/ (or the builder page)
#         DIR/issued.tsv                    every certificate issued: serial, kind, id, notAfter
#   scripts/pki.sh device DIR ID [--days N]      DIR/devices/ID.{pem,key}  (test devices, small fleets)
#   scripts/pki.sh service DIR ID [--days N]     DIR/services/ID.{pem,key} (backends, operators)
#   scripts/pki.sh sign-csr DIR CSR [--service] [--days N]
#       a certificate for a key that was born on the device (the way at scale):
#       the identity is the CSR's CN; writes DIR/devices/ID.pem (services/ with --service)
#   scripts/pki.sh server DIR --dns NAME... | --ip ADDR... [--days N]
#       a new server key and certificate for rotation: DIR/deploy/server-YYYYMMDD.{pem,key}
#   scripts/pki.sh ca DIR NAME [--days N]
#       another CA under DIR/offline/NAME.key, DIR/deploy/NAME.pem: a second
#       operational CA (rotation with overlap) or a bootstrap CA (provisioning role)
#   scripts/pki.sh revoke DIR CERT.pem | --serial HEX
#       adds the serial to DIR/deploy/revoked.txt (the format tls.revocation_list reads)
#   scripts/pki.sh check DIR      (also: --check DIR)
#       checks DIR (a deploy/<env>/ directory, or a PKI made by init: its deploy/)
#       the way the kernel will: `urmqtt-config pack` (expiry against
#       tls.min_server_cert_days and trust.min_anchor_days, PEM kinds, the control key,
#       the revocation list), plus a few OpenSSL checks pack does not make
#       (the key matches the certificate, chains, key types, identities).
#
# Rules this follows (crates/tls/src/identity.rs, docs/PROVISIONING.md):
#   - every key is ECDSA P-256 (the broker's TLS stack has no other), the control key Ed25519;
#   - a client certificate carries its identity twice, as the subject CN and as the SAN URI
#     urn:urmqtt:device:ID or urn:urmqtt:service:ID, so it works with tls.identity_field
#     "cn" (the default) and "san_uri"; an identity is [A-Za-z0-9][A-Za-z0-9._:-]* (it
#     becomes a topic level: no / + # and no leading $);
#   - serials are random, 127 bits, positive (no DER sign byte), so the revocation list's
#     hex is what `openssl x509 -serial` prints, in lower case;
#   - the server key is never encrypted (the VM has no way to ask for a passphrase); the CA
#     and control keys are, unless --no-passphrase. URMQTT_CA_PASSPHRASE, when set, is the
#     passphrase (tests, scripted offline ceremonies); otherwise OpenSSL asks on the terminal.
#   - nothing that exists is ever overwritten; private keys are created 0600.
#
# Needs OpenSSL 3 (LibreSSL cannot handle the urn: URI SANs). `check` uses urmqtt-config
# (URMQTT_CONFIG=path, or on PATH, or target/{release,debug}/ of this checkout, or cargo).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ID_RE='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'

die() { printf 'pki: error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'pki: warning: %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2; exit 2; }

is_openssl3() { command -v "$1" >/dev/null 2>&1 && "$1" version | grep -q '^OpenSSL [3-9]'; }
OPENSSL=${OPENSSL:-}
if [[ -z $OPENSSL ]]; then
    for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
        if is_openssl3 "$c"; then OPENSSL=$c; break; fi
    done
fi
is_openssl3 "${OPENSSL:-none}" || die "OpenSSL >= 3 not found (LibreSSL is not supported); set OPENSSL=/path/to/openssl"
ossl() { "$OPENSSL" "$@"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
umask 077

# Passphrase options for the CA and control keys.
PASS=1
# A passphrase from URMQTT_CA_PASSPHRASE goes to OpenSSL as a file in $TMP (0600 in a 0700
# directory, removed on exit), not as env: (that was seen to fail intermittently with OpenSSL 3.6).
PASSFILE=
if [[ -n ${URMQTT_CA_PASSPHRASE:-} ]]; then
    PASSFILE=$TMP/passphrase
    printf '%s\n' "$URMQTT_CA_PASSPHRASE" >"$PASSFILE"
fi
pass_out() { if ((PASS)); then if [[ -n $PASSFILE ]]; then echo "-aes-256-cbc -pass file:$PASSFILE"; else echo "-aes-256-cbc"; fi; fi; }
pass_in() { if [[ -n $PASSFILE ]]; then echo "-passin file:$PASSFILE"; fi; }

new_file() { [[ ! -e $1 ]] || die "$1 exists; nothing is overwritten (move it away first)"; }
ec_key() { new_file "$1"; ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 "${@:2}" -out "$1" 2>/dev/null; chmod 600 "$1"; }
serial() { ossl rand -hex 16 | sed 's/^./7/'; }
check_id() { [[ $1 =~ $ID_RE ]] || die "identity '$1' must match $ID_RE (it becomes a topic level: no / + # and no leading \$)"; }

# record <dir> <cert> <kind> <id>
record() {
    local s na
    s=$(ossl x509 -in "$2" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
    na=$(ossl x509 -in "$2" -noout -enddate | cut -d= -f2)
    printf '%s\t%s\t%s\t%s\n' "$s" "$3" "$4" "$na" >>"$1/issued.tsv"
    chmod 600 "$1/issued.tsv"
}

org_of() { ossl x509 -in "$1/deploy/ca.pem" -noout -subject -nameopt multiline | sed -n 's/^ *organizationName *= *//p' | head -1; }

need_pki() {
    [[ -f $1/deploy/ca.pem && -f $1/offline/ca.key ]] \
        || die "$1 is not a PKI made by 'pki.sh init' (needs deploy/ca.pem and offline/ca.key; run it on the offline machine that holds the CA key)"
}

# ca_plain <pki>: the CA key, decrypted once per run into $TMP/ca-plain.key (0600 in a
# 0700 directory that is removed on exit; on the offline machine only). OpenSSL then never
# reads the encrypted file in req/x509: with OpenSSL 3.6 that failed intermittently (the
# decoder fell back to a passphrase prompt although -passin was given), and so, rarely,
# did one `pkey -passin`; a second attempt is made before giving up.
ca_plain() {
    [[ -s $TMP/ca-plain.key ]] && return 0
    for _ in 1 2 3; do
        # shellcheck disable=SC2046 # pass_in is zero or two words
        if ossl pkey -in "$1/offline/ca.key" $(pass_in) -out "$TMP/ca-plain.key" 2>"$TMP/pkey.log"; then return 0; fi
        [[ -n $PASSFILE ]] || break
        sleep 1
    done
    cat "$TMP/pkey.log" >&2
    die "cannot open the CA key $1/offline/ca.key (wrong passphrase?)"
}

# sign_leaf <pki> <csr> <out.pem> <extfile> <days>
sign_leaf() {
    local pki=$1 csr=$2 out=$3 ext=$4 days=$5
    new_file "$out"
    ca_plain "$pki"
    ossl x509 -req -in "$csr" -CA "$pki/deploy/ca.pem" -CAkey "$TMP/ca-plain.key" \
        -set_serial "0x$(serial)" -sha256 -days "$days" -extfile "$ext" -out "$out" 2>"$TMP/x509.log" \
        || { cat "$TMP/x509.log" >&2; die "signing $out failed"; }
    chmod 644 "$out"
    ossl verify -CAfile "$pki/deploy/ca.pem" "$out" >/dev/null || die "$out does not verify against the CA"
}

client_ext() { # client_ext <device|service> <id>
    cat >"$TMP/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:urmqtt:$1:$2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
    echo "$TMP/client.ext"
}

server_ext() { # server_ext <san list>
    cat >"$TMP/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
    echo "$TMP/server.ext"
}

# new_ca <key> <pem> <subject> <days>
# The key is made in $TMP (0700, removed on exit), the self-signed certificate made
# from it there, and only then written encrypted to <key>: no encrypted file is read
# back by req (OpenSSL 3.6's req and x509 failed intermittently to use -passin on it).
new_ca() {
    new_file "$1"
    new_file "$2"
    ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/ca-plain.key" 2>/dev/null
    ossl req -x509 -new -key "$TMP/ca-plain.key" -sha256 -days "$4" -subj "$3" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" -out "$2"
    chmod 644 "$2"
    # shellcheck disable=SC2046 # pass_out is zero, one or three words
    ossl pkey -in "$TMP/ca-plain.key" $(pass_out | sed 's/-pass /-passout /') -out "$1"
    chmod 600 "$1"
    # The operational CA of `init` signs the server certificate next: keep it decrypted for this run.
    if [[ $(basename "$1") != ca.key ]]; then rm -f "$TMP/ca-plain.key"; fi
}

# new_server <pki> <stem> <days> <dns/ip args...>
new_server() {
    local pki=$1 stem=$2 days=$3 san="" cn=""
    shift 3
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dns) [[ $2 =~ ^[A-Za-z0-9.-]+$ ]] || die "--dns $2 is not a host name"; san+="${san:+,}DNS:$2"; cn=${cn:-$2}; shift 2 ;;
            --ip) [[ $2 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "--ip $2 is not an IPv4 address"; san+="${san:+,}IP:$2"; cn=${cn:-$2}; shift 2 ;;
            *) die "unknown option $1" ;;
        esac
    done
    [[ -n $san ]] || die "the server certificate needs at least one --dns NAME or --ip ADDR (what devices connect to)"
    ec_key "$pki/deploy/$stem.key"
    ossl req -new -key "$pki/deploy/$stem.key" -subj "/O=$(org_of "$pki")/CN=$cn" -out "$TMP/server.csr"
    sign_leaf "$pki" "$TMP/server.csr" "$pki/deploy/$stem.pem" "$(server_ext "$san")" "$days"
    record "$pki" "$pki/deploy/$stem.pem" server "$cn"
}

# leaf <pki> <device|service> <id> <days>: key generated here
leaf() {
    local pki=$1 kind=$2 id=$3 days=$4 dir
    check_id "$id"
    dir=$pki/${kind}s
    mkdir -p "$dir"
    new_file "$dir/$id.pem"
    ec_key "$dir/$id.key"
    ossl req -new -key "$dir/$id.key" -subj "/O=$(org_of "$pki")/CN=$id" -out "$TMP/leaf.csr"
    sign_leaf "$pki" "$TMP/leaf.csr" "$dir/$id.pem" "$(client_ext "$kind" "$id")" "$days"
    record "$pki" "$dir/$id.pem" "$kind" "$id"
    echo "$kind '$id': $dir/$id.pem, $dir/$id.key ($days days)"
}

# ---------------------------------------------------------------------------

cmd_init() {
    local dir=${1:-}
    [[ -n $dir ]] || usage
    shift
    local org="urMQTT" ca_days=3650 server_days=397 control=1 sargs=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --org) org=$2; shift 2 ;;
            --ca-days) ca_days=$2; shift 2 ;;
            --server-days) server_days=$2; shift 2 ;;
            --dns | --ip) sargs+=("$1" "$2"); shift 2 ;;
            --no-passphrase) PASS=0; shift ;;
            --no-control-key) control=0; shift ;;
            *) die "unknown option $1" ;;
        esac
    done
    [[ $org =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] || die "--org must be letters, digits, spaces, . _ -"
    [[ $ca_days =~ ^[0-9]+$ && $server_days =~ ^[0-9]+$ ]] || die "--ca-days and --server-days are numbers of days"
    ((${#sargs[@]})) || die "init needs at least one --dns NAME or --ip ADDR for the server certificate"
    if [[ -e $dir ]] && [[ -n $(ls -A "$dir") ]]; then die "$dir exists and is not empty; nothing is overwritten"; fi
    mkdir -p "$dir/offline" "$dir/deploy"
    chmod 700 "$dir" "$dir/offline"
    chmod 755 "$dir/deploy"
    ((PASS)) && [[ -z ${URMQTT_CA_PASSPHRASE:-} ]] && echo "pki: OpenSSL will ask for the CA key's passphrase (and again for each signature)."
    new_ca "$dir/offline/ca.key" "$dir/deploy/ca.pem" "/O=$org/CN=$org Operational CA" "$ca_days"
    echo "operational CA: $dir/deploy/ca.pem ($ca_days days), key $dir/offline/ca.key"
    new_server "$dir" server "$server_days" "${sargs[@]}"
    echo "server: $dir/deploy/server.pem, $dir/deploy/server.key ($server_days days)"
    if ((control)); then
        new_file "$dir/offline/control.key"
        # shellcheck disable=SC2046
        ossl genpkey -algorithm ed25519 $(pass_out) -out "$dir/offline/control.key"
        chmod 600 "$dir/offline/control.key"
        # shellcheck disable=SC2046
        ossl pkey -in "$dir/offline/control.key" $(pass_in) -pubout -out "$dir/deploy/control.pub"
        chmod 644 "$dir/deploy/control.pub"
        echo "control key: $dir/deploy/control.pub, key $dir/offline/control.key"
    fi
    printf '# Revoked certificate serials (tls.revocation_list): one hex serial per line, # comments.\n' >"$dir/deploy/revoked.txt"
    chmod 644 "$dir/deploy/revoked.txt"
    cat >"$dir/deploy/config-snippet.toml" <<'EOF'
# The PKI part of deploy/prod/config.toml (scripts/pki.sh init). File names are
# relative to the TOML. Merge it into your configuration; the rest stays as it is.
[tls]
cert = "server.pem"
key = "server.key"
identity_field = "cn"            # the certificates carry the identity as CN and as the SAN URI
revocation_list = "revoked.txt"

[trust]
operational = ["ca.pem"]

[control]
public_key = "control.pub"
EOF
    chmod 644 "$dir/deploy/config-snippet.toml"
    cat <<EOF

Done. What goes where:

  deploy/prod/ (or the builder page)       from $dir/deploy/
    ca.pem          [trust] operational        builder: "Operational CA"
    server.pem      [tls] cert                 builder: "Server certificate"
    server.key      [tls] key                  builder: "Server private key" (the image then holds it: keep the image secret)
    control.pub     [control] public_key       builder: "Control public key"
    revoked.txt     [tls] revocation_list      (empty for now; scripts/pki.sh revoke)
    config-snippet.toml: the lines for config.toml

  cp $dir/deploy/{ca.pem,server.pem,server.key,control.pub,revoked.txt} deploy/prod/

  KEEP OFFLINE, never in deploy/, never on the build machine, never in the browser:
    $dir/offline/ca.key       (and its passphrase): issues every device and service identity
    $dir/offline/control.key  signs control messages (urmqtt-control --sign-cmd, docs/PROVISIONING.md)

  Next: scripts/pki.sh device|service|sign-csr $dir ...; scripts/pki.sh check deploy/prod (after copying).
EOF
}

cmd_leaf() { # device|service DIR ID [--days N]
    local kind=$1 dir=${2:-} id=${3:-} days=825
    [[ -n $dir && -n $id ]] || usage
    shift 3
    while [[ $# -gt 0 ]]; do
        case $1 in --days) days=$2; shift 2 ;; *) die "unknown option $1" ;; esac
    done
    need_pki "$dir"
    leaf "$dir" "$kind" "$id" "$days"
    [[ $kind == service ]] && echo "list '$id' in acl.service_ids (a backend) or acl.operator_ids (an operator), or both, and rebuild the image"
    return 0
}

cmd_sign_csr() {
    local dir=${1:-} csr=${2:-} kind=device days=825 id
    [[ -n $dir && -f $csr ]] || usage
    shift 2
    while [[ $# -gt 0 ]]; do
        case $1 in --service) kind=service; shift ;; --days) days=$2; shift 2 ;; *) die "unknown option $1" ;; esac
    done
    need_pki "$dir"
    ossl req -in "$csr" -noout -verify 2>/dev/null || die "$csr is not a valid, self-signed CSR"
    ossl req -in "$csr" -noout -text | grep -q 'ASN1 OID: prime256v1' || die "$csr: the key must be ECDSA P-256"
    id=$(ossl req -in "$csr" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p' | head -1)
    check_id "$id"
    mkdir -p "$dir/${kind}s"
    # Only the public key and the CN of the CSR are used; its requested extensions are ignored.
    sign_leaf "$dir" "$csr" "$dir/${kind}s/$id.pem" "$(client_ext "$kind" "$id")" "$days"
    record "$dir" "$dir/${kind}s/$id.pem" "$kind" "$id"
    echo "$kind '$id': $dir/${kind}s/$id.pem ($days days; the key stays on the device)"
}

cmd_server() {
    local dir=${1:-} days=397 args=()
    [[ -n $dir ]] || usage
    shift
    while [[ $# -gt 0 ]]; do
        case $1 in --days) days=$2; shift 2 ;; --dns | --ip) args+=("$1" "$2"); shift 2 ;; *) die "unknown option $1" ;; esac
    done
    need_pki "$dir"
    local stem
    stem=server-$(date -u +%Y%m%d)
    new_server "$dir" "$stem" "$days" "${args[@]}"
    echo "new server certificate: $dir/deploy/$stem.pem, $stem.key ($days days)"
    echo "copy both into deploy/prod/, set [tls] cert = \"$stem.pem\", key = \"$stem.key\", rebuild and deploy the image"
}

cmd_ca() {
    local dir=${1:-} name=${2:-} days=3650
    [[ -n $dir && -n $name ]] || usage
    shift 2
    while [[ $# -gt 0 ]]; do
        case $1 in --days) days=$2; shift 2 ;; *) die "unknown option $1" ;; esac
    done
    [[ $name =~ ^ca-[A-Za-z0-9_-]{1,32}$ ]] || die "a CA name looks like ca-2 or ca-bootstrap"
    need_pki "$dir"
    new_ca "$dir/offline/$name.key" "$dir/deploy/$name.pem" "/O=$(org_of "$dir")/CN=$(org_of "$dir") $name" "$days"
    echo "CA $name: $dir/deploy/$name.pem ($days days), key $dir/offline/$name.key"
    echo "add \"$name.pem\" to [trust] operational (rotation: next to ca.pem) or [trust] bootstrap (provisioning only)"
    echo "note: device, service and server certificates of this script are issued by ca.pem; issue under $name with OpenSSL directly (docs/PKI.md)"
}

cmd_revoke() {
    local dir=${1:-} what=${2:-} s
    [[ -n $dir && -n $what ]] || usage
    local list=$dir/deploy/revoked.txt
    [[ -d $dir/deploy ]] || list=$dir/revoked.txt
    if [[ $what == --serial ]]; then
        s=$(printf '%s' "${3:-}" | tr -d ':' | tr 'A-F' 'a-f')
    else
        [[ -f $what ]] || die "$what not found"
        s=$(ossl x509 -in "$what" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')
    fi
    [[ $s =~ ^([0-9a-f]{2}){1,20}$ ]] || die "serial '$s' is not an even number of hex digits (at most 40)"
    if [[ -f $list ]] && grep -qx "$s" "$list"; then echo "already revoked: $s"; return 0; fi
    printf '%s\n' "$s" >>"$list"
    chmod 644 "$list"
    echo "revoked $s in $list: copy it into deploy/prod/ and rebuild the image; to cut off live connections now, also"
    echo "  urmqtt-control revoke --serial $s ... (docs/PROVISIONING.md)"
}

find_config_tool() {
    if [[ -n ${URMQTT_CONFIG:-} ]]; then echo "$URMQTT_CONFIG"; return; fi
    if command -v urmqtt-config >/dev/null 2>&1; then command -v urmqtt-config; return; fi
    for b in "$ROOT/target/release/urmqtt-config" "$ROOT/target/debug/urmqtt-config"; do
        if [[ -x $b ]]; then echo "$b"; return; fi
    done
    if command -v cargo >/dev/null 2>&1 && [[ -f $ROOT/tools/config/Cargo.toml ]]; then
        (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool --bin urmqtt-config) && echo "$ROOT/target/debug/urmqtt-config" && return
    fi
    echo ""
}

cmd_check() {
    local dir=${1:-}
    [[ -n $dir && -d $dir ]] || usage
    [[ -d $dir/deploy && -f $dir/deploy/ca.pem ]] && dir=$dir/deploy
    local bad=0 tool toml
    fail() { printf 'pki check: FAIL: %s\n' "$*" >&2; bad=1; }
    ok() { printf 'pki check: ok: %s\n' "$*"; }

    # 1. The kernel's own checks, through urmqtt-config pack (the same code as the image build).
    tool=$(find_config_tool)
    if [[ -f $dir/config.toml ]]; then
        toml=$dir/config.toml
    else
        # No configuration: check the PKI files alone, in a minimal one.
        toml=$TMP/check.toml
        {
            echo '[tls]'
            echo 'cert = "server.pem"'
            echo 'key = "server.key"'
            [[ -f $dir/revoked.txt ]] && echo 'revocation_list = "revoked.txt"'
            echo '[trust]'
            printf 'operational = [%s]\n' "$(find "$dir" -maxdepth 1 -name 'ca*.pem' ! -name 'ca-bootstrap*' -exec basename {} \; | sort | sed 's/.*/"&"/' | paste -sd, -)"
            [[ -f $dir/control.pub ]] && printf '[control]\npublic_key = "control.pub"\n'
        } >"$toml"
    fi
    if [[ -z $tool ]]; then
        warn "urmqtt-config not found (URMQTT_CONFIG=, PATH, or a checkout with cargo): the kernel's checks were NOT run, only the OpenSSL ones below"
        bad=1
    elif "$tool" pack "$toml" --env prod --root "$dir" --out-slot "$TMP/slot" >"$TMP/pack.out" 2>&1; then
        ok "urmqtt-config pack accepts $(basename "$toml") (expiry, PEM kinds, anchors, control key, revocation list): $(head -1 "$TMP/pack.out")"
    else
        fail "urmqtt-config pack refuses it:"
        sed 's/^/    /' "$TMP/pack.out" >&2
    fi

    # 2. What pack does not check (kept minimal on purpose; docs/PKI.md).
    local cas=() f
    while IFS= read -r f; do cas+=("$f"); done < <(find "$dir" -maxdepth 1 -name 'ca*.pem' | sort)
    ((${#cas[@]})) || fail "no ca*.pem in $dir"
    cat "${cas[@]}" >"$TMP/anchors.pem" 2>/dev/null || true
    for f in "${cas[@]}"; do
        ossl x509 -in "$f" -noout -text | grep -q 'ASN1 OID: prime256v1' || fail "$(basename "$f"): not an ECDSA P-256 key"
        ossl x509 -in "$f" -noout -text | grep -q 'CA:TRUE' || fail "$(basename "$f"): not a CA certificate (basicConstraints CA:TRUE)"
    done
    if [[ -f $dir/server.pem && -f $dir/server.key ]]; then
        if [[ "$(ossl x509 -in "$dir/server.pem" -noout -pubkey 2>/dev/null)" == "$(ossl pkey -in "$dir/server.key" -pubout 2>/dev/null)" ]]; then
            ok "server.key belongs to server.pem"
        else
            fail "server.key does not belong to server.pem"
        fi
        ossl x509 -in "$dir/server.pem" -noout -text | grep -q 'ASN1 OID: prime256v1' || fail "server.pem: not an ECDSA P-256 key"
        if ossl verify -CAfile "$TMP/anchors.pem" "$dir/server.pem" >/dev/null 2>&1; then
            ok "server.pem is issued by an operational CA"
        else
            warn "server.pem does not verify against the CAs here (fine if a public CA issued it; devices must trust that CA)"
        fi
        ossl x509 -in "$dir/server.pem" -noout -ext subjectAltName 2>/dev/null | grep -qE 'DNS:|IP Address:' || fail "server.pem has no DNS or IP subjectAltName"
    else
        fail "server.pem and server.key are needed"
    fi
    local key mode
    for key in "$dir"/*.key "$dir"/devices/*.key "$dir"/services/*.key; do
        [[ -f $key ]] || continue
        mode=$(stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key")
        [[ $mode == 600 || $mode == 400 ]] || warn "$key is mode $mode; private keys should be 0600"
        [[ $(basename "$key") == ca*.key || $(basename "$key") == control.key ]] && fail "$key is a CA or control private key: it must not be in a deploy directory"
    done
    for f in "$dir"/devices/*.pem "$dir"/services/*.pem "$dir"/../devices/*.pem "$dir"/../services/*.pem; do
        [[ -f $f ]] || continue
        local kind cn uri
        kind=$(basename "$(dirname "$f")"); kind=${kind%s}
        cn=$(ossl x509 -in "$f" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p' | head -1)
        uri=$(ossl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | grep -o "URI:urn:urmqtt:[a-z]*:[^, ]*" | head -1 || true)
        [[ $cn =~ $ID_RE ]] || fail "$f: CN '$cn' is not a usable identity"
        [[ -z $uri || $uri == "URI:urn:urmqtt:$kind:$cn" ]] || fail "$f: SAN $uri does not match CN '$cn' (identity_field cn and san_uri would disagree)"
        ossl verify -CAfile "$TMP/anchors.pem" "$f" >/dev/null 2>&1 || fail "$f does not verify against the operational CAs here"
        ossl x509 -in "$f" -noout -checkend $((30 * 86400)) >/dev/null || warn "$f expires within 30 days"
    done
    if ((bad)); then echo "pki check: $dir has problems (above)" >&2; return 1; fi
    echo "pki check: $dir is usable"
}

[[ $# -ge 1 ]] || usage
sub=$1
shift
case $sub in
    init) cmd_init "$@" ;;
    device | service) cmd_leaf "$sub" "$@" ;;
    sign-csr) cmd_sign_csr "$@" ;;
    server) cmd_server "$@" ;;
    ca) cmd_ca "$@" ;;
    revoke) cmd_revoke "$@" ;;
    check | --check) cmd_check "$@" ;;
    -h | --help | help) usage ;;
    *) usage ;;
esac
