#!/usr/bin/env bash
# H2 interop matrix: tools/interop/client.c built against every TLS library
# found (OpenSSL 3 and 4, wolfSSL, mbedTLS), run against one dev VM. Prints
# a Markdown table; non-zero exit if any supported test fails.
#
#   scripts/interop.sh [--accel hvf|kvm|tcg]
#
# Libraries are found through pkg-config or Homebrew prefixes; missing ones
# are listed as skipped. Resumption is also checked in the server log (the
# `, resumed)` of the authentication line), which decides for libraries
# that cannot tell themselves (mbedTLS).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/interop"
D="$ROOT/deploy/dev"
ACCEL=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --accel) ACCEL=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -z "$ACCEL" ]]; then
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) ACCEL=hvf ;;
        Linux-aarch64) [[ -w /dev/kvm ]] && ACCEL=kvm || ACCEL=tcg ;;
        *) ACCEL=tcg ;;
    esac
fi
mkdir -p "$OUT"
clean() { LC_ALL=C sed -e $'s/\x1b\\[[0-9;?=]*[A-Za-z]//g' -e $'s/\r//g' "$1"; }

# Each candidate: name, macro, and a prefix (Homebrew) or pkg-config module.
build() {
    local name=$1 macro=$2 cflags libs
    read -ra cflags <<<"$3"
    read -ra libs <<<"$4"
    if cc -O1 -Wall -Wextra -D"$macro" "${cflags[@]}" "$ROOT/tools/interop/client.c" "${libs[@]}" \
        -o "$OUT/client-$name" 2>"$OUT/client-$name.err"; then
        LIBS+=("$name")
    else
        SKIPPED+=("$name (build failed, see $OUT/client-$name.err)")
    fi
}
LIBS=()
SKIPPED=()
brew_prefix() { command -v brew >/dev/null && brew --prefix "$1" 2>/dev/null; }
for v in openssl@3 openssl@4; do
    p=$(brew_prefix "$v" || true)
    if [[ -n "$p" && -f "$p/include/openssl/ssl.h" ]]; then
        build "$v" USE_OPENSSL "-I$p/include" "-L$p/lib -lssl -lcrypto"
    fi
done
if [[ ${#LIBS[@]} -eq 0 ]] && pkg-config --exists openssl 2>/dev/null; then
    build openssl USE_OPENSSL "$(pkg-config --cflags openssl)" "$(pkg-config --libs openssl)"
fi
p=$(brew_prefix wolfssl || true)
if [[ -n "$p" && -f "$p/include/wolfssl/ssl.h" ]]; then
    build wolfssl USE_WOLFSSL "-I$p/include" "-L$p/lib -lwolfssl"
elif pkg-config --exists wolfssl 2>/dev/null; then
    build wolfssl USE_WOLFSSL "$(pkg-config --cflags wolfssl)" "$(pkg-config --libs wolfssl)"
else
    SKIPPED+=("wolfssl (not installed)")
fi
p=$(brew_prefix mbedtls || true)
if [[ -n "$p" && -f "$p/include/mbedtls/ssl.h" ]]; then
    build mbedtls USE_MBEDTLS "-I$p/include" "-L$p/lib -lmbedtls -lmbedx509 -lmbedcrypto"
else
    SKIPPED+=("mbedtls (not installed)")
fi

"$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$OUT/vm.iso" --cmdline "serve" --esp-out "$OUT/vm.esp" >/dev/null
python3 -I "$ROOT/scripts/mkraw.py" "$OUT/vm.esp" "$OUT/vm.img" >/dev/null
rm -f "$OUT/vm.iso" "$OUT/vm.esp" "$OUT/vm.log"
truncate -s 64m "$OUT/vm.img"
"$ROOT/scripts/run-qemu.sh" --serial "$OUT/vm.log" --disk "$OUT/vm.img" --accel "$ACCEL" --headless \
    --fwd 18883:8883 >/dev/null 2>&1 &
VM=$!
trap 'kill "$VM" 2>/dev/null || true' EXIT
for _ in $(seq 1 600); do
    clean "$OUT/vm.log" 2>/dev/null | grep -q "TLS 1.3 listener" && break
    sleep 0.2
done

resumed_count() { clean "$OUT/vm.log" | grep -c "device-001 authenticated (.*, resumed)" || true; }
cell() { grep -E "^$1: " "$2" | head -1 | sed -E "s/^$1: //; s/^ok.*/✅/; s/^FAILED(.*)/❌\1/; s/^n\/a(.*)/— n\/a\1/"; }
FAIL=0
echo "| Library | handshake (mTLS + CONNECT) | resumption | KeyUpdate | 1-byte records | 16 KiB record |"
echo "|---|---|---|---|---|---|"
for l in ${LIBS[@]+"${LIBS[@]}"}; do
    before=$(resumed_count)
    "$OUT/client-$l" 18883 "$D/ca.pem" "$D/devices/device-001.pem" "$D/devices/device-001.key" device-001 \
        >"$OUT/$l.txt" 2>&1 || true
    sleep 0.3
    after=$(resumed_count)
    lib=$(grep '^library: ' "$OUT/$l.txt" | sed 's/^library: //')
    res=$(cell resumption "$OUT/$l.txt")
    if [[ $res == unknown* ]]; then
        if (( after > before )); then res="✅ (server log)"; else res="❌ (not resumed, server log)"; fi
    elif [[ $res == ✅ ]] && (( after <= before )); then
        res="❌ (the server log shows no resumption)"
    fi
    row="| ${lib:-$l} | $(cell handshake "$OUT/$l.txt") | $res | $(cell key-update "$OUT/$l.txt") | $(cell records-1-byte "$OUT/$l.txt") | $(cell records-max "$OUT/$l.txt") |"
    echo "$row"
    if [[ $row == *❌* || -z $lib ]]; then
        FAIL=1
        sed "s/^/    $l: /" "$OUT/$l.txt" >&2
        # Why the server refused (its side of the story).
        clean "$OUT/vm.log" | grep -E "tls: connection refused|WARN" | tail -5 | sed "s/^/    $l (server): /" >&2
    fi
done
for s in ${SKIPPED[@]+"${SKIPPED[@]}"}; do
    echo "| $s | | | | | |"
done
echo
echo "accelerator: $ACCEL; client output and serial log in $OUT"
exit $FAIL
