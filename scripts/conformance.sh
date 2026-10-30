#!/usr/bin/env bash
# H2 TLS conformance: the tlsfuzzer probes in scripts/tlsfuzzer/ against a
# dev VM. tlsfuzzer and tlslite-ng are fetched at pinned commits into
# build/conformance (host tools, never in the image).
#
#   scripts/conformance.sh [--accel hvf|kvm|tcg]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/conformance"
D="$ROOT/deploy/dev"
TLSFUZZER_COMMIT=5eebc4464e5197a7f7392fb9acda99cfc32441f7
TLSLITE_COMMIT=7e95ea1a86c0d42d8d931ff14134d31f01ce1d76
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

fetch() {
    local dir=$1 url=$2 commit=$3
    if [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]]; then
        rm -rf "${dir:?}"
        git init -q "$dir"
        git -C "$dir" fetch -q --depth 1 "$url" "$commit"
        git -C "$dir" checkout -q FETCH_HEAD
    fi
}
fetch "$OUT/tlsfuzzer" https://github.com/tlsfuzzer/tlsfuzzer.git "$TLSFUZZER_COMMIT"
fetch "$OUT/tlslite-ng" https://github.com/tlsfuzzer/tlslite-ng.git "$TLSLITE_COMMIT"
if [[ ! -x "$OUT/venv/bin/python" ]]; then
    python3 -m venv "$OUT/venv"
    "$OUT/venv/bin/pip" install -q ecdsa
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
PYTHONPATH="$OUT/tlsfuzzer:$OUT/tlslite-ng" "$OUT/venv/bin/python" "$ROOT/scripts/tlsfuzzer/urmqtt_tls13.py" \
    -h 127.0.0.1 -p 18883 -c "$D/devices/device-001.pem" -k "$D/devices/device-001.key" -i device-001
