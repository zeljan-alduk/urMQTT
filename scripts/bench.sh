#!/usr/bin/env bash
# Multicore benchmarks (M13): prints a Markdown table.
#
#   scripts/bench.sh [--accel hvf|tcg|kvm] [--threads N] [--duration S] [--cmdline WORDS] [--relaxed]
#
# --relaxed adds the dev word `limits=bench` to the network image: the
# handshake limits (per address, per core, per second) are lifted, because
# every client of this benchmark has the address of QEMU's user network and
# --threads above 32 would otherwise measure the per-address limit
# (ADR-082). Never the default; a production image ignores the word.
#
# --cmdline appends dev command-line words to both images, e.g.
# "cpu-disable=aes,pmull,sha2,crc32" to measure the portable crypto (X0b).
#
# 1. dp-bench: full TLS 1.3 + mTLS handshakes with CONNECT/CONNACK on 1, 2
#    and 4 worker cores, client and server inside the guest (shows how the
#    shared-nothing data plane scales).
# 2. network: urmqtt-loadgen against the VM through QEMU user networking
#    for 1, 2 and 4 worker cores (core 0 dispatches; DB core separate).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/bench"
ACCEL=""
THREADS=32
DURATION=10
EXTRA="" RELAXED=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --accel) ACCEL=$2; shift 2 ;;
        --threads) THREADS=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --cmdline) EXTRA=" $2"; shift 2 ;;
        --relaxed) RELAXED=1; shift ;;
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
cargo build --release --locked -p urmqtt-loadgen -q
LOADGEN="$ROOT/target/release/urmqtt-loadgen"
clean() { LC_ALL=C sed -e $'s/\x1b\\[[0-9;?=]*[A-Za-z]//g' -e $'s/\r//g' "$1"; }

# Single-disk model (S1): each run boots a fresh copy of the raw image.
mkimg() {
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$1.iso" --cmdline "$2" --esp-out "$1.esp" >/dev/null
    python3 -I "$ROOT/scripts/mkraw.py" "$1.esp" "$1" >/dev/null
    rm -f "$1.iso" "$1.esp"
}
mkimg "$OUT/dp.raw" "smoke test=dp-bench$EXTRA"
mkimg "$OUT/net.raw" "serve log=info$EXTRA$([[ $RELAXED == 1 ]] && echo ' limits=bench')"

cp "$OUT/dp.raw" "$OUT/dp.img"
truncate -s 64m "$OUT/dp.img"
"$ROOT/scripts/run-qemu.sh" --serial "$OUT/dp.log" --disk "$OUT/dp.img" --accel "$ACCEL" --smp 6 \
    --headless --fwd none >/dev/null 2>&1
dp() { clean "$OUT/dp.log" | grep -Eo "dp-bench: $1 worker core\(s\): [0-9]+" | awk '{print $NF}'; }

net() {
    local smp=$1 log="$OUT/net-$1.log"
    rm -f "$log" "$OUT/net.img"
    cp "$OUT/net.raw" "$OUT/net.img"
    truncate -s 64m "$OUT/net.img"
    "$ROOT/scripts/run-qemu.sh" --serial "$log" --disk "$OUT/net.img" --accel "$ACCEL" --smp "$smp" \
        --headless --fwd 18883:8883 >/dev/null 2>&1 &
    local pid=$!
    until clean "$log" 2>/dev/null | grep -q "log: level Info"; do sleep 0.2; done
    sleep 1
    "$LOADGEN" handshake --port 18883 --threads "$THREADS" --duration "$DURATION" --certs "$ROOT/deploy/dev" 2>/dev/null \
        | grep -Eo '= [0-9]+ conn/s' | grep -Eo '[0-9]+'
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

d1=$(dp 1) d2=$(dp 2) d4=$(dp 4)
n1=$(net 3) n2=$(net 4) n4=$(net 6)
ratio() { awk -v a="$1" -v b="$2" 'BEGIN { if (b > 0) printf "%.2fx", a / b; else print "?" }'; }
echo "| Worker cores | dp-bench (handshakes/s, in guest) | scaling | network via QEMU user net (conn/s, $THREADS clients) | scaling |"
echo "|---|---|---|---|---|"
echo "| 1 | $d1 | 1.00x | $n1 | 1.00x |"
echo "| 2 | $d2 | $(ratio "$d2" "$d1") | $n2 | $(ratio "$n2" "$n1") |"
echo "| 4 | $d4 | $(ratio "$d4" "$d1") | $n4 | $(ratio "$n4" "$n1") |"
echo
echo "accelerator: $ACCEL${EXTRA:+; command line:$EXTRA}$([[ $RELAXED == 1 ]] && echo '; RELAXED handshake limits (limits=bench)'); serial logs in $OUT"
