#!/usr/bin/env bash
# The plaintext path against the TLS path on the same VM (P1, ADR-230), through
# QEMU user networking: the same kernel, the same cores, the same load generator,
# once with TLS (8883, mutual authentication) and once on the plaintext port.
#
#   scripts/plain-bench.sh [--accel hvf|tcg|kvm] [--smp N] [--duration S] [--runs N]
#
# One dev image serves both ports. The plaintext listener is in anonymous mode
# (so a message costs the same to authorise as on the TLS port: an ACL match) for
# the message rows, and a second image in password mode (PBKDF2 at the
# default count of `urmqtt-config hash-password`, ADR-267) for the login row. The handshake limits and the
# per-device publish rate are lifted in the configuration of this image so that
# neither port is held back by them; this is a measurement image, never a
# deployment.
#
# Measures: messages per second and latency of 1 and of 16 publisher/subscriber
# pairs (QoS 0 flood, QoS 1 flood), and connections per second (TLS 1.3 with a
# client certificate, plaintext without login, plaintext with a password).
#
# It measures a development machine behind a user-mode network stack. Read
# docs/PERFORMANCE.md section 5 before quoting any number.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/plain-bench"
ACCEL="" SMP=4 DURATION=10 RUNS=2
while [[ $# -gt 0 ]]; do
    case $1 in
        --accel) ACCEL=$2; shift 2 ;;
        --smp) SMP=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --runs) RUNS=$2; shift 2 ;;
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
cargo build --release --locked -q -p urmqtt-loadgen -p urmqtt-config-tool
LOADGEN="$ROOT/target/release/urmqtt-loadgen"
TOOL="$ROOT/target/release/urmqtt-config"
clean() { LC_ALL=C sed -e $'s/\x1b\\[[0-9;?=]*[A-Za-z]//g' -e $'s/\r//g' "$1"; }

TLS_PORT=18883 PLAIN_PORT=11883
HASH=$(printf '%s\n' bench-secret | "$TOOL" hash-password)
ITERS=$(cut -d'$' -f2 <<<"$HASH")

# The development configuration with its plaintext port off, the limits lifted
# and the new section on. $@: the lines of the [plaintext] section that differ
# between the two images.
make_blob() {
    local name=$1
    shift
    sed -e 's/^mqtt_plain_port = 1883 .*/mqtt_plain_port = 0/' \
        -e 's/^publish_rate_per_device = .*/publish_rate_per_device = "1000000\/s"/' \
        -e 's/^handshakes_per_core_per_sec = .*/handshakes_per_core_per_sec = 100000/' \
        -e 's/^max_handshakes_in_flight_per_core = .*/max_handshakes_in_flight_per_core = 4096/' \
        -e 's/^max_handshakes_in_flight_per_ip = .*/max_handshakes_in_flight_per_ip = 4096/' \
        -e 's/^kernel_heap_mb = [0-9]*/kernel_heap_mb = 128/' \
        -e 's/^service_ids = \["backend"\]/service_ids = ["backend", "svc*"]/' \
        "$ROOT/deploy/dev/config.toml" >"$OUT/$name.toml"
    {
        printf '\n[plaintext]\nenabled = true\nallow_from = ["10.0.2.0/24"]\nmax_connections = 20000\n'
        printf 'max_connections_per_ip = 20000\nmax_packet_size = 1024\npublish_rate_per_device = "1000000/s"\n'
        printf 'acl_publish = ["fleet/bench/#"]\nacl_subscribe = ["fleet/bench/#"]\n'
        printf '%s\n' "$@"
    } >>"$OUT/$name.toml"
    "$TOOL" pack "$OUT/$name.toml" --env dev --root "$ROOT/deploy/dev" --out "$OUT/$name.blob" >/dev/null
}

make_blob anonymous 'auth = "anonymous"' 'anonymous_identity = "bench"'
make_blob password 'auth = "password"' "users = [{ id = \"bench\", password_hash = \"$HASH\" }]"

mkimg() { # mkimg <name>
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$OUT/$1.iso" --cmdline "serve log=info" --esp-out "$OUT/$1.esp" \
        --config "$OUT/$1.blob" >/dev/null
    python3 -I "$ROOT/scripts/mkraw.py" "$OUT/$1.esp" "$OUT/$1.raw" >/dev/null
    rm -f "$OUT/$1.iso"
}

VM_PID=
boot_vm() { # boot_vm <name>
    local log="$OUT/$1.log"
    rm -f "$log" "$OUT/$1.img"
    cp "$OUT/$1.raw" "$OUT/$1.img"
    truncate -s 64m "$OUT/$1.img"
    "$ROOT/scripts/run-qemu.sh" --serial "$log" --disk "$OUT/$1.img" --accel "$ACCEL" --smp "$SMP" --mem 1G \
        --headless --fwd "$TLS_PORT:8883,$PLAIN_PORT:1883" >/dev/null 2>&1 &
    VM_PID=$!
    until clean "$log" 2>/dev/null | grep -q '^URMQTT READY$'; do sleep 0.3; done
    sleep 1
}
stop_vm() {
    kill "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
}
trap stop_vm EXIT

# lg <loadgen args...>: runs the generator; prints its RESULT line followed by
# gen_cpu=<cores>, the CPU the whole process used (user + system) over its wall
# time, from the shell's `time` (the generator's own figure is Linux only). A
# generator near the number of free host cores measures itself, not the broker.
lg() {
    local out tf u s r
    tf=$(mktemp)
    TIMEFORMAT='%U %S %R'
    out=$({ time "$LOADGEN" "$@" 2>/dev/null; } 2>"$tf" | grep -E '^RESULT' | tail -1 | sed -e 's/ gen_cpu=[0-9.]*//')
    read -r u s r <"$tf" || true
    rm -f "$tf"
    printf '%s gen_cpu=%s\n' "$out" "$(awk -v u="${u:-0}" -v s="${s:-0}" -v r="${r:-1}" 'BEGIN { printf "%.2f", (u + s) / (r > 0 ? r : 1) }')"
}
field() { # field <key> <RESULT line>
    grep -Eo " $1=[0-9.]+" <<<"$2" | head -1 | cut -d= -f2
}

row_pubsub() { # row_pubsub <label> <pairs> <qos> <payload> <rate per publisher, 0: flood>
    local label=$1 pairs=$2 qos=$3 payload=$4 rate=$5 run
    for run in $(seq "$RUNS"); do
        local t p
        t=$(lg pubsub --port "$TLS_PORT" --certs "$ROOT/deploy/dev" --prefix svc --publishers "$pairs" \
            --subscribers "$pairs" --topics "$pairs" --qos "$qos" --payload "$payload" --rate "$rate" --duration "$DURATION" --open-par 4)
        p=$(lg pubsub --plain 1 --port "$PLAIN_PORT" --prefix bench --publishers "$pairs" \
            --subscribers "$pairs" --topics "$pairs" --qos "$qos" --payload "$payload" --rate "$rate" --duration "$DURATION" --open-par 4)
        printf '| %s | %s | %s (p50 %s ms, p99 %s ms, generator %s cores) | %s (p50 %s ms, p99 %s ms, generator %s cores) |\n' "$label" "$run" \
            "$(field delivered_per_s "$t")" "$(field lat_p50_ms "$t")" "$(field lat_p99_ms "$t")" "$(field gen_cpu "$t")" \
            "$(field delivered_per_s "$p")" "$(field lat_p50_ms "$p")" "$(field lat_p99_ms "$p")" "$(field gen_cpu "$p")"
    done
}

conn_rate() { # conn_rate <loadgen args...>: connections per second, and the generator's cores
    local rate tf u s r
    tf=$(mktemp)
    TIMEFORMAT='%U %S %R'
    rate=$({ time "$LOADGEN" handshake --threads 32 --duration "$DURATION" "$@" 2>&1 | grep -Eo '= [0-9]+ conn/s' | grep -Eo '[0-9]+' | tail -1; } 2>"$tf")
    read -r u s r <"$tf" || true
    rm -f "$tf"
    printf '%s (generator %s cores)' "$rate" "$(awk -v u="${u:-0}" -v s="${s:-0}" -v r="${r:-1}" 'BEGIN { printf "%.2f", (u + s) / (r > 0 ? r : 1) }')"
}

mkimg anonymous
mkimg password
echo "accelerator: $ACCEL, $SMP vCPUs, user-mode network, $DURATION s per measurement, $RUNS run(s)"
boot_vm anonymous
echo
echo "| Messages (delivered per second) | run | TLS 1.3 + client certificate | plaintext |"
echo "|---|---|---|---|"
row_pubsub "16 pairs, QoS 0, 64 B, 500 msg/s each" 16 0 64 500
row_pubsub "16 pairs, QoS 1, 64 B, 500 msg/s each" 16 1 64 500
row_pubsub "16 pairs, QoS 0, 512 B, 500 msg/s each" 16 0 512 500
echo
echo "| New connections per second (32 clients) | run | rate |"
echo "|---|---|---|"
for run in $(seq "$RUNS"); do
    echo "| TLS 1.3 + client certificate | $run | $(conn_rate --port "$TLS_PORT" --certs "$ROOT/deploy/dev") |"
    echo "| plaintext, anonymous | $run | $(conn_rate --plain 1 --port "$PLAIN_PORT") |"
done
echo
echo "| Messages (delivered per second) | run | TLS 1.3 + client certificate | plaintext |"
echo "|---|---|---|---|"
# Last, because an unbounded flood can wedge the guest (the watchdog resets it).
row_pubsub "1 pair, QoS 0, 64 B, flood" 1 0 64 0
stop_vm
boot_vm password
for run in $(seq "$RUNS"); do
    echo "| plaintext, password (PBKDF2 $ITERS) | $run | $(conn_rate --plain 1 --port "$PLAIN_PORT" --user bench --password bench-secret) |"
done
stop_vm
clean "$OUT/password.log" | grep -E "plaintext: one password check costs" | head -1 || true
echo "serial logs and images in $OUT"
