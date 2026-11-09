#!/usr/bin/env bash
# The multiqueue rig (NEXT-6, ADR-314): boots an urMQTT image on a multi-queue
# tap with virtio-net multiqueue and RSS, carries MQTT over mutual TLS through
# it and keeps the serial log for the caller to check. Linux only (a tap device
# needs it), as root (or with sudo): a CI runner, or a container with
# NET_ADMIN and /dev/net/tun (scripts/smoke.sh SMOKE_ONLY=mq runs it in Docker
# on macOS, see docs/perf-results/next6-mq/).
#
#   scripts/mq-rig.sh --arch aarch64|x86_64 (--disk RAW | --iso ISO) --smp N --queues Q --log FILE
#                     [--accel tcg|kvm] [--gic 2|3] [--rounds 16] [--bench SECONDS] [--loadgen PATH]
#
# The guest gets 10.77.0.2/24 from its configuration (network.mode = "static",
# gateway 10.77.0.1; scripts/smoke.sh builds the image); the tap is 10.77.0.1.
# --rounds: QoS 1 round trips over mutual TLS, each on two new connections
# (new source ports, so the flows spread over the queue pairs); the client
# prints "client: mq-qos1 <i> ok|FAILED". After them one statistics window
# (5 s) passes, so the per-pair counters are in the log. --bench SECONDS adds
# a QoS 0 flood with urmqtt-loadgen (--loadgen, a Linux build) and prints its
# RESULT line: the throughput figures of docs/PERFORMANCE.md 13.7.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCH=aarch64 DISK="" ISO="" SMP=4 QUEUES=4 LOG="" ACCEL=tcg ROUNDS=16 BENCH=0 LOADGEN="" GIC=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch) ARCH=$2; shift 2 ;;
        --disk) DISK=$2; shift 2 ;;
        --iso) ISO=$2; shift 2 ;;
        --smp) SMP=$2; shift 2 ;;
        --queues) QUEUES=$2; shift 2 ;;
        --log) LOG=$2; shift 2 ;;
        --accel) ACCEL=$2; shift 2 ;;
        --rounds) ROUNDS=$2; shift 2 ;;
        --bench) BENCH=$2; shift 2 ;;
        --loadgen) LOADGEN=$2; shift 2 ;;
        --gic) GIC=(--gic "$2"); shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$LOG" ]] || { echo "error: --log FILE" >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "error: the rig needs Linux (a multi-queue tap)" >&2; exit 2; }
SUDO=()
[[ $(id -u) -eq 0 ]] || SUDO=(sudo)

TAP="mqtap$$"
HOSTIP=10.77.0.1 GUEST=10.77.0.2
D="$ROOT/deploy/dev"
TLS=(--cafile "$D/ca.pem" --insecure)
QPID=""
cleanup() {
    [[ -n "$QPID" ]] && { kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }
    "${SUDO[@]}" ip link del "$TAP" 2>/dev/null || true
}
trap cleanup EXIT

if (( QUEUES > 1 )); then
    "${SUDO[@]}" ip tuntap add dev "$TAP" mode tap multi_queue user "$(id -u)"
else
    "${SUDO[@]}" ip tuntap add dev "$TAP" mode tap user "$(id -u)"
fi
"${SUDO[@]}" ip addr add "$HOSTIP/24" dev "$TAP"
"${SUDO[@]}" ip link set "$TAP" up

MEDIUM=()
if [[ -n "$DISK" ]]; then
    work="$LOG.img"
    rm -f "$work"
    cp "$DISK" "$work"
    truncate -s 64m "$work"
    MEDIUM=(--disk "$work")
else
    MEDIUM=(--iso "$ISO")
fi
rm -f "$LOG"
# Ubuntu's OVMF has its 4 MiB build only.
if [[ $ARCH == x86_64 && -z ${URMQTT_FIRMWARE:-} && -f /usr/share/OVMF/OVMF_CODE_4M.fd ]]; then
    export URMQTT_FIRMWARE=/usr/share/OVMF/OVMF_CODE_4M.fd URMQTT_FIRMWARE_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
fi
URMQTT_ARCH=$ARCH "$ROOT/scripts/run-qemu.sh" --arch "$ARCH" "${MEDIUM[@]}" --accel "$ACCEL" --smp "$SMP" "${GIC[@]}" \
    --headless --serial "$LOG" --tap "$TAP:$QUEUES" >"$LOG.qemu" 2>&1 &
QPID=$!

wait_log() {
    local pat=$1 n=0
    until LC_ALL=C grep -aEq -- "$pat" "$LOG" 2>/dev/null; do
        kill -0 "$QPID" 2>/dev/null || return 1
        (( n++ >= 3000 )) && return 1
        sleep 0.1
    done
}
if ! wait_log "TLS 1.3 listener on port 8883" || ! wait_log "net: static address $GUEST"; then
    echo "client: the broker did not come up" | tee -a "$LOG.client"
    exit 0
fi
sleep 1
{
    for i in $(seq 1 "$ROUNDS"); do
        dev=$(printf 'device-%03d' $(( (i - 1) % 3 + 1 )))
        mosquitto_sub -h "$GUEST" -p 8883 -V mqttv311 -i backend "${TLS[@]}" \
            --cert "$D/services/backend.pem" --key "$D/services/backend.key" \
            -t "devices/$dev/mq" -q 1 -C 1 -W 30 >"$LOG.got" 2>&1 &
        spid=$!
        sleep 0.7
        mosquitto_pub -h "$GUEST" -p 8883 -V mqttv311 -i "$dev" "${TLS[@]}" \
            --cert "$D/devices/$dev.pem" --key "$D/devices/$dev.key" \
            -t "devices/$dev/mq" -q 1 -m "mq $i" || echo "client: publish failed"
        wait "$spid" || echo "client: subscriber failed"
        if [[ $(cat "$LOG.got") == "mq $i" ]]; then echo "client: mq-qos1 $i ok"; else echo "client: mq-qos1 $i FAILED"; fi
    done
    if (( BENCH > 0 )) && [[ -x "$LOADGEN" ]]; then
        "$LOADGEN" pubsub --host "$GUEST" --port 8883 --certs "$D" --pairs 8 --qos 0 --size 64 \
            --duration "$BENCH" 2>&1 | grep -E '^(RESULT|loadgen: (pubsub|errors))' | sed 's/^/client: /' || true
    fi
    # One statistics window with the traffic in it.
    sleep 6
} >"$LOG.client" 2>&1
cat "$LOG.client" >>"$LOG"
