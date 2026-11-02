#!/usr/bin/env bash
# Boots the public demo image (D1) under QEMU on this machine and runs scripts/demo-scenarios.py against it.
# Nothing is exposed: QEMU's user networking forwards only 127.0.0.1 ports.
#
#   scripts/demo-smoke.sh --template ISO [--tool PATH] [--accel hvf|tcg|kvm] [--arch aarch64|x86_64] [--keep]
#
# Makes the certificates when deploy/demo/pki is missing, packs deploy/demo/config.toml with --bridge 10.0.2.0/24
# (the address QEMU gives the host), boots the ISO, waits for "URMQTT READY" and runs the scenarios.
# Exit status: 0 if every scenario passed.
set -euo pipefail

cd "$(dirname "$0")/.."
TEMPLATE="" TOOL=target/debug/urmqtt-config ACCEL="" ARCH=aarch64 KEEP=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --template) TEMPLATE=$2; shift 2 ;;
        --tool) TOOL=$2; shift 2 ;;
        --accel) ACCEL=$2; shift 2 ;;
        --arch) ARCH=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "usage: $0 --template ISO [--tool PATH] [--accel hvf|tcg|kvm] [--arch aarch64|x86_64] [--keep]" >&2; exit 2 ;;
    esac
done
[[ -n $TEMPLATE ]] || { echo "error: --template is required" >&2; exit 2; }
if [[ -z $ACCEL ]]; then
    case "$(uname -s)" in Darwin) ACCEL=hvf ;; Linux) ACCEL=kvm ;; *) ACCEL=tcg ;; esac
    [[ $ARCH == aarch64 || $ACCEL == tcg ]] || { [[ $(uname -s) == Linux ]] || ACCEL=tcg; }
fi
[[ -f deploy/demo/pki/ca.pem ]] || scripts/demo-certs.sh
WORK=$(mktemp -d)
LOG=$WORK/serial.log
QPID=""
cleanup() {
    [[ -n $QPID ]] && kill "$QPID" 2>/dev/null || true
    pkill -f "demo-smoke-$$" 2>/dev/null || true
    ((KEEP)) && echo "kept: $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

scripts/demo-pack.sh --template "$TEMPLATE" --out "$WORK/demo.iso" --bridge 10.0.2.0/24 --tool "$TOOL" >"$WORK/pack.log" 2>&1 \
    || { cat "$WORK/pack.log"; exit 1; }
grep -E 'fingerprint|^demo image' "$WORK/pack.log" || true

# Free ports on the loopback address (QEMU forwards 127.0.0.1 only).
free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
TLS_PORT=$(free_port)
PLAIN_PORT=$(free_port)
URMQTT_ARCH=$ARCH scripts/run-qemu.sh --iso "$WORK/demo.iso" --accel "$ACCEL" --headless --serial "$LOG" \
    --fwd "$TLS_PORT:8883,$PLAIN_PORT:1883" --mem 512M -- -name "demo-smoke-$$" >"$WORK/qemu.out" 2>&1 &
QPID=$!
for _ in $(seq 1 120); do
    grep -aq 'URMQTT READY' "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || { echo "QEMU exited early"; cat "$WORK/qemu.out"; tail -20 "$LOG"; exit 1; }
    sleep 1
done
grep -aq 'URMQTT READY' "$LOG" || { echo "the broker did not become ready"; tail -30 "$LOG"; exit 1; }
for want in "EPHEMERAL: data is lost on reboot" "TLS 1.3 listener on port 8883" "PLAINTEXT listener on port 1883"; do
    grep -aq "$want" "$LOG" && echo "  boot: $want" || { echo "  MISSING in the boot log: $want"; exit 1; }
done
status=0
python3 -I scripts/demo-scenarios.py "$TLS_PORT" "$PLAIN_PORT" deploy/demo/pki | tee "$WORK/scenarios.log" || status=$?
grep -c '^client: [^ ]* ok' "$WORK/scenarios.log" | sed 's/^/scenarios ok: /'
grep -E '^client: [^ ]* FAILED|Traceback' "$WORK/scenarios.log" || true
if grep -aE 'panic|FAULT' "$LOG" >/dev/null; then echo "the serial log has a panic or fault"; status=1; fi
exit $status
