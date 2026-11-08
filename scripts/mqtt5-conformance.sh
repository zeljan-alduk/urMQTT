#!/usr/bin/env bash
# MQTT 5.0 conformance harness (docs/MQTT5-CONFORMANCE.md, ADR-273, ADR-274):
# the Eclipse Paho interoperability suite, each test in its own process with
# a timeout, against the expected-failure list scripts/mqtt5-conformance.xfail.
#
#   scripts/mqtt5-conformance.sh --boot [--port PORT] [--arch aarch64|x86_64] [--accel hvf|tcg|kvm]
#       builds the conformance image (the dev configuration, its development
#       port off, the plaintext listener in its open login mode with
#       acl_publish = acl_subscribe = ["#"], retain on, the rate and packet
#       limits raised for the suite, mqtt5.max_keep_alive_s = 60), boots it
#       in QEMU with the plaintext port forwarded to PORT, runs, stops it
#   scripts/mqtt5-conformance.sh --boot --listener dev
#       the same suite on the dev image's development port (dev builds only:
#       identity = client id, sessions persist as on the TLS port) with the
#       device ACL opened to # and the publish rate raised: the tests that need
#       a stored session run against the broker too, with their own list
#       (scripts/mqtt5-conformance-dev.xfail)
#   --smp N (default 1) vCPUs of the VM: the suite subscribes one client and
#       publishes from another without waiting for the SUBACK, an order the
#       broker does not keep across cores (ADR-032), so the reference run has
#       one vCPU; with more, test_subscribe_options and test_request_response
#       may lose that race (docs/MQTT5-CONFORMANCE.md)
#   scripts/mqtt5-conformance.sh --port PORT     against a broker already running
#   scripts/mqtt5-conformance.sh --mosquitto     the baseline: a local Mosquitto
#                                                (no expected-failure list)
#   [--suite 5|311|both] [--timeout S] [--work DIR]
#
# The suite (third-party code, pinned by commit) is cloned into WORK (default
# $TMPDIR/urmqtt-mqtt5-conformance), never into the repository.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

PORT=1883
TARGET=running
TIMEOUT=60
SUITE=both
ARCH=aarch64
ACCEL=""
LISTENER=plain
SMP=1
WORK=${TMPDIR:-/tmp}/urmqtt-mqtt5-conformance
PAHO_REPO=https://github.com/eclipse/paho.mqtt.testing
PAHO_COMMIT=fdab9d2b1ce125385135e5d9f282a0ad315268cc
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT=$2; shift 2 ;;
        --boot) TARGET=boot; shift ;;
        --mosquitto) TARGET=mosquitto; shift ;;
        --timeout) TIMEOUT=$2; shift 2 ;;
        --suite) SUITE=$2; shift 2 ;;
        --arch) ARCH=$2; shift 2 ;;
        --accel) ACCEL=$2; shift 2 ;;
        --listener) LISTENER=$2; shift 2 ;;
        --smp) SMP=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        *) echo "usage: $0 [--boot|--mosquitto] [--port PORT] [--suite 5|311|both] [--timeout S] [--work DIR] [--arch A] [--accel X]" >&2; exit 2 ;;
    esac
done
case $SUITE in
    5) SUITES=(client_test5) ;;
    311) SUITES=(client_test) ;;
    both) SUITES=(client_test5 client_test) ;;
    *) echo "--suite 5|311|both" >&2; exit 2 ;;
esac
mkdir -p "$WORK"

# 1. The suite at its pinned commit.
if [[ ! -d "$WORK/paho/.git" ]]; then
    git clone -q "$PAHO_REPO" "$WORK/paho"
fi
git -C "$WORK/paho" checkout -q "$PAHO_COMMIT"
SUITE_DIR="$WORK/paho/interoperability"

XFAIL="$ROOT/scripts/mqtt5-conformance.xfail"
[[ $LISTENER == dev ]] && XFAIL="$ROOT/scripts/mqtt5-conformance-dev.xfail"

run_suite() { # run_suite <xfail file or ->
    python3 -I "$ROOT/scripts/mqtt5-conformance.py" "$SUITE_DIR" "$PORT" "$1" "$TIMEOUT" "${SUITES[@]}"
}

wait_port() {
    local i
    for ((i = 0; i < 300; i++)); do
        python3 -I -c "import socket,sys; socket.create_connection(('127.0.0.1', $PORT), 1)" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

case $TARGET in
    running)
        run_suite "$XFAIL"
        ;;
    mosquitto)
        # The baseline of docs/MQTT5-CONFORMANCE.md: anonymous, no persistence,
        # every topic but test/nosubscribe.
        printf 'topic readwrite #\ntopic deny test/nosubscribe\n' >"$WORK/mosquitto.acl"
        printf 'listener %s 127.0.0.1\nallow_anonymous true\npersistence false\nacl_file %s\n' \
            "$PORT" "$WORK/mosquitto.acl" >"$WORK/mosquitto.conf"
        mosquitto -c "$WORK/mosquitto.conf" >"$WORK/mosquitto.log" 2>&1 &
        mpid=$!
        trap 'kill "$mpid" 2>/dev/null || true' EXIT
        wait_port
        run_suite -
        ;;
    boot)
        # 2. The conformance image: the dev configuration with the plaintext
        # listener in its open login mode.
        img="$WORK/image"
        mkdir -p "$img"
        (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool)
        tool="$ROOT/target/debug/urmqtt-config"
        kernel="$ROOT/target/aarch64-unknown-none/release/urmqtt"
        [[ $ARCH == x86_64 ]] && kernel="$ROOT/target/x86_64-urmqtt-none/release/urmqtt"
        [[ -f $kernel ]] || { echo "build the kernel first: make build${ARCH:+ ARCH=$ARCH}" >&2; exit 2; }
        if [[ $LISTENER == dev ]]; then
            # The development port: client id = identity, the device ACL opened.
            {
                sed -e 's/^publish_rate_per_device = .*/publish_rate_per_device = "1000\/s"/' \
                    -e 's/^device_publish = .*/device_publish = ["#"]/' \
                    -e 's/^device_subscribe = .*/device_subscribe = ["#"]/' "$ROOT/deploy/dev/config.toml"
                printf '\n[mqtt5]\nmax_keep_alive_s = 60\n'
            } >"$img/conformance.toml"
        else
        {
            sed -e 's/^mqtt_plain_port = 1883 .*/mqtt_plain_port = 0/' "$ROOT/deploy/dev/config.toml"
            cat <<'EOF'

[plaintext]
enabled = true
allow_from = ["10.0.2.0/24"]
auth = "anonymous"
anonymous_identity = "conformance"
acl_publish = ["#"]
acl_subscribe = ["#"]
retain = true
max_connections_per_ip = 64
max_packet_size = 65536
publish_rate_per_device = "1000/s"

[mqtt5]
max_keep_alive_s = 60
EOF
        } >"$img/conformance.toml"
        fi
        "$tool" pack "$img/conformance.toml" --env dev --root "$ROOT/deploy/dev" --out "$img/conformance.blob" >/dev/null
        URMQTT_ARCH=$ARCH "$ROOT/scripts/mkiso.sh" --kernel "$kernel" --out "$img/c.iso" --cmdline "serve" \
            --esp-out "$img/c.esp" --config "$img/conformance.blob" >/dev/null
        python3 -I "$ROOT/scripts/mkraw.py" "$img/c.esp" "$img/c.raw" >/dev/null
        cp "$img/c.raw" "$img/disk.img"
        truncate -s 64m "$img/disk.img"
        if [[ -z $ACCEL ]]; then
            case "$(uname -s)-$(uname -m)-$ARCH" in
                Darwin-arm64-aarch64) ACCEL=hvf ;;
                Linux-aarch64-aarch64 | Linux-x86_64-x86_64) [[ -w /dev/kvm ]] && ACCEL=kvm || ACCEL=tcg ;;
                *) ACCEL=tcg ;;
            esac
        fi
        rm -f "$img/serial.log"
        URMQTT_ARCH=$ARCH "$ROOT/scripts/run-qemu.sh" --serial "$img/serial.log" --headless --disk "$img/disk.img" \
            --accel "$ACCEL" --smp "$SMP" --fwd "$PORT:1883" >"$img/qemu.log" 2>&1 &
        vm=$!
        trap 'kill "$vm" 2>/dev/null || true; wait "$vm" 2>/dev/null || true' EXIT
        for ((i = 0; i < 1500; i++)); do
            grep -aq "net: dhcp lease 10.0.2.15" "$img/serial.log" 2>/dev/null && break
            kill -0 "$vm" 2>/dev/null || { echo "QEMU exited; serial log: $img/serial.log" >&2; exit 1; }
            sleep 0.2
        done
        grep -aq "net: dhcp lease 10.0.2.15" "$img/serial.log" || { echo "no READY; serial log: $img/serial.log" >&2; exit 1; }
        status=0
        run_suite "$XFAIL" || status=$?
        echo "serial log: $img/serial.log"
        exit "$status"
        ;;
esac
