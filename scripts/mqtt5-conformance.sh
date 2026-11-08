#!/usr/bin/env bash
# MQTT 5.0 conformance harness (docs/MQTT5-CONFORMANCE.md, ADR-273).
#
# STUB until NEXT-3 part 2: the broker refuses MQTT 5.0 today, so this prints
# what it will run and exits 0. Part 2 replaces the "would run" lines with the
# runs and adds scripts/mqtt5-conformance.xfail.
#
#   scripts/mqtt5-conformance.sh [--port PORT] [--mosquitto] [--timeout S]
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=1883
TARGET=urmqtt
TIMEOUT=60
PAHO_REPO=https://github.com/eclipse/paho.mqtt.testing
PAHO_COMMIT=fdab9d2b1ce125385135e5d9f282a0ad315268cc
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT=$2; shift 2 ;;
        --mosquitto) TARGET=mosquitto; shift ;;
        --timeout) TIMEOUT=$2; shift 2 ;;
        *) echo "usage: $0 [--port PORT] [--mosquitto] [--timeout S]" >&2; exit 2 ;;
    esac
done

echo "mqtt5-conformance: STUB (NEXT-3 part 2 implements it); target $TARGET on 127.0.0.1:$PORT"
echo "would run:"
echo "  1. clone $PAHO_REPO at $PAHO_COMMIT into a scratch directory"
if [[ $TARGET == mosquitto ]]; then
    echo "  2. start mosquitto on 127.0.0.1:$PORT (allow_anonymous, acl: readwrite #, deny test/nosubscribe)"
else
    echo "  2. boot the deploy/conformance image (plaintext listener, open login, ACL # minus test/nosubscribe)"
fi
echo "  3. each test of interoperability/client_test5.py and client_test.py in its own process,"
echo "     timeout ${TIMEOUT}s, through a wrapper that passes -p $PORT to the script"
echo "  4. compare with scripts/mqtt5-conformance.xfail: PASS/FAIL/XFAIL/XPASS/TIMEOUT per test;"
echo "     exit non-zero on FAIL, TIMEOUT or XPASS"
echo "  5. the mosquitto -V mqttv5 scenarios of docs/MQTT5-CONFORMANCE.md section 3"
exit 0
