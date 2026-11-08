#!/usr/bin/env bash
# Regenerates the MQTT 5.0 packet-capture fixtures in
# crates/mqtt/tests/fixtures/v5 (see the README there for the list).
#
#   scripts/mqtt5-capture.sh [--broker-port 28831] [--proxy-port 28832] [--out DIR]
#
# Starts a private Mosquitto 2.x (allow_anonymous, one listener on
# 127.0.0.1), and for every scenario runs scripts/mqtt-record.py between the
# client and the broker, so each scenario leaves NAME.c2s.bin (client to
# server) and NAME.s2c.bin (server to client). Needs mosquitto,
# mosquitto_pub/_sub, python3 and uv (for the paho-mqtt 2.x scenario).
# Everything it starts is stopped by PID on exit. Byte streams are
# deterministic except for broker-assigned client identifiers, packet
# identifiers chosen by paho and timing-dependent TCP segmentation (which
# does not show in the files).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BPORT=28831
PPORT=28832
OUT="$ROOT/crates/mqtt/tests/fixtures/v5"
while [[ $# -gt 0 ]]; do
    case $1 in
        --broker-port) BPORT=$2; shift 2 ;;
        --proxy-port) PPORT=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
MOSQUITTO=${MOSQUITTO:-$(command -v mosquitto || echo /opt/homebrew/sbin/mosquitto)}
mkdir -p "$OUT"
WORK=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

printf 'listener %s 127.0.0.1\nallow_anonymous true\npersistence false\n' "$BPORT" >"$WORK/mosquitto.conf"
"$MOSQUITTO" -c "$WORK/mosquitto.conf" >"$WORK/mosquitto.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do
    mosquitto_pub -p "$BPORT" -t ping -n 2>/dev/null && break
    sleep 0.1
done
echo "broker: $("$MOSQUITTO" -h 2>&1 | grep -o "mosquitto version [0-9.]*" | head -1)" >&2

# record NAME COUNT: starts the proxy and waits until it listens.
PROXY=""
record() {
    local name=$1 count=${2:-1}
    rm -f "$OUT/$name".*.bin "$OUT/$name"-[0-9].*.bin
    python3 -I "$ROOT/scripts/mqtt-record.py" --listen "127.0.0.1:$PPORT" \
        --upstream "127.0.0.1:$BPORT" --out "$OUT" --name "$name" --count "$count" \
        >"$WORK/proxy.out" 2>&1 &
    PROXY=$!
    PIDS+=("$PROXY")
    for _ in $(seq 50); do grep -q READY "$WORK/proxy.out" && return; sleep 0.1; done
    echo "proxy for $name did not start" >&2; cat "$WORK/proxy.out" >&2; exit 1
}
finish() {
    if ! wait "$PROXY"; then echo "proxy for $1 failed" >&2; cat "$WORK/proxy.out" >&2; exit 1; fi
    echo "captured $1" >&2
}
pub() { mosquitto_pub -V mqttv5 -h 127.0.0.1 -p "$PPORT" "$@"; }
direct_pub() { mosquitto_pub -V mqttv5 -h 127.0.0.1 -p "$BPORT" "$@"; }
# sub_scenario NAME ARGS...: mosquitto_sub through the proxy (exits after
# one message); a direct publisher feeds it once it has subscribed.
sub_scenario() {
    local name=$1 topic=$2; shift 2
    record "$name"
    mosquitto_sub -V mqttv5 -h 127.0.0.1 -p "$PPORT" -C 1 -W 10 "$@" >"$WORK/sub.out" &
    local sub=$!
    PIDS+=("$sub")
    sleep 0.5
    direct_pub -t "$topic" -m "to-$name" -q 1
    wait "$sub"
    finish "$name"
}

record pub-qos0
pub -i pub-qos0 -t fx/q0 -m hello
finish pub-qos0

record pub-qos1-props
pub -i pub-qos1-props -t fx/q1 -m hello -q 1 \
    -D publish user-property k v -D publish user-property k v2 \
    -D publish content-type text/plain -D publish payload-format-indicator 1 \
    -D publish message-expiry-interval 30 -D publish response-topic r/t \
    -D publish correlation-data abc -D publish topic-alias 3
finish pub-qos1-props

record pub-qos2
pub -i pub-qos2 -t fx/q2 -m hello -q 2
finish pub-qos2

record pub-connect-props
pub -i pub-connect-props -t fx/c -m hello \
    -D connect session-expiry-interval 60 -D connect receive-maximum 10 \
    -D connect maximum-packet-size 2000 -D connect topic-alias-maximum 5 \
    -D connect request-response-information 1 -D connect user-property a b
finish pub-connect-props

record pub-will
pub -i pub-will -t fx/w -m hello --will-topic w --will-payload bye --will-qos 1 --will-retain \
    -D will will-delay-interval 5 -D will content-type x
finish pub-will

record pub-userpass
pub -i pub-userpass -t fx/u -m hello -u user -P pass
finish pub-userpass

record pub-retain
pub -i pub-retain -t fx/r -m kept -q 1 -r
finish pub-retain
direct_pub -t fx/r -n -r -q 1   # clear it again

record pub-disconnect-props
pub -i pub-disconnect-props -t fx/d -m hello -D connect session-expiry-interval 30 \
    -D disconnect session-expiry-interval 0 -D disconnect user-property r s
finish pub-disconnect-props

# Subscribe: QoS 1, three filters, subscription identifier and user
# property; the broker's PUBLISH to it carries the identifier.
sub_scenario sub-props fx/s/1 -i sub-props -q 1 -t fx/s/+ -t fx/other -t 'fx/#' \
    -D subscribe subscription-identifier 7 -D subscribe user-property x y

# Unsubscribe: mosquitto_sub sends SUBSCRIBE for the -t filters, then
# UNSUBSCRIBE for the -U ones (one subscribed, one never subscribed, so the
# UNSUBACK carries 0x00 and 0x11), then receives one QoS 2 message.
sub_scenario sub-unsub fx/n/1 -i sub-unsub -q 2 -t fx/n/1 -t fx/n/2 -U fx/n/2 -U fx/never \
    -D unsubscribe user-property x y

# Paho 2.x session: CONNECT/SUBSCRIBE options/PUBLISH 0,1,2 with properties
# both ways/UNSUBSCRIBE/DISCONNECT 0x04 with session expiry.
record paho-session
(cd "$WORK" && uv run -q --with 'paho-mqtt>=2,<3' python -I "$ROOT/scripts/mqtt5-capture-paho.py" \
    --port "$PPORT" --direct-port "$BPORT")
finish paho-session

# Every client stream must start with CONNECT (0x10) at protocol level 5.
python3 -I - "$OUT" <<'EOF'
import pathlib, sys
bad = 0
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.bin")):
    b = f.read_bytes()
    ok = len(b) > 0
    if ok and f.name.endswith(".c2s.bin"):
        i = 1
        while b[i] & 0x80:
            i += 1
        i += 1  # past the remaining length
        ok = b[0] == 0x10 and b[i:i + 6] == b"\x00\x04MQTT" and b[i + 6] == 5
    print(f"{'ok ' if ok else 'BAD'} {len(b):5d} {f.name}")
    bad += not ok
sys.exit(1 if bad else 0)
EOF
