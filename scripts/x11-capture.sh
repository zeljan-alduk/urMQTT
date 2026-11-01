#!/usr/bin/env bash
# One single-flow run (1 publisher, 1 subscriber, QoS 0, flood) with a packet capture of 4 seconds in
# the middle, on the load generator host (PERF, ADR-233). The capture is read on another machine
# with scripts/pcap-flows.py. Same constraints as x11-bench.sh: nice, two CPUs, a short run.
#
#   x11-capture.sh LABEL PAYLOAD
#
# Environment: HOST [169.58.184.193] PORT [8883] DIR [/tmp/x11] CORES [2,3] CAPSEC [4] CAPAT [5]
set -u
LABEL=${1:?label}
PAYLOAD=${2:-64}
HOST=${HOST:-169.58.184.193}
PORT=${PORT:-8883}
DIR=${DIR:-/tmp/x11}
CORES=${CORES:-2,3}
CAPSEC=${CAPSEC:-4}
CAPAT=${CAPAT:-5}
OUT=$DIR/results/$LABEL
mkdir -p "$DIR/results"
t=$(curl -s -o /dev/null -m 5 -w '%{time_total}' "${SITE:-https://aldo.tech/}" || echo 9)
echo "site_s=$t load1=$(cut -d' ' -f1 /proc/loadavg)"
awk -v t="$t" 'BEGIN{exit !(t>1.0)}' && { echo "the web server is slow, not running"; exit 3; }
(
    sleep "$CAPAT"
    nice -n 19 timeout "$CAPSEC" tcpdump -i any -s 128 -c 400000 -w "$OUT.pcap" "host $HOST and tcp port $PORT" 2>"$OUT.tcpdump.err"
    ss -tin dst "$HOST" >"$OUT.ss" 2>/dev/null
) &
bg=$!
ulimit -n 65536 2>/dev/null
nice -n 19 taskset -c "$CORES" "$DIR/urmqtt-loadgen" pubsub --host "$HOST" --port "$PORT" --certs "$DIR/certs" \
    --prefix "svc-cap$RANDOM$RANDOM" --publishers 1 --subscribers 1 --topics 1 --qos 0 --payload "$PAYLOAD" \
    --rate 0 --duration 10 --warmup 2 2>&1 | grep -E 'RESULT|published|latency:' | tee "$OUT.txt"
wait "$bg" 2>/dev/null
ls -la "$OUT".* 2>/dev/null
