#!/usr/bin/env bash
# NOW-13b rig measurement: rig.sh MODE SMP RTT OUTFILE  (MODE irq|poll)
set -uo pipefail
MODE=$1 SMP=$2 RTT=$3 OUT=$4
ROOT=/Users/aldo/dev/urMQTT-now13b-c
C=now13b-c-rig
LG="docker exec $C /w/tgt/release/urmqtt-loadgen"
CERTS=/src/deploy/bench-n13b-$MODE
LOG=$ROOT/build/n13/rig-$MODE-smp$SMP.log
say() { echo "$*" | tee -a "$OUT"; }
cpu_s() { ps -o time= -p "$1" | awk -F'[:.]' '{ if (NF==3) print $1*60+$2+$3/100; else print $1*3600+$2*60+$3+$4/100 }'; }

docker exec $C pkill wan-bridge 2>/dev/null; sleep 0.5
docker exec -d $C /w/wan-bridge 27101 "$RTT" 0 0 1000
sleep 1
rm -f "$LOG"
"$ROOT/scripts/run-qemu.sh" --iso "$ROOT/build/urmqtt-bench-n13b-$MODE.iso" --accel hvf --smp "$SMP" \
    --dgram 27102:27101 --serial "$LOG" --headless >"$LOG.qemu" 2>&1 &
RQ=$!
for i in $(seq 120); do grep -q "TLS 1.3 listener" "$LOG" 2>/dev/null && break; sleep 0.5; done
sleep 2
# run-qemu.sh execs QEMU: the PID is QEMU itself.
QP=$RQ
say "== mode=$MODE smp=$SMP rtt_cfg=${RTT}ms qemu_pid=$QP($(ps -o comm= -p $QP | xargs basename)) $(date -u +%FT%TZ)"
say "boot: $(grep -E 'receive wake-up' "$LOG" | sed 's/^.*INFO  //')"

# (a) round trip: no connection, then one idle connection held
say "a0 ping, no connection: $(docker exec $C ping -q -c 40 -i 0.25 10.0.2.15 | tail -1)"
$LG hold --host 10.0.2.15 --certs $CERTS --clients 1 --threads 1 --duration 70 --prefix "bench-i$RANDOM" >/dev/null 2>&1 &
HP=$!
sleep 4
say "a1 ping, one idle connection: $(docker exec $C ping -q -c 80 -i 0.25 10.0.2.15 | tail -1)"
say "a2 mqtt 1 pub/1 sub 5 msg/s, one idle connection: $($LG pubsub --host 10.0.2.15 --certs $CERTS --publishers 1 --subscribers 1 --qos 0 --payload 64 --rate 5 --duration 20 --prefix "svc-r$RANDOM" 2>&1 | grep RESULT)"
wait $HP 2>/dev/null

# (b) host CPU of QEMU: idle, then 100 idle connections, 60 s each
c0=$(cpu_s $QP); sleep 60; c1=$(cpu_s $QP)
say "b0 qemu cpu, 0 connections, 60 s: $(echo "$c0 $c1" | awk '{printf "%.2f s = %.1f %% of one host CPU", $2-$1, ($2-$1)/60*100}')"
$LG hold --host 10.0.2.15 --certs $CERTS --clients 100 --threads 16 --duration 85 --prefix "bench-i$RANDOM" >"$LOG.hold" 2>&1 &
HP=$!
sleep 15
c0=$(cpu_s $QP); sleep 60; c1=$(cpu_s $QP)
say "b1 qemu cpu, $(grep -o '[0-9]* of [0-9]* connections' "$LOG.hold") idle, 60 s: $(echo "$c0 $c1" | awk '{printf "%.2f s = %.1f %% of one host CPU", $2-$1, ($2-$1)/60*100}')"
wait $HP 2>/dev/null
sleep 2

# (c) 16 x 1000/s QoS 0, and a 16-pair QoS 0 flood
for rate in 1000 0; do
    say "c rate=$rate 16 pairs qos0: $($LG pubsub --host 10.0.2.15 --certs $CERTS --publishers 16 --subscribers 16 --topics 16 --qos 0 --payload 64 --rate $rate --duration 10 --prefix "svc-c$RANDOM" 2>&1 | grep RESULT)"
done
sleep 6
say "core 0 statistics (last 6 windows):"
grep "dataplane: core 0" "$LOG" | tail -6 | sed 's/^.*dataplane/  dataplane/' | tee -a "$OUT" >/dev/null
grep -E "WARN|stalls: core 0" "$LOG" | tail -5 | sed 's/^/  /' | tee -a "$OUT" >/dev/null
kill $RQ 2>/dev/null; kill $QP 2>/dev/null; wait $RQ 2>/dev/null
docker exec $C pkill wan-bridge 2>/dev/null
say ""
