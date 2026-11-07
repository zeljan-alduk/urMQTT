#!/usr/bin/env bash
# shellcheck disable=SC2016 # the $SYS/... MQTT topics are literal, not shell variables
# X11: the measurement suite, run ON the load-generator host (a Linux machine
# that reaches the VPS), against one broker at a time. Writes the raw output
# to $DIR/results/<label>.txt; scripts/x11-report.py turns it into tables.
#
#   scripts/x11-bench.sh LABEL [SUITE...]
#
#   LABEL   urmqtt-prod | urmqtt-bench | mosquitto (any word; it names the file)
#   SUITE   handshake | throughput | latency | fanout | idle | sweep | single  (default: all but sweep, single)
#           single (ADR-221/215): one publisher and one subscriber, QoS 0, 64 B and 1 KiB, flood;
#           with CONSOLE=1 every run also records the broker's console (watchdog reports, late
#           ticks, steal, drops) and `$SYS` counters through scripts/x11-console.py
#
# Environment (defaults in brackets):
#   HOST [169.58.184.193]  PORT [8883]  DIR [/tmp/x11]  REPS [3]
#   CORES [2,3]            the generator is pinned to these CPUs (taskset)
#   MAXLOAD [8]            wait while the 1-minute load average is above this
#   PUBSUB [1]             0: skip the publish suites (the prod image has no
#                          identity that may publish at speed, see PERFORMANCE.md)
#   BROKER [urmqtt]        urmqtt | mosquitto: which $SYS topics to sample
#   SSHVPS []              "user@host" to read the broker's RSS over ssh (mosquitto)
#   SS [0]                 1: sample `ss -tin` of the generator's flows once per run, 8 s in (the
#                          congestion window, round trip time, retransmissions and delivery rate of
#                          each flow as the sender, the generator, sees them): to $OUT.ss
#   CONSOLE [0]            1: record the urMQTT console and drop counters during each run
#                          (needs DIR/x11-console.py; python3 on this host)
#
# Layout of $DIR: urmqtt-loadgen, certs/ (ca.pem ca.key = the CA that signs the
# simulated devices; operator.pem operator.key for $SYS), results/.
#
# Being a guest on a shared host (the build server also runs a web server):
# everything runs under nice -n 19 on two pinned CPUs, one run lasts at most
# about 30 s, and before every run the script waits for the load average to
# fall and checks that the web server still answers quickly; it stops the
# whole suite if the site takes more than 1 s twice.
set -u
LABEL=${1:?label}
shift
SUITES=${*:-handshake throughput latency fanout idle}
CONSOLE=${CONSOLE:-0}
SS=${SS:-0}
HOST=${HOST:-169.58.184.193}
PORT=${PORT:-8883}
DIR=${DIR:-/tmp/x11}
REPS=${REPS:-3}
CORES=${CORES:-2,3}
MAXLOAD=${MAXLOAD:-8}
PUBSUB=${PUBSUB:-1}
BROKER=${BROKER:-urmqtt}
SITE=${SITE:-https://aldo.tech/}
CERTS=$DIR/certs
OUT=$DIR/results/$LABEL.txt
mkdir -p "$DIR/results"
ulimit -n 65536 2>/dev/null
LG=(taskset -c "$CORES" nice -n 19 "$DIR/urmqtt-loadgen")
COMMON=(--host "$HOST" --port "$PORT" --certs "$CERTS")
slow=0

say() { echo "$@" | tee -a "$OUT"; }

# A new identity prefix for every run: an id that is reused a moment after an
# unclean close can meet the old session's teardown (see PERFORMANCE.md).
uid() { echo "x$RANDOM$RANDOM"; }

guard() {
    local l t
    for _ in $(seq 1 30); do
        l=$(cut -d' ' -f1 /proc/loadavg)
        awk -v l="$l" -v m="$MAXLOAD" 'BEGIN{exit !(l<=m)}' && break
        sleep 5
    done
    t=$(curl -s -o /dev/null -m 5 -w '%{time_total}' "$SITE" || echo 9)
    say "GUARD load1=$l site_s=$t"
    if awk -v t="$t" 'BEGIN{exit !(t>1.0)}'; then
        slow=$((slow + 1))
        if [ "$slow" -ge 2 ]; then
            say "ABORT: the web server answered slowly twice, stopping"
            exit 3
        fi
        sleep 20
    fi
}

# run NAME ARGS...: one loadgen run, only the RESULT line is kept (plus the
# whole output of a failing run).
run() {
    local name=$1 rep=$2
    shift 2
    guard
    say "RUN $name rep=$rep"
    local o s0 s1
    busy_start
    console_start
    ss_start "$name" "$rep"
    s0=$(head -1 /proc/stat)
    o=$("${LG[@]}" "$@" 2>"$DIR/err.out")
    echo "$o" | grep -E '^(RESULT|loadgen: (handshake|pubsub|hold):|loadgen: (whole|tcp|tls|errors))' | tee -a "$OUT"
    grep -E 'loadgen: (lost|svc-|bench-)' "$DIR/err.out" | head -5 | tee -a "$OUT"
    s1=$(head -1 /proc/stat)
    # CPU time of the whole generator host during the run: the share stolen by
    # the hypervisor (the host is itself a VM) and the share idle.
    awk -v a="$s0" -v b="$s1" 'BEGIN{split(a,x," ");split(b,y," ");t=0;for(i=2;i<=9;i++)t+=y[i]-x[i];
        if(t>0)printf "HOSTCPU steal=%.0f%% idle=%.0f%% user+sys=%.0f%%\n",100*(y[9]-x[9])/t,100*(y[5]-x[5])/t,100*((y[2]-x[2])+(y[4]-x[4]))/t}' | tee -a "$OUT"
    busy_end
    console_end "$name" "$rep"
    ss_end
    sleep 3
}

# With SS=1: what the generator's TCP says about its flows, once, 8 s into the run.
ss_start() {
    SSPID=
    [ "$SS" = 1 ] || return 0
    (
        sleep "${SS_AT:-8}"
        echo "### ss $1 rep=$2"
        ss -tin dst "$HOST" 2>/dev/null
    ) >>"$OUT.ss" &
    SSPID=$!
}

ss_end() {
    [ -n "${SSPID:-}" ] || return 0
    wait "$SSPID" 2>/dev/null
    SSPID=
}

# With CONSOLE=1: the broker's console lines and `$SYS` counters during the run.
console_start() {
    CONPID=
    [ "$CONSOLE" = 1 ] && [ "$BROKER" = urmqtt ] || return 0
    python3 "$DIR/x11-console.py" "$HOST" "$PORT" "$CERTS" "${CONSOLE_S:-17}" "$DIR/console.out" 2>"$DIR/console.err" &
    CONPID=$!
    sleep 1
}

console_end() {
    [ -n "${CONPID:-}" ] || return 0
    wait "$CONPID" 2>/dev/null
    CONPID=
    {
        echo "### console $1 rep=$2"
        cat "$DIR/console.out"
    } >>"$OUT.console"
    # The console replays its last lines to every new subscriber: count only
    # the reports not seen in an earlier run (by their timestamps).
    local over drop late
    grep -E 'over budget' "$DIR/console.out" | sort -u >"$DIR/wd.cur"
    grep -E 'watchdog: aborting connection' "$DIR/console.out" | sort -u >"$DIR/wd.cur.abort"
    touch "$DIR/wd.seen" "$DIR/wd.seen.abort"
    over=$(comm -13 "$DIR/wd.seen" "$DIR/wd.cur" | wc -l)
    drop=$(comm -13 "$DIR/wd.seen.abort" "$DIR/wd.cur.abort" | wc -l)
    cat "$DIR/wd.cur" "$DIR/wd.seen" | sort -u >"$DIR/wd.seen.tmp" && mv "$DIR/wd.seen.tmp" "$DIR/wd.seen"
    cat "$DIR/wd.cur.abort" "$DIR/wd.seen.abort" | sort -u >"$DIR/wd.seen.tmp" && mv "$DIR/wd.seen.tmp" "$DIR/wd.seen.abort"
    late=$(grep -o '[0-9]* late tick(s), worst [0-9]* us' "$DIR/console.out" | sort -u | awk '{n+=$1; if ($5>w) w=$5} END{printf "late_ticks_in_window=%d worst_us=%d", n, w}')
    local steal excused
    steal=$(grep -o 'host steal [0-9]* us' "$DIR/console.out" | sort -u | awk '{n+=$3} END{printf "host_steal_us_in_window=%d", n}')
    excused=$(grep -c 'not charged' "$DIR/console.out")
    echo "CONSOLE new_watchdog_reports=$over new_aborted_connections=$drop $late $steal not_charged_lines_in_window=$excused" | tee -a "$OUT"
    grep -E 'SYSVAL .*(dropped|messages/(received|sent))' "$DIR/console.out" | sed 's/SYSVAL \$SYS\/broker\///' | tr '\n' ' ' | sed 's/^/DROPS /' | tee -a "$OUT"
    echo | tee -a "$OUT" >/dev/null
}

# The broker's own CPU use while a run is going: urMQTT publishes the busy
# percentage of every core in $SYS (refreshed every 5 s); for Mosquitto the
# CPU time of its process is read over ssh (utime+stime in ticks of 10 ms, so
# the value over 10 s is a percentage of one core).
busy_start() {
    : >"$DIR/busy.out"
    BUSYPID=
    if [ "$BROKER" = urmqtt ]; then
        mosquitto_sub -h "$HOST" -p "$PORT" --cafile "$CERTS/ca.pem" --cert "$CERTS/operator.pem" \
            --key "$CERTS/operator.key" --tls-version tlsv1.3 --insecure -V mqttv311 -i operator \
            -W 14 -v -t '$SYS/broker/cpu/busy/#' >"$DIR/busy.out" 2>/dev/null &
        BUSYPID=$!
    elif [ -n "${SSHVPS:-}" ]; then
        ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$DIR/id" "$SSHVPS" \
            'p=$(pidof mosquitto); a=$(awk "{print \$14+\$15}" /proc/$p/stat); sleep 10; b=$(awk "{print \$14+\$15}" /proc/$p/stat); echo "mosquitto_cpu_pct_10s=$((b-a))"' \
            >"$DIR/busy.out" 2>/dev/null &
        BUSYPID=$!
    fi
}

busy_end() {
    [ -n "$BUSYPID" ] || return 0
    wait "$BUSYPID" 2>/dev/null
    BUSYPID=
    if [ "$BROKER" = urmqtt ]; then
        awk '{v[$1]=$2} END{s=""; for(k=0;k<8;k++){key="$SYS/broker/cpu/busy/" k; if(key in v) s=s " c" k "=" v[key]} if(s!="") print "BROKERBUSY" s}' "$DIR/busy.out" | tee -a "$OUT"
    else
        sed 's/^/BROKERBUSY /' "$DIR/busy.out" | tee -a "$OUT"
    fi
}

sys_sample() { # prints broker-side numbers from $SYS (operator identity)
    local t
    if [ "$BROKER" = urmqtt ]; then
        t='$SYS/broker/memory/used $SYS/broker/memory/total $SYS/broker/clients/connected $SYS/broker/handshakes/done $SYS/broker/handshakes/refused $SYS/broker/handshakes/syn_dropped'
    else
        t='$SYS/broker/heap/current $SYS/broker/clients/connected'
    fi
    local args=()
    for x in $t; do args+=(-t "$x"); done
    mosquitto_sub -h "$HOST" -p "$PORT" --cafile "$CERTS/ca.pem" --cert "$CERTS/operator.pem" \
        --key "$CERTS/operator.key" --tls-version tlsv1.3 --insecure -V mqttv311 -i operator -v -W 6 "${args[@]}" 2>/dev/null |
        awk '{v[$1]=$2} END{for(k in v) printf "SYS %s=%s\n", k, v[k]}' | sort | tee -a "$OUT"
    if [ -n "${SSHVPS:-}" ]; then
        say "SYS rss_kb=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$DIR/id" "$SSHVPS" 'ps -o rss= -C mosquitto | head -1' 2>/dev/null | tr -d ' ')"
    fi
}

say "# $LABEL $(date -u +%FT%TZ) host=$HOST:$PORT cores=$CORES reps=$REPS"
say "# loadgen $(sha256sum "$DIR/urmqtt-loadgen" | cut -c1-12) kernel $(uname -r) nproc=$(nproc)"

for suite in $SUITES; do
    say "## suite $suite"
    case $suite in
    handshake)
        for th in 32 64 128; do
            for r in $(seq 1 "$REPS"); do
                run "handshake threads=$th" "$r" handshake "${COMMON[@]}" --threads "$th" --duration 10 --prefix "bench-$(uid)"
            done
        done
        ;;
    throughput)
        [ "$PUBSUB" = 1 ] || continue
        # THROUGHPUT_CFGS="QOS PAYLOAD PAIRS;..." picks a subset.
        IFS=';' read -ra tp_cfgs <<<"${THROUGHPUT_CFGS:-0 64 16;0 1024 16;1 64 16;1 1024 16;1 64 64}"
        for cfg in "${tp_cfgs[@]}"; do
            # shellcheck disable=SC2086 # cfg is a space-separated list of benchmark parameters
            set -- $cfg
            for r in $(seq 1 "$REPS"); do
                run "throughput qos=$1 payload=$2 pairs=$3" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers "$3" --subscribers "$3" --topics "$3" --qos "$1" --payload "$2" \
                    --rate 0 --duration 10 --warmup 2
            done
        done
        ;;
    latency)
        [ "$PUBSUB" = 1 ] || continue
        for q in 0 1; do
            for r in $(seq 1 "$REPS"); do
                run "latency qos=$q payload=64 pairs=8 rate=100" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers 8 --subscribers 8 --topics 8 --qos "$q" --payload 64 \
                    --rate 100 --duration 10 --warmup 2
            done
        done
        ;;
    sweep)
        # Offered load at fixed rates: what is delivered, how late, and whether
        # a connection is lost. 16 publishers and 16 subscribers on 16 topics.
        [ "$PUBSUB" = 1 ] || continue
        # SWEEP_CFGS="QOS PAYLOAD RATE;QOS PAYLOAD RATE;..." picks a subset.
        IFS=';' read -ra sweep_cfgs <<<"${SWEEP_CFGS:-0 64 100;0 64 300;0 64 1000;1 64 100;1 64 300;1 64 1000;0 1024 100;0 1024 300}"
        for cfg in "${sweep_cfgs[@]}"; do
            # shellcheck disable=SC2086 # cfg is a space-separated list of benchmark parameters
            set -- $cfg
            for r in $(seq 1 "$REPS"); do
                run "sweep qos=$1 payload=$2 rate=$3 pairs=16" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers 16 --subscribers 16 --topics 16 --qos "$1" --payload "$2" \
                    --rate "$3" --duration 10 --warmup 2
            done
        done
        # One connection each way, as fast as the broker takes it: the limit of a
        # single TCP flow over this path.
        for cfg in "0 1024" "0 64"; do
            # shellcheck disable=SC2086 # cfg is a space-separated list of benchmark parameters
            set -- $cfg
            for r in $(seq 1 "$REPS"); do
                run "single-flow qos=$1 payload=$2" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers 1 --subscribers 1 --topics 1 --qos "$1" --payload "$2" \
                    --rate 0 --duration 10 --warmup 2
            done
        done
        ;;
    single)
        [ "$PUBSUB" = 1 ] || continue
        for cfg in "0 64" "0 1024" "1 64"; do
            # shellcheck disable=SC2086 # cfg is a space-separated list of benchmark parameters
            set -- $cfg
            for r in $(seq 1 "$REPS"); do
                run "single-flow qos=$1 payload=$2" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers 1 --subscribers 1 --topics 1 --qos "$1" --payload "$2" \
                    --rate 0 --duration 10 --warmup 2
            done
        done
        ;;
    fanout)
        [ "$PUBSUB" = 1 ] || continue
        for cfg in "0 100 50" "0 1000 10" "1 100 50" "0 100 0"; do
            # shellcheck disable=SC2086 # cfg is a space-separated list of benchmark parameters
            set -- $cfg
            for r in $(seq 1 "$REPS"); do
                run "fanout qos=$1 subs=$2 rate=$3" "$r" pubsub "${COMMON[@]}" --prefix "svc-$(uid)" \
                    --publishers 1 --subscribers "$2" --topics 1 --qos "$1" --payload 64 \
                    --rate "$3" --duration 10 --warmup 2 --open-par 16
            done
        done
        ;;
    idle)
        # Connections are kept by one process; the broker's own figures are read
        # while they are open. The client closes first, so its ports sit in
        # TIME_WAIT for 60 s afterwards: wait before the next size.
        say "IDLE baseline"
        sys_sample
        for n in ${IDLE_SIZES:-5000 10000 20000}; do
            guard
            say "IDLE clients=$n"
            rm -f "$DIR/hold.out" "$DIR/hold.err"
            "${LG[@]}" hold "${COMMON[@]}" --clients "$n" --threads 64 --duration 25 --keepalive "${KEEPALIVE:-60}" --prefix "bench-$(uid)" \
                >"$DIR/hold.out" 2>"$DIR/hold.err" &
            pid=$!
            t=0
            until grep -q 'connections established' "$DIR/hold.out" 2>/dev/null || [ $t -ge "${IDLE_WAIT:-150}" ]; do
                sleep 1
                t=$((t + 1))
                if [ -n "${SSHVPS:-}" ] && [ $((t % 20)) -eq 0 ]; then
                    say "IDLE progress t=${t}s vps: $(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$DIR/id" "$SSHVPS" 'ss -s | sed -n 2p; ps -o pcpu=,rss= -C mosquitto' 2>/dev/null | tr '\n' ' ')"
                fi
            done
            sleep 3
            say "IDLE opened_in=${t}s errors=$(wc -l <"$DIR/hold.err") first: $(head -2 "$DIR/hold.err" | tr '\n' '|')"
            say "IDLE generator_rss_kb=$(ps -o rss= -p $pid | tr -d ' ') generator_threads=$(ps -o nlwp= -p $pid | tr -d ' ')"
            grep -E 'hold:' "$DIR/hold.out" | tee -a "$OUT"
            sys_sample
            wait $pid
            say "IDLE after close"
            sleep 3
            sys_sample
            sleep 65
        done
        ;;
    esac
done
say "# done $(date -u +%FT%TZ)"
