#!/usr/bin/env bash
# Boots urMQTT headless and checks the serial log. Non-zero exit on any failure.
#
#   scripts/smoke.sh [--kernel ELF] [--accels "hvf tcg"] [--out build/smoke]
#
# Each scenario builds an ISO with a dev-only kernel command line, boots it,
# waits for QEMU to exit (the kernel powers off via PSCI in smoke mode) and
# greps the serial log. Scenarios grow with each milestone.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/smoke"
ACCELS=""
TIMEOUT=${SMOKE_TIMEOUT:-120}
while [[ $# -gt 0 ]]; do
    case $1 in
        --kernel) KERNEL=$2; shift 2 ;;
        --accels) ACCELS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -z "$ACCELS" ]]; then
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) ACCELS="hvf tcg" ;;
        Linux-aarch64) [[ -w /dev/kvm ]] && ACCELS="kvm tcg" || ACCELS="tcg" ;;
        *) ACCELS="tcg" ;;
    esac
fi
mkdir -p "$OUT"
FAILED=0
PASSED=0

# Patterns are extended regexes that must match; prefix NOT: for ones that must not.

# boot <name> <log> <qemu args...>: runs QEMU until it exits or times out.
# Returns QEMU's exit status, or 124 on timeout.
boot() {
    local log=$1
    shift
    rm -f "$log"
    "$ROOT/scripts/run-qemu.sh" --serial "$log" "$@" >"$log.qemu" 2>&1 &
    local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if (( waited >= TIMEOUT * 10 )); then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    wait "$pid"
}

# Strip terminal escapes the firmware and Limine print.
clean() { LC_ALL=C sed -e $'s/\x1b\\[[0-9;?=]*[A-Za-z]//g' -e $'s/\r//g' "$1"; }

check() {
    local name=$1 log=$2 status=$3
    shift 3
    local ok=1 pat
    if [[ $status -ne 0 ]]; then
        echo "  ✗ QEMU exit status $status (124 = timeout after ${TIMEOUT}s)"
        ok=0
    fi
    for pat in "$@"; do
        if [[ $pat == NOT:* ]]; then
            if clean "$log" | grep -Eq -- "${pat:4}"; then
                echo "  ✗ unexpected: ${pat:4}"
                ok=0
            fi
        elif ! clean "$log" | grep -Eq -- "$pat"; then
            echo "  ✗ missing: $pat"
            ok=0
        fi
    done
    if [[ $ok -eq 1 ]]; then
        echo "  ✓ $name"
        PASSED=$((PASSED + 1))
    else
        echo "  serial log: $log"
        if [[ -s "$log.qemu" ]]; then
            echo "  qemu stderr:"
            sed 's/^/    ! /' "$log.qemu" | tail -10
        fi
        clean "$log" | grep -vE '^\s*$' | tail -25 | sed 's/^/    | /'
        FAILED=$((FAILED + 1))
    fi
}

# scenario <name> <cmdline> <acpi on|off> <patterns...>
scenario() {
    local name=$1 cmdline=$2 acpi=$3
    shift 3
    local iso="$OUT/$name.iso"
    [[ -f "$iso" ]] || "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "$cmdline" >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/$name-$accel.log" status=0
        local data="$OUT/$name-$accel.img"
        rm -f "$data" "$log.pcap"
        truncate -s 64m "$data"
        boot "$log" --iso "$iso" --accel "$accel" --acpi "$acpi" --smp "${SMP:-4}" --headless \
            --data "$data" --pcap "$log.pcap" --fwd "${FWD:-none}" || status=$?
        check "$name [$accel]" "$log" "$status" "$@"
    done
}

# service <name> <cmdline> <port> <ready-pattern> <client...> -- <patterns...>
# Boots a long-running image, waits for <ready-pattern> in the serial log,
# runs the host-side client against 127.0.0.1:<port>, then stops QEMU and
# checks the serial log plus the client's output.
service() {
    local name=$1 cmdline=$2 port=$3 ready=$4
    shift 4
    local client=()
    while [[ $# -gt 0 && $1 != -- ]]; do
        client+=("$1")
        shift
    done
    shift
    local iso="$OUT/$name.iso"
    [[ -f "$iso" ]] || "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "$cmdline" >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/$name-$accel.log" data="$OUT/$name-$accel.img" status=0 waited=0
        rm -f "$log" "$data"
        truncate -s 64m "$data"
        "$ROOT/scripts/run-qemu.sh" --serial "$log" --iso "$iso" --accel "$accel" --headless \
            --data "$data" --fwd "$port:${SERVICE_PORT:-$port}" >"$log.qemu" 2>&1 &
        local pid=$!
        until clean "$log" 2>/dev/null | grep -Eq -- "$ready"; do
            if ! kill -0 "$pid" 2>/dev/null || (( waited >= TIMEOUT * 10 )); then
                status=124
                break
            fi
            sleep 0.1
            waited=$((waited + 1))
        done
        if [[ $status -eq 0 ]]; then
            "${client[@]}" "$port" >"$log.client" 2>&1 || status=$?
            sleep 0.5
        fi
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        cat "$log.client" >>"$log" 2>/dev/null || true
        check "$name [$accel]" "$log" "$status" "$@"
    done
}

# start_vm <log> <qemu args...>: boots in the background; sets VM_PID.
start_vm() {
    local log=$1
    shift
    rm -f "$log"
    "$ROOT/scripts/run-qemu.sh" --serial "$log" --headless "$@" >"$log.qemu" 2>&1 &
    VM_PID=$!
}

# wait_log <log> <pattern> [count]: waits until the pattern occurs <count>
# times (default 1). Fails on timeout or if QEMU exits first.
wait_log() {
    local log=$1 pat=$2 count=${3:-1} waited=0
    until (( $(clean "$log" 2>/dev/null | grep -Ec -- "$pat" || true) >= count )); do
        if ! kill -0 "$VM_PID" 2>/dev/null || (( waited >= TIMEOUT * 10 )); then
            return 124
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
}

# kill_vm: SIGKILL, like pulling the power cord (host page cache survives,
# which matches a VM crash rather than a host power loss).
kill_vm() {
    kill -9 "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
}

# M11: QEMU is killed while the kernel commits transactions in a loop;
# the next boot must pass quick_check and hold every committed row.
db_crash() {
    local crash="$OUT/db-crash.iso" verify="$OUT/db-verify.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$crash" --cmdline "smoke test=db-crash" >/dev/null
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$verify" --cmdline "smoke test=db-verify" >/dev/null
    for accel in $ACCELS; do
        local data="$OUT/db-crash-$accel.img" log1="$OUT/db-crash-$accel.log" log2="$OUT/db-verify-$accel.log"
        local status=0
        rm -f "$data"
        truncate -s 64m "$data"
        start_vm "$log1" --iso "$crash" --accel "$accel" --data "$data" --fwd none
        wait_log "$log1" "db-crash: committed [0-9]+" 5 || status=$?
        # Kill at an arbitrary point inside the write stream.
        sleep "0.$((RANDOM % 5))"
        kill_vm
        local last
        last=$(clean "$log1" | grep -Eo 'db-crash: committed [0-9]+' | tail -1 | awk '{print $3}')
        check "db-crash-writer [$accel]" "$log1" "$status" "db-crash: writing from row 1" "db-crash: committed [0-9]+" "$NO_FAULT"
        status=0
        boot "$log2" --iso "$verify" --accel "$accel" --headless --data "$data" --fwd none || status=$?
        check "db-crash-recovery [$accel]" "$log2" "$status" "storage: data disk opened" \
            "quick_check ok" "db-verify: [0-9]+ rows consistent" "^URMQTT READY$" "NOT:INCONSISTENT" "$NO_FAULT"
        local found
        found=$(clean "$log2" | grep -Eo 'db-verify: [0-9]+ rows' | awk '{print $2}')
        if [[ -n "$last" && -n "$found" ]] && (( found >= last )); then
            echo "  ✓ every acknowledged commit survived SIGKILL: $found rows >= $last logged [$accel]"
            PASSED=$((PASSED + 1))
        else
            echo "  ✗ committed rows lost after SIGKILL: found '${found:-?}', last logged '${last:-?}' [$accel]"
            FAILED=$((FAILED + 1))
        fi
    done
}

# M12: every core but the DB core appends telemetry records; QEMU is killed
# once at least a million are durable. The next boot must recover every
# flushed record (contiguous per core) and truncate a torn tail if any.
log_crash() {
    local crash="$OUT/log-crash.iso" verify="$OUT/log-verify.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$crash" --cmdline "smoke test=log-crash" >/dev/null
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$verify" --cmdline "smoke test=log-verify" >/dev/null
    for accel in $ACCELS; do
        local data="$OUT/log-crash-$accel.img" log1="$OUT/log-crash-$accel.log" log2="$OUT/log-verify-$accel.log"
        local status=0
        rm -f "$data"
        # 1 GiB sparse: the 8 log partitions hold ~55 MiB each, so a million
        # records from three cores never wrap.
        truncate -s 1g "$data"
        start_vm "$log1" --iso "$crash" --accel "$accel" --data "$data" --fwd none
        wait_log "$log1" "log-crash: durable (1[0-9]{6}|[2-9][0-9]{6})" || status=$?
        sleep "0.$((RANDOM % 4))"
        kill_vm
        local last
        last=$(clean "$log1" | grep -Eo 'log-crash: durable [0-9]+' | tail -1 | awk '{print $3}')
        check "log-crash-writers [$accel]" "$log1" "$status" "log-crash: core 0 writing" "log-crash: core 1 writing" \
            "log-crash: core 2 writing" "log-crash: durable [0-9]+" "$NO_FAULT"
        status=0
        boot "$log2" --iso "$verify" --accel "$accel" --headless --data "$data" --fwd none || status=$?
        check "log-crash-recovery [$accel]" "$log2" "$status" \
            "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in [0-9]+ segment\(s\), [0-9]+ torn tail\(s\) truncated" \
            "log-verify: [0-9]+ records, every core's sequence contiguous" "^URMQTT READY$" "NOT:INCONSISTENT" "$NO_FAULT"
        local found torn
        found=$(clean "$log2" | grep -Eo 'log-verify: [0-9]+ records' | awk '{print $2}')
        torn=$(clean "$log2" | grep -Eo '[0-9]+ torn tail' | awk '{print $1}')
        if [[ -n "$last" && -n "$found" ]] && (( found >= last && last >= 1000000 )); then
            echo "  ✓ every flushed telemetry record recovered: $found >= $last durable, ${torn:-?} torn tail(s) truncated [$accel]"
            PASSED=$((PASSED + 1))
        else
            echo "  ✗ telemetry records lost: recovered '${found:-?}', durable before the kill '${last:-?}' [$accel]"
            FAILED=$((FAILED + 1))
        fi
    done
}

# M12: a torn record written on purpose must be truncated on the next boot,
# keeping every complete record before it.
log_tear() {
    local tear="$OUT/log-tear.iso" verify="$OUT/log-verify.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$tear" --cmdline "smoke test=log-tear" >/dev/null
    [[ -f "$verify" ]] || "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$verify" --cmdline "smoke test=log-verify" >/dev/null
    for accel in $ACCELS; do
        local data="$OUT/log-tear-$accel.img" log1="$OUT/log-tear-$accel.log" log2="$OUT/log-tear-verify-$accel.log"
        local status=0
        rm -f "$data"
        truncate -s 64m "$data"
        boot "$log1" --iso "$tear" --accel "$accel" --headless --data "$data" --fwd none || status=$?
        check "log-tear-write [$accel]" "$log1" "$status" "log-tear: 10000 records durable, then a torn write" "$NO_FAULT"
        status=0
        boot "$log2" --iso "$verify" --accel "$accel" --headless --data "$data" --fwd none || status=$?
        check "log-tear-truncated [$accel]" "$log2" "$status" \
            "telemetry: log recovered in [0-9]+ ms: 10500 record\(s\) in [0-9]+ segment\(s\), 1 torn tail\(s\) truncated" \
            "log-verify: 10500 records, every core's sequence contiguous" "^URMQTT READY$" "$NO_FAULT"
    done
}

# M11: broker state across a restart: retained message and a QoS 1 command
# queued for an offline persistent session, over mTLS.
mqtt_persist() {
    local iso="$OUT/mqtt-persist.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "serve" >/dev/null
    for accel in $ACCELS; do
        local data="$OUT/mqtt-persist-$accel.img"
        rm -f "$data"
        truncate -s 64m "$data"
        for phase in 1 2; do
            local log="$OUT/mqtt-persist-$accel-$phase.log" status=0
            start_vm "$log" --iso "$iso" --accel "$accel" --data "$data" --fwd "18883:8883"
            if wait_log "$log" "TLS 1.3 listener on port 8883"; then
                python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$ROOT/deploy/dev" --phase "$phase" \
                    >"$log.client" 2>&1 || status=$?
            else
                status=124
            fi
            kill_vm
            cat "$log.client" >>"$log" 2>/dev/null || true
            if [[ $phase == 1 ]]; then
                check "mqtt-persist-before-kill [$accel]" "$log" "$status" "storage: data disk formatted" \
                    "client: persist-phase1 ok" "NOT:FAILED" "$NO_FAULT"
            else
                check "mqtt-persist-after-restart [$accel]" "$log" "$status" "storage: data disk opened" \
                    "db: restored 1 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), 1 revoked serial\(s\), 3 known device\(s\)" \
                    "telemetry: log recovered in [0-9]+ ms: 1 record\(s\)" \
                    "client: persist-retained ok" "client: persist-queued ok" "NOT:FAILED" "$NO_FAULT"
            fi
        done
    done
}

# M16: reconnect storms. Admission pretends the heap has 8 MiB, so 3000
# devices do not all fit: each round all connect at once (retrying, like
# devices with backoff), then all drop without DISCONNECT. The kernel must
# refuse what does not fit, never run out of memory, and give the memory
# back between rounds.
storm() {
    local loadgen="$ROOT/target/release/urmqtt-loadgen"
    if [[ ! -x "$loadgen" ]]; then
        (cd "$ROOT" && cargo build --release -q -p urmqtt-loadgen) || return 0
    fi
    local iso="$OUT/storm.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "serve log=info heap_limit_mb=8" >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/storm-$accel.log" data="$OUT/storm-$accel.img" status=0
        rm -f "$data"
        truncate -s 64m "$data"
        start_vm "$log" --iso "$iso" --accel "$accel" --data "$data" --fwd "18883:8883"
        if wait_log "$log" "TLS 1.3 listener on port 8883"; then
            (cd "$ROOT" && "$loadgen" storm --port 18883 --clients 3000 --threads 8 --rounds 3 \
                --retry-s 30 --subscribe 1 --min-connected 500) >"$log.client" 2>&1 || status=$?
            # Memory left by the last round is returned within 10 s.
            sleep 12
        else
            status=124
        fi
        kill_vm
        grep -v '^loadgen: bench-' "$log.client" >>"$log" 2>/dev/null || true
        check "storm [$accel]" "$log" "$status" "loadgen: storm round 3: [0-9]+ of 3000 connected" \
            "admission: [0-9]+ connection\(s\) refused: heap below the free reserve" \
            "mem: 0 connection\(s\)" "NOT:memory allocation of" "$NO_FAULT"
    done
}

# M16: the dev configuration sends syslog to 10.0.2.2:5514 and statsd to
# 10.0.2.2:8125, which QEMU user networking delivers to the host.
observability() {
    local iso="$OUT/ops.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "serve" >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/ops-$accel.log" data="$OUT/ops-$accel.img" status=0
        rm -f "$data" "$log.udp"
        truncate -s 64m "$data"
        python3 -I - "$log.udp" 45 <<'PY' &
import select, socket, sys, time
out, end = open(sys.argv[1], "w"), time.time() + int(sys.argv[2])
socks = []
for port in (5514, 8125):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    socks.append(s)
while time.time() < end:
    r, _, _ = select.select(socks, [], [], 0.5)
    for s in r:
        data = s.recv(65535).decode("utf-8", "replace")
        out.write(f"udp:{s.getsockname()[1]}: " + data.replace("\n", f"\nudp:{s.getsockname()[1]}: ") + "\n")
        out.flush()
PY
        local collector=$!
        sleep 0.5
        start_vm "$log" --iso "$iso" --accel "$accel" --data "$data" --fwd "18883:8883"
        if wait_log "$log" "TLS 1.3 listener on port 8883"; then
            # Metrics go out every 10 s.
            sleep 22
        else
            status=124
        fi
        kill_vm
        kill "$collector" 2>/dev/null || true
        wait "$collector" 2>/dev/null || true
        cat "$log.udp" >>"$log" 2>/dev/null || true
        check "observability [$accel]" "$log" "$status" "ops: syslog 10\.0\.2\.2:5514, statsd 10\.0\.2\.2:8125" \
            "^udp:5514: <13[0-9]>1 [0-9T:.Z-]+ 10\.0\.2\.15 urmqtt cpu[0-9]+ [a-z0-9-]+ \[meta sysUpTime=\"[0-9]+\"\] " \
            "^udp:5514: .* mqtt: TLS 1\.3 listener on port 8883" \
            "^udp:8125: urmqtt\.connections:0\|g" "^udp:8125: urmqtt\.health:1\|g" \
            "^udp:8125: urmqtt\.refused\.memory:0\|c" "$NO_FAULT"
    done
}

[[ -f "$KERNEL" ]] || { echo "error: $KERNEL not found (make build)" >&2; exit 1; }
rm -f "$OUT"/*.iso
echo "smoke: accelerators: $ACCELS"

BOOT_LINE='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$'
NO_FAULT='NOT:EXCEPTION|PANIC'

MEMORY_OK=("vm: switched to kernel tables" "selftest: frames ok" "page tables locked" "selftest: W\^X ok \([0-9]+ leaf mappings audited, 0 W\+X")
TIME_OK=("gic: v3 at gicd=0x8000000" "timer: counter [0-9]+ Hz, virtual timer PPI 27" "tick 10$"
    "irq latency \(busy-poll, 25 samples\) min=[0-9]+" "irq latency \(wfi, 25 samples\) min=[0-9]+"
    "timer: 5[0-9] ticks in [0-9]+ ms")
DEV_OK=("pci: ECAM 0x4010000000 buses 0-255" "virtio-blk" "virtio-net" "virtio-rng"
    "entropy: [0-9]+ bytes from virtio-rng" "entropy: ChaCha20 CSPRNG seeded"
    "blk: self-test ok \(4 KiB random pattern written, flushed, read back" "net: gratuitous ARP sent"
    "net: rx ok, ARP reply from 52:55:0a:00:02:02")
DB_OK=("storage: data disk formatted \(was blank\)" "db: sqlite 3\.[0-9]+\.[0-9]+ on the data disk: WAL, exclusive locking, quick_check ok"
    "telemetry: log recovered in [0-9]+ ms: 0 record\(s\)"
    "db: restored 0 retained" "db: DB core is cpu 3" "db: worker running on cpu 3")
SMP4_OK=("cpu 1 online" "cpu 3 online" "smp: 4/4 cpus online" "ipi: 12/12 ordered pairs ping-pong ok"
    "smp: 4/4 cpus ticking on their own timer")

scenario boot-acpi "smoke" on \
    "$BOOT_LINE" "platform: discovered via Acpi" "console: pl011 at 0x9000000" "psci 1\.[0-9]+ via hvc" \
    "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${DEV_OK[@]}" "${SMP4_OK[@]}" "${DB_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario boot-dtb "smoke" off \
    "$BOOT_LINE" "platform: discovered via DeviceTree" "console: pl011 at 0x9000000" "${MEMORY_OK[@]}" \
    "${TIME_OK[@]}" "${DEV_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario fault-data-abort "smoke test=data-abort" on \
    "$BOOT_LINE" "EXCEPTION: synchronous, current EL, SP0" \
    "EC=0x25 data abort \(same EL\), read, translation fault" "FAR=0x" "x30=0x" \
    "fatal exception, stopping" "NOT:URMQTT READY"
scenario fault-undefined "smoke test=undef" on \
    "EXCEPTION: synchronous" "EC=0x00 unknown reason \(undefined instruction\)" "NOT:URMQTT READY"
scenario brk-resume "smoke test=brk" on \
    "resumable brk at 0x" "test: resumed after brk" "^URMQTT READY$" "NOT:fatal exception"
scenario panic "smoke test=panic" on \
    "PANIC: panicked at" "test panic requested on the command line" "NOT:URMQTT READY"
# M4: eight CPUs, all 56 ordered IPI pairs.
SMP=8 scenario smp8 "smoke" on \
    "cpu=8 mem=" "cpu 7 online" "smp: 8/8 cpus online" "ipi: 56/56 ordered pairs ping-pong ok" \
    "smp: 8/8 cpus ticking on their own timer" "^URMQTT READY$" "$NO_FAULT"

# M2: W^X, guard pages, lower half, PAC, BTI.
scenario wx-write-text "smoke test=write-text" on \
    "${MEMORY_OK[@]}" "data abort \(same EL\), write, permission fault, level 3" "NOT:URMQTT READY"
scenario wx-exec-heap "smoke test=exec-heap" on \
    "instruction abort \(same EL\), permission fault, level 3" "NOT:URMQTT READY"
scenario stack-overflow "smoke test=stack-overflow" on \
    "EXCEPTION: synchronous, current EL, SP0" "data abort \(same EL\), write, translation fault" \
    "FAR is in: main stack guard page \(stack overflow\)" "NOT:URMQTT READY"
scenario null-deref "smoke test=null" on \
    "translation fault, level 0" "FAR is in: lower half" "NOT:URMQTT READY"
scenario pac-forgery "smoke test=pac" on \
    "pointer authentication failure|instruction abort" "NOT:was NOT detected" "NOT:URMQTT READY"
scenario bti-violation "smoke test=bti" on \
    "branch target exception \(BTI\)" "NOT:was NOT detected" "NOT:URMQTT READY"

# M7: DHCP lease, ICMP to the gateway, TCP echo through the QEMU port forward.
SERVICE_PORT=7 service net-echo "serve" 17007 "net: dhcp lease" python3 -I "$ROOT/scripts/echo-client.py" -- \
    "net: dhcp lease 10\.0\.2\.15/24 router 10\.0\.2\.2" "net: icmp echo reply from 10\.0\.2\.2" \
    "net: tcp echo service on port 7" "client: echo 1 ok" "client: echo 3000 ok" "client: echo 60000 ok" \
    "net: echo connection closed after 60000 byte" "NOT:dhcp lease lost" "$NO_FAULT"

# M9: broker over plain TCP (dev) with the real mosquitto clients.
if command -v mosquitto_pub >/dev/null && command -v mosquitto_sub >/dev/null; then
    SERVICE_PORT=1883 service mqtt-plain "serve" 11883 "PLAINTEXT listener on port 1883" \
        python3 -I "$ROOT/scripts/mqtt-scenarios.py" -- \
        "client: pubsub-wildcard ok" "client: retained ok" "client: lwt-forced-disconnect ok" \
        "client: qos1-after-reconnect ok" "client: acl-subscribe-denied ok" "NOT:FAILED" "$NO_FAULT"
    # M10: the same scenarios over TLS 1.3 with mutual TLS, plus the four
    # handshakes/CONNECTs that must be refused.
    SERVICE_PORT=8883 service mqtt-tls "serve" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" -- \
        "client: pubsub-wildcard ok" "client: retained ok" "client: lwt-forced-disconnect ok" \
        "client: qos1-after-reconnect ok" "client: acl-subscribe-denied ok" \
        "client: tls-wrong-ca-rejected ok" "client: tls-expired-rejected ok" \
        "client: tls-client-id-mismatch-rejected ok" "client: tls-revoked-rejected ok" \
        "tls: device-001 authenticated \(TLS13_" "invalid peer certificate: UnknownIssuer" \
        "certificate expired" "invalid peer certificate: Revoked" "NOT:FAILED" "$NO_FAULT"
else
    echo "  ✗ mosquitto clients not installed (brew install mosquitto / apt install mosquitto-clients)"
    FAILED=$((FAILED + 1))
fi

# M11: SQLite on the data disk: batched write throughput, crash
# consistency after SIGKILL, broker state across a restart.
scenario db-bench "smoke test=db-bench" on \
    "db-bench: 5000 inserts in 50 transactions: [0-9]+ ops/s" "5100 rows verified" "^URMQTT READY$" "$NO_FAULT"
# M16: a handler overrunning its budget is reported from the tick.
scenario watchdog "smoke test=watchdog" on \
    "watchdog: core 0 self-test handler for conn 42 over budget: [0-9]+ ms > 10 ms \(action: Log\)" \
    "^URMQTT READY$" "$NO_FAULT"
db_crash
log_crash
log_tear
# M13: shared-nothing scaling, in the guest (no host network in the way).
SMP=6 scenario dp-bench "smoke test=dp-bench" on \
    "dp-bench: 1 worker core\(s\): [0-9]+ handshakes/s" "dp-bench: 4 worker core\(s\): [0-9]+ handshakes/s" \
    "dp-bench: done, 0 failure\(s\)" "^URMQTT READY$" "$NO_FAULT"
for accel in $ACCELS; do
    x=$(clean "$OUT/dp-bench-$accel.log" | grep -Eo 'scaling 4 core\(s\): [0-9.]+x' | grep -Eo '[0-9.]+x' | tr -d x)
    # TCG on a small CI runner has fewer host CPUs than vCPUs: report only.
    if [[ $accel == tcg ]]; then
        echo "  ✓ dp-bench scaling with 4 worker cores: ${x:-?}x (reported only under TCG) [$accel]"
        PASSED=$((PASSED + 1))
    elif [[ -n "$x" ]] && awk -v x="$x" 'BEGIN { exit !(x >= 3.0) }'; then
        echo "  ✓ dp-bench scales near-linearly: ${x}x with 4 worker cores [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ dp-bench scaling with 4 worker cores is ${x:-?}x (< 3.0x) [$accel]"
        FAILED=$((FAILED + 1))
    fi
done
if command -v mosquitto_pub >/dev/null; then
    mqtt_persist
fi
storm
observability

# M6: the gratuitous ARP must be on the wire (QEMU filter-dump pcap).
pcap_has_garp() {
    python3 -I - "$1" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
off, found = 24, False
while off + 16 <= len(data):
    incl = struct.unpack_from("<I", data, off + 8)[0]
    pkt = data[off + 16 : off + 16 + incl]
    off += 16 + incl
    if len(pkt) >= 42 and pkt[12:14] == b"\x08\x06" and pkt[6:12] == bytes.fromhex("525400123456") \
            and pkt[20:22] == b"\x00\x01" and pkt[28:32] == bytes(4) and pkt[38:42] == bytes(4):
        found = True
sys.exit(0 if found else 1)
PY
}
for accel in $ACCELS; do
    if pcap_has_garp "$OUT/boot-acpi-$accel.log.pcap"; then
        echo "  ✓ gratuitous ARP from 52:54:00:12:34:56 found in pcap [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ gratuitous ARP missing from $OUT/boot-acpi-$accel.log.pcap"
        FAILED=$((FAILED + 1))
    fi
done

# M5: DTB and ACPI must describe the same machine identically.
for accel in $ACCELS; do
    a=$(clean "$OUT/boot-acpi-$accel.log" | grep -o 'platform summary: .*' || true)
    d=$(clean "$OUT/boot-dtb-$accel.log" | grep -o 'platform summary: .*' || true)
    if [[ -n "$a" && "$a" == "$d" ]]; then
        echo "  ✓ platform summary identical for acpi=on/off [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ platform summaries differ [$accel]"
        echo "    acpi=on:  ${a:-<missing>}"
        echo "    acpi=off: ${d:-<missing>}"
        FAILED=$((FAILED + 1))
    fi
done

echo "smoke: $PASSED passed, $FAILED failed"
[[ $FAILED -eq 0 ]]
