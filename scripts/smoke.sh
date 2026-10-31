#!/usr/bin/env bash
# Boots urMQTT headless and checks the serial log. Non-zero exit on any failure.
#
#   scripts/smoke.sh [--kernel ELF] [--accels "hvf tcg"] [--out build/smoke]
#   scripts/smoke.sh --arch x86_64 [--accels "tcg"]       (the x86_64 suite: X2 boot/fault, X8 parity)
#   scripts/smoke.sh --arch universal                     (the universal ISO on both architectures, X10)
#
# The live scenarios (O3, ADR-054) boot the ISO's first entry with NO disk:
# the broker runs from RAM, serves mTLS, and a reboot loses what it held.
#
# Each scenario builds an ISO with a dev-only kernel command line, boots it,
# waits for QEMU to exit (the kernel powers off via PSCI in smoke mode) and
# greps the serial log. Scenarios grow with each milestone.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL="$ROOT/target/aarch64-unknown-none/release/urmqtt"
OUT="$ROOT/build/smoke"
ACCELS=""
ARCH=aarch64
TIMEOUT=${SMOKE_TIMEOUT:-120}
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch) ARCH=$2; shift 2 ;;
        --kernel) KERNEL=$2; shift 2 ;;
        --accels) ACCELS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ $ARCH == x86_64 ]]; then
    [[ $KERNEL == "$ROOT/target/aarch64-unknown-none/release/urmqtt" ]] \
        && KERNEL="$ROOT/target/x86_64-urmqtt-none/release/urmqtt"
    if [[ -z "$ACCELS" ]]; then
        case "$(uname -s)-$(uname -m)" in
            Linux-x86_64) [[ -w /dev/kvm ]] && ACCELS="kvm tcg" || ACCELS="tcg" ;;
            *) ACCELS="tcg" ;;
        esac
    fi
elif [[ $ARCH == universal ]]; then
    # One ISO, four machines: aarch64 under HVF and TCG, x86_64 UEFI and BIOS under TCG.
    KERNEL_A64="$ROOT/target/aarch64-unknown-none/release/urmqtt"
    KERNEL_X86="$ROOT/target/x86_64-urmqtt-none/release/urmqtt"
    KERNEL=$KERNEL_A64
    [[ -n "$ACCELS" ]] || case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) ACCELS="hvf tcg" ;;
        *) ACCELS="tcg" ;;
    esac
elif [[ $ARCH != aarch64 ]]; then
    echo "error: --arch aarch64|x86_64|universal" >&2; exit 2
fi
# run-qemu.sh and mkiso.sh take their architecture from here.
[[ $ARCH == universal ]] || export URMQTT_ARCH=$ARCH
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

# Single-disk model (S1, STORAGE-PLAN §2a): every VM boots one disk, a copy
# of the raw GPT image (scripts/mkraw.py) on a larger disk, and the kernel
# keeps its data in a partition of that disk.
#
# mkimg <image> <cmdline>: the raw boot image with <cmdline> (once per run);
# its ESP is kept as <image>.esp for set_esp.
mkimg() {
    local out=$1 cmdline=$2
    [[ -f "$out" ]] && return 0
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$out.iso" --cmdline "$cmdline" --esp-out "$out.esp" >/dev/null
    python3 -I "$ROOT/scripts/mkraw.py" "$out.esp" "$out" >/dev/null
    rm -f "$out.iso"
}

# fresh_disk <image> <disk> [size]: a new VM disk (default 64 MiB).
fresh_disk() {
    rm -f "$2"
    cp "$1" "$2"
    truncate -s "${3:-64m}" "$2"
}

# set_esp <disk> <image>: the next boot of <disk> runs <image>'s ESP (its
# kernel command line) with the data partition kept, as an offline kernel
# update does. The ESP starts at 1 MiB in every image.
set_esp() {
    dd if="$2.esp" of="$1" bs=1048576 seek=1 conv=notrunc status=none
}

check() {
    local name=$1 log=$2 status=$3
    shift 3
    local ok=1 pat text="$log.clean"
    if [[ $status -ne 0 ]]; then
        echo "  ✗ QEMU exit status $status (124 = timeout after ${TIMEOUT}s)"
        ok=0
    fi
    # Grep a file, not `clean | grep -q`: with pipefail, grep -q quitting at
    # the first match can SIGPIPE the writer and turn a match into a miss.
    clean "$log" >"$text"
    for pat in "$@"; do
        if [[ $pat == NOT:* ]]; then
            if grep -Eq -- "${pat:4}" "$text"; then
                echo "  ✗ unexpected: ${pat:4}"
                ok=0
            fi
        elif ! grep -Eq -- "$pat" "$text"; then
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
    # SMOKE_SCENARIOS=<regex>: run only the scenarios whose name matches (dev
    # shortcut, e.g. 'crypto|watchdog'); unset runs them all.
    [[ -z ${SMOKE_SCENARIOS:-} || $name =~ $SMOKE_SCENARIOS ]] || return 0
    local iso="$OUT/$name.raw"
    mkimg "$iso" "$cmdline"
    for accel in $ACCELS; do
        local log="$OUT/$name-$accel.log" status=0
        local data="$OUT/$name-$accel.img"
        rm -f "$log.pcap"
        fresh_disk "$iso" "$data"
        boot "$log" --disk "$data" --accel "$accel" --acpi "$acpi" --smp "${SMP:-4}" --headless \
            --pcap "$log.pcap" --fwd "${FWD:-none}" || status=$?
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
    [[ -z ${SMOKE_SCENARIOS:-} || $name =~ $SMOKE_SCENARIOS ]] || return 0
    local client=()
    while [[ $# -gt 0 && $1 != -- ]]; do
        client+=("$1")
        shift
    done
    shift
    local iso="$OUT/$name.raw"
    mkimg "$iso" "$cmdline"
    for accel in $ACCELS; do
        local log="$OUT/$name-$accel.log" data="$OUT/$name-$accel.img" status=0 waited=0
        rm -f "$log"
        fresh_disk "$iso" "$data"
        "$ROOT/scripts/run-qemu.sh" --serial "$log" --disk "$data" --accel "$accel" --headless \
            --fwd "$port:${SERVICE_PORT:-$port}" >"$log.qemu" 2>&1 &
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

# H2: session-ticket keys are per boot. A ticket taken before a reboot is
# offered to the new boot: a full handshake, counted as an unknown key.
ticket_restart() {
    local iso="$OUT/ticket-restart.raw"
    mkimg "$iso" "serve"
    for accel in $ACCELS; do
        local log1="$OUT/ticket-restart-$accel-1.log" log2="$OUT/ticket-restart-$accel-2.log"
        local data="$OUT/ticket-restart-$accel.img" go="$OUT/ticket-restart-$accel.go" status=0 cpid=""
        rm -f "$go" "$log2.client"
        fresh_disk "$iso" "$data"
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd 18883:8883
        if wait_log "$log1" "TLS 1.3 listener"; then
            python3 -I "$ROOT/scripts/ticket-scenarios.py" "$ROOT/deploy/dev" restart "$go" 18883 \
                >"$log2.client" 2>&1 &
            cpid=$!
            local waited=0
            until grep -q "client: ticket held" "$log2.client" 2>/dev/null; do
                if ! kill -0 "$cpid" 2>/dev/null || (( waited >= TIMEOUT * 10 )); then
                    status=124
                    break
                fi
                sleep 0.1
                waited=$((waited + 1))
            done
        else
            status=124
        fi
        kill_vm
        if [[ $status -eq 0 ]]; then
            start_vm "$log2" --disk "$data" --accel "$accel" --fwd 18883:8883
            if wait_log "$log2" "TLS 1.3 listener"; then
                touch "$go"
                wait "$cpid" || status=1
                wait_log "$log2" "session ticket\(s\) refused" || status=124
                sleep 0.5
            else
                status=124
            fi
            kill_vm
        fi
        [[ -n "$cpid" ]] && { kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true; }
        # Appended only now: QEMU writes the serial log at its own offset.
        cat "$log2.client" >>"$log2" 2>/dev/null || true
        check "ticket-restart [$accel]" "$log2" "$status" \
            "client: ticket-resume-before-restart ok" "client: ticket-after-restart ok" \
            "tls: 1 session ticket\(s\) refused, full handshake instead \(expired 0, unknown key 1, invalid 0, malformed 0\)" \
            "NOT:FAILED" "$NO_FAULT"
    done
}

# H1: a revocation and the control sequence number survive a reboot (the
# VM is killed, as by a power cut, after the message was applied): the same
# message replayed to the new boot is rejected, the device stays refused.
control_persist() {
    local iso="$OUT/control-persist.raw" msg="$OUT/control-persist.bin"
    mkimg "$iso" "serve"
    local d="$ROOT/deploy/dev"
    local tls=(--port 18883 --ca "$d/ca.pem" --client-cert "$d/services/operator.pem" --client-key "$d/services/operator.key")
    for accel in $ACCELS; do
        local log1="$OUT/control-persist-$accel-1.log" log2="$OUT/control-persist-$accel-2.log"
        local data="$OUT/control-persist-$accel.img" status=0
        rm -f "$msg" "$log2.client"
        fresh_disk "$iso" "$data"
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd 18883:8883
        if wait_log "$log1" "TLS 1.3 listener"; then
            "$CONTROL_TOOL" revoke --cert "$d/devices/device-002.pem" --env dev --key "$d/control.key" \
                --out "$msg" "${tls[@]}" >>"$log1.client" 2>&1 || status=1
            wait_log "$log1" "revoke of 1 item\(s\) applied" || status=124
        else
            status=124
        fi
        kill_vm
        if [[ $status -eq 0 ]]; then
            start_vm "$log2" --disk "$data" --accel "$accel" --fwd 18883:8883
            if wait_log "$log2" "TLS 1.3 listener"; then
                "$CONTROL_TOOL" publish-file "$msg" "${tls[@]}" >>"$log2.client" 2>&1 || status=1
                wait_log "$log2" "rejected: replay" || status=124
                if mosquitto_pub -h 127.0.0.1 -p 18883 -V mqttv311 -i device-002 --cafile "$d/ca.pem" \
                    --cert "$d/devices/device-002.pem" --key "$d/devices/device-002.key" \
                    -t devices/device-002/x -m x >/dev/null 2>&1; then
                    echo "client: revoked device admitted after reboot" >>"$log2.client"
                fi
                sleep 0.5
            else
                status=124
            fi
            kill_vm
            # Appended only now: QEMU writes the serial log at its own offset.
            cat "$log2.client" >>"$log2" 2>/dev/null || true
        fi
        check "control-persist [$accel]" "${log2}" "$status" \
            "db: restored .* 2 revoked serial\(s\), .* control seq [1-9][0-9]*" \
            "control: message from operator rejected: replay" "invalid peer certificate: Revoked" \
            "NOT:revoked device admitted" "$NO_FAULT"
    done
}

# H7: boots with the RTC before the build time; the date is refused and a
# device handshake fails for want of a trustworthy clock.
time_before_build() {
    local iso="$OUT/time-before-build.raw"
    mkimg "$iso" "serve"
    local d="$ROOT/deploy/dev"
    for accel in $ACCELS; do
        local log="$OUT/time-before-build-$accel.log" data="$OUT/time-before-build-$accel.img" status=0
        rm -f "$log.client"
        fresh_disk "$iso" "$data"
        start_vm "$log" --disk "$data" --accel "$accel" --fwd 18883:8883 \
            -- -rtc base=2020-01-01T00:00:00
        if wait_log "$log" "TLS 1.3 listener"; then
            if mosquitto_pub -h 127.0.0.1 -p 18883 -V mqttv311 -i device-001 --cafile "$d/ca.pem" \
                --cert "$d/devices/device-001.pem" --key "$d/devices/device-001.key" \
                -t devices/device-001/x -m x >/dev/null 2>&1; then
                echo "client: handshake ACCEPTED without a trustworthy clock" >>"$log.client"
            fi
            sleep 0.5
        else
            status=124
        fi
        kill_vm
        cat "$log.client" >>"$log" 2>/dev/null || true
        check "time-before-build [$accel]" "$log" "$status" \
            "date at boot: unix 15[0-9]+ is before this image was built" \
            "tls: connection refused" "NOT:handshake ACCEPTED" "$NO_FAULT"
    done
}

# M11: QEMU is killed while the kernel commits transactions in a loop;
# the next boot must pass quick_check and hold every committed row.
db_crash() {
    local crash="$OUT/db-crash.raw" verify="$OUT/db-verify.raw"
    mkimg "$crash" "smoke test=db-crash"
    mkimg "$verify" "smoke test=db-verify"
    for accel in $ACCELS; do
        local data="$OUT/db-crash-$accel.img" log1="$OUT/db-crash-$accel.log" log2="$OUT/db-verify-$accel.log"
        local status=0
        fresh_disk "$crash" "$data"
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd none
        wait_log "$log1" "db-crash: committed [0-9]+" 5 || status=$?
        # Kill at an arbitrary point inside the write stream.
        sleep "0.$((RANDOM % 5))"
        kill_vm
        local last
        last=$(clean "$log1" | grep -Eo 'db-crash: committed [0-9]+' | tail -1 | awk '{print $3}')
        check "db-crash-writer [$accel]" "$log1" "$status" "db-crash: writing from row 1" "db-crash: committed [0-9]+" "$NO_FAULT"
        status=0
        set_esp "$data" "$verify"
        boot "$log2" --disk "$data" --accel "$accel" --headless --fwd none || status=$?
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
    local crash="$OUT/log-crash.raw" verify="$OUT/log-verify.raw"
    mkimg "$crash" "smoke test=log-crash"
    mkimg "$verify" "smoke test=log-verify"
    for accel in $ACCELS; do
        local data="$OUT/log-crash-$accel.img" log1="$OUT/log-crash-$accel.log" log2="$OUT/log-verify-$accel.log"
        local status=0
        # 1 GiB sparse: the 8 log partitions hold ~55 MiB each, so a million
        # records from three cores never wrap.
        fresh_disk "$crash" "$data" 1g
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd none
        wait_log "$log1" "log-crash: durable (1[0-9]{6}|[2-9][0-9]{6})" || status=$?
        sleep "0.$((RANDOM % 4))"
        kill_vm
        local last
        last=$(clean "$log1" | grep -Eo 'log-crash: durable [0-9]+' | tail -1 | awk '{print $3}')
        check "log-crash-writers [$accel]" "$log1" "$status" "log-crash: core 0 writing" "log-crash: core 1 writing" \
            "log-crash: core 2 writing" "log-crash: durable [0-9]+" "$NO_FAULT"
        status=0
        set_esp "$data" "$verify"
        boot "$log2" --disk "$data" --accel "$accel" --headless --fwd none || status=$?
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
    local tear="$OUT/log-tear.raw" verify="$OUT/log-verify.raw"
    mkimg "$tear" "smoke test=log-tear"
    mkimg "$verify" "smoke test=log-verify"
    for accel in $ACCELS; do
        local data="$OUT/log-tear-$accel.img" log1="$OUT/log-tear-$accel.log" log2="$OUT/log-tear-verify-$accel.log"
        local status=0
        fresh_disk "$tear" "$data"
        boot "$log1" --disk "$data" --accel "$accel" --headless --fwd none || status=$?
        check "log-tear-write [$accel]" "$log1" "$status" "log-tear: 10000 records durable, then a torn write" "$NO_FAULT"
        status=0
        set_esp "$data" "$verify"
        boot "$log2" --disk "$data" --accel "$accel" --headless --fwd none || status=$?
        check "log-tear-truncated [$accel]" "$log2" "$status" \
            "telemetry: log recovered in [0-9]+ ms: 10500 record\(s\) in [0-9]+ segment\(s\), 1 torn tail\(s\) truncated" \
            "log-verify: 10500 records, every core's sequence contiguous" "^URMQTT READY$" "$NO_FAULT"
    done
}

# M11: broker state across a restart: retained message and a QoS 1 command
# queued for an offline persistent session, over mTLS.
mqtt_persist() {
    local iso="$OUT/mqtt-persist.raw"
    mkimg "$iso" "serve"
    for accel in $ACCELS; do
        local data="$OUT/mqtt-persist-$accel.img"
        fresh_disk "$iso" "$data"
        for phase in 1 2; do
            local log="$OUT/mqtt-persist-$accel-$phase.log" status=0
            start_vm "$log" --disk "$data" --accel "$accel" --fwd "18883:8883"
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
    local iso="$OUT/storm.raw"
    mkimg "$iso" "serve log=info heap_limit_mb=8"
    for accel in $ACCELS; do
        local log="$OUT/storm-$accel.log" data="$OUT/storm-$accel.img" status=0
        fresh_disk "$iso" "$data"
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "18883:8883"
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

# H3 (tools/attack): raw layer-2 TCP floods. The attack tool is the guest's
# whole network over a QEMU dgram netdev — it serves one DHCP lease, then
# injects 20 000 crafted segments. The broker must absorb them: SYN cookies
# issued without per-connection state, the RFC 5961 RST/challenge rate cap
# holding, RSTs for unknown connections dropped, and the heap never growing.
attack_raw() {
    local attack="$ROOT/target/release/urmqtt-attack"
    if [[ ! -x "$attack" ]]; then
        (cd "$ROOT" && cargo build --release -q -p urmqtt-attack) || {
            echo "  ✗ urmqtt-attack build failed"; FAILED=$((FAILED + 1)); return 0; }
    fi
    local iso="$OUT/attack-raw.raw"
    mkimg "$iso" "serve log=info"
    # mode|extra checks (beyond the common ones) ...
    local specs=(
        "syn-flood|cookies [1-9][0-9]* sent/[0-9]+ ok/0 bad|attack: syn-flood sent 20000"
        "ack-flood|RST [0-9]+ sent \([1-9][0-9]* rate-limited\)|attack: ack-flood sent 20000"
        "rst-flood|RST 0 sent \(0 rate-limited\)|attack: rst-flood sent 20000"
    )
    local n=0
    for accel in $ACCELS; do
        for spec in "${specs[@]}"; do
            IFS='|' read -r mode p_counter p_client <<<"$spec"
            local log="$OUT/attack-$mode-$accel.log" data="$OUT/attack-$mode-$accel.img" status=0
            local lp=$((45000 + n * 2)) rp=$((45001 + n * 2)); n=$((n + 1))
            fresh_disk "$iso" "$data"
            # Start the tool first: it binds the socket and serves DHCP, then
            # blocks until the guest's boot-time lease, floods, and exits.
            ("$attack" "$mode" --dgram "$lp:$rp" --port 8883 --count 20000 --pps 8000) \
                >"$log.client" 2>&1 &
            local apid=$!
            start_vm "$log" --disk "$data" --accel "$accel" --dgram "$lp:$rp"
            local waited=0
            while kill -0 "$apid" 2>/dev/null; do
                if ! kill -0 "$VM_PID" 2>/dev/null || (( waited >= TIMEOUT * 10 )); then
                    status=124; kill "$apid" 2>/dev/null || true; break
                fi
                sleep 0.1; waited=$((waited + 1))
            done
            local rc=0; wait "$apid" 2>/dev/null || rc=$?
            (( status == 0 )) && status=$rc
            # Let the per-core TCP-stats and memory reports emit.
            sleep 6
            kill_vm
            cat "$log.client" >>"$log" 2>/dev/null || true
            check "attack-$mode [$accel]" "$log" "$status" \
                "net: dhcp lease 10\.0\.2\.15" "$p_counter" "$p_client" \
                "tcp: core [0-9]+: [0-9]+ seg\(s\) in,.* 0 connection\(s\)" \
                "NOT:memory allocation of" "$NO_FAULT"
        done
    done
}

# H3 (tools/attack): application-level adversaries over the TLS port, run in
# sequence against one broker. Each must be bounded: slowloris trips the
# per-IP in-flight cap, fragmented records still complete, an oversize packet
# is a protocol error, the retained store and subscriptions are capped,
# keepalive and identity floods are absorbed — all with a flat heap.
attack_app() {
    local attack="$ROOT/target/release/urmqtt-attack"
    if [[ ! -x "$attack" ]]; then
        (cd "$ROOT" && cargo build --release -q -p urmqtt-attack) || {
            echo "  ✗ urmqtt-attack build failed"; FAILED=$((FAILED + 1)); return 0; }
    fi
    local iso="$OUT/attack-app.raw"
    mkimg "$iso" "serve log=info"
    for accel in $ACCELS; do
        local log="$OUT/attack-app-$accel.log" data="$OUT/attack-app-$accel.img" status=0
        fresh_disk "$iso" "$data"
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "18883:8883"
        if wait_log "$log" "TLS 1.3 listener on port 8883"; then
            local c=(--port 18883 --certs "$ROOT/deploy/dev")
            {
                "$attack" slowloris --stage tcp "${c[@]}" --clients 200 --duration 1
                "$attack" slowloris --stage tls "${c[@]}" --clients 200 --duration 1
                "$attack" slowloris --stage mqtt "${c[@]}" --clients 60 --duration 1
                "$attack" half-records "${c[@]}"
                "$attack" max-packets "${c[@]}" --max-packet 4096 --count 30
                "$attack" topic-flood "${c[@]}" --topics 60 --pace-ms 60
                "$attack" sub-flood "${c[@]}" --filters 64
                "$attack" keepalive-abuse "${c[@]}" --pings 5000
                "$attack" identities "${c[@]}" --clients 200
            } >"$log.client" 2>&1 || status=$?
            sleep 2
        else
            status=124
        fi
        kill_vm
        cat "$log.client" >>"$log" 2>/dev/null || true
        check "attack-app [$accel]" "$log" "$status" \
            "attack: slowloris-tcp opened" "attack: slowloris-tls opened" \
            "attack: slowloris-mqtt opened" \
            "admission: [0-9]+ connection\(s\) refused: too many handshakes in flight" \
            "attack: half-records CONNECT completed in fragments, CONNACK ok" \
            "attack: max-packets .* oversize packet closed the connection" \
            "attack: topic-flood retained 60 distinct topic" \
            "broker: [0-9]+ retained message\(s\) not retained .* over an identity's limit of 32" \
            "attack: sub-flood .* server closed the session" \
            "attack: keepalive-abuse sent 5000 PINGREQ" \
            "attack: identities [0-9]+ connected" \
            "NOT:memory allocation of" "$NO_FAULT"
    done
}

# M16: the dev configuration sends syslog to 10.0.2.2:5514 and statsd to
# 10.0.2.2:8125, which QEMU user networking delivers to the host.
observability() {
    local iso="$OUT/ops.raw"
    mkimg "$iso" "serve"
    for accel in $ACCELS; do
        local log="$OUT/ops-$accel.log" data="$OUT/ops-$accel.img" status=0
        rm -f "$log.udp"
        fresh_disk "$iso" "$data"
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "18883:8883"
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

# S1 (STORAGE-PLAN §2a): the first boot of the image on a larger disk
# moves the backup GPT, gives the disk its own GUID and creates the data
# partition; a second disk attached to the same VM stays byte for byte as
# it was, and the second boot finds the partition again.
first_boot() {
    local img="$OUT/first-boot.raw"
    mkimg "$img" "smoke"
    for accel in $ACCELS; do
        local disk="$OUT/first-boot-$accel.img" other="$OUT/first-boot-other-$accel.img" status=0
        local log1="$OUT/first-boot-$accel.log" log2="$OUT/first-boot-again-$accel.log"
        fresh_disk "$img" "$disk"
        # The second disk holds data that must survive (random bytes).
        head -c 16777216 /dev/urandom >"$other"
        local before
        before=$(shasum -a 256 "$other" | cut -d' ' -f1)
        boot "$log1" --disk "$disk" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=other0,file=$other,format=raw,cache=none" \
            -device virtio-blk-pci,drive=other0,romfile= || status=$?
        [[ $(shasum -a 256 "$other" | cut -d' ' -f1) == "$before" ]] || echo "SECOND DISK MODIFIED" >>"$log1"
        check "first-boot [$accel]" "$log1" "$status" "boot: from a GPT disk, disk GUID" \
            "disk: virtio-blk 00:0[0-9a-f]\.0 \(16 MiB\) is not the boot disk, left untouched" \
            "gpt: backup table moved to the end of the 64 MiB disk" \
            "gpt: data partition [0-9a-f-]+ at LBA [0-9]+\.\.[0-9]+ \([0-9]+ MiB\), created now, new disk GUID" \
            "inside the data partition" "storage: data disk formatted \(was blank\)" "^URMQTT READY$" \
            "NOT:SECOND DISK MODIFIED" "$NO_FAULT"
        status=0
        boot "$log2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "first-boot-again [$accel]" "$log2" "$status" "gpt: data partition [0-9a-f-]+ at LBA" \
            "NOT:created now" "NOT:backup table moved" "storage: data disk opened" "^URMQTT READY$" "$NO_FAULT"
    done
}

# S1: a power cut at a write of the first boot (injected with
# test=disk-fault, dev only); the next boot finishes the job. The host test
# `first_boot_survives_a_crash_at_every_write` covers every write; these
# cover the kernel path at the backup move, the head clearing, the new
# backup copy and a torn primary.
first_boot_crash() {
    local good="$OUT/first-boot-crash-ok.raw" spec
    mkimg "$good" "smoke"
    for spec in stop-after-write=2 stop-after-write=6 stop-after-write=8 tear-write=9:4; do
        local img="$OUT/first-boot-crash-${spec//[=:]/-}.raw"
        mkimg "$img" "smoke test=disk-fault:$spec"
        for accel in $ACCELS; do
            local disk="$OUT/first-boot-crash-$accel.img" status=0
            local log1="$OUT/first-boot-crash-${spec//[=:]/-}-$accel.log" log2="$OUT/first-boot-crash-${spec//[=:]/-}-$accel-2.log"
            fresh_disk "$img" "$disk"
            boot "$log1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
            check "first-boot-crash $spec [$accel]" "$log1" "$status" \
                "disk-fault: power cut injected during the first boot" "NOT:URMQTT READY" "$NO_FAULT"
            status=0
            set_esp "$disk" "$good"
            boot "$log2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
            check "first-boot-crash $spec recovered [$accel]" "$log2" "$status" \
                "gpt: data partition [0-9a-f-]+ at LBA" "storage: data disk (formatted|opened)" \
                "^URMQTT READY$" "$NO_FAULT"
        done
    done
}

# The boot disk as a virtio-scsi LUN (Hetzner, Oracle), with a second LUN
# that must stay untouched: formatted and benchmarked, then reopened.
scsi_boot() {
    local bench="$OUT/scsi-bench.raw" plain="$OUT/scsi-plain.raw"
    mkimg "$bench" "smoke test=db-bench"
    mkimg "$plain" "smoke"
    for accel in $ACCELS; do
        local disk="$OUT/scsi-boot-$accel.img" other="$OUT/scsi-other-$accel.img"
        fresh_disk "$bench" "$disk"
        head -c 16777216 /dev/urandom >"$other"
        local before
        before=$(shasum -a 256 "$other" | cut -d' ' -f1)
        for phase in 1 2; do
            local log="$OUT/scsi-boot-$accel-$phase.log" status=0
            [[ $phase == 2 ]] && set_esp "$disk" "$plain"
            boot "$log" --disk "$disk" --bus scsi --accel "$accel" --headless --no-net \
                -- -drive "if=none,id=other0,file=$other,format=raw,cache=none" \
                -device scsi-hd,drive=other0,bus=scsi0.0,scsi-id=1,lun=0 || status=$?
            [[ $(shasum -a 256 "$other" | cut -d' ' -f1) == "$before" ]] || echo "SECOND DISK MODIFIED" >>"$log"
            if [[ $phase == 1 ]]; then
                check "scsi-boot-format [$accel]" "$log" "$status" \
                    "scsi: target 0 lun 0: [0-9]+ MiB, the boot disk" \
                    "scsi: target 1 lun 0: 16 MiB, not the boot disk, left untouched" \
                    "blk: boot disk is scsi target 0 lun 0" "blk: self-test ok" \
                    "storage: data disk formatted \(was blank\)" "db-bench: .* 5100 rows verified" \
                    "^URMQTT READY$" "NOT:SECOND DISK MODIFIED" "$NO_FAULT"
            else
                check "scsi-boot-reopen [$accel]" "$log" "$status" "storage: data disk opened" \
                    "quick_check ok" "^URMQTT READY$" "NOT:SECOND DISK MODIFIED" "$NO_FAULT"
            fi
        done
    done
}

# The ISO as a CD: read-only media cannot hold a data partition. A dev
# image runs memory-only and says why; production refuses (the policy is
# `storage.require_data_disk`, host-tested in config-schema).
iso_as_cd() {
    local iso="$OUT/iso-as-cd.iso"
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$iso" --cmdline "smoke" --no-live >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/iso-as-cd-$accel.log" status=0
        boot "$log" --iso "$iso" --accel "$accel" --headless --no-net || status=$?
        check "iso-as-cd [$accel]" "$log" "$status" "boot: from optical media \(CD/ISO\)" \
            "storage: no data partition: booted from read-only media \(CD/ISO\): write the image to the machine's disk" \
            "running WITHOUT persistence \(dev configuration\)" "^URMQTT READY$" "$NO_FAULT"
    done
}

# S1: urMQTT's own data partition, damaged, is refused and left exactly as
# it is: never formatted again (S5 restores it from a backup).
own_damaged() {
    local img="$OUT/own-damaged.raw"
    mkimg "$img" "smoke"
    for accel in $ACCELS; do
        local disk="$OUT/own-damaged-$accel.img" log1="$OUT/own-damaged-$accel-1.log"
        local log2="$OUT/own-damaged-$accel-2.log" status=0
        fresh_disk "$img" "$disk"
        boot "$log1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        local first
        first=$(clean "$log1" | grep -Eo 'data partition [0-9a-f-]+ at LBA [0-9]+' | awk '{print $NF}')
        if [[ $status -ne 0 || -z "$first" ]]; then
            check "own-damaged [$accel]" "$log1" 1 "gpt: data partition"
            continue
        fi
        # Flip one byte inside the superblock's region table.
        printf '\xff' | dd of="$disk" bs=1 seek=$((first * 512 + 100)) conv=notrunc status=none
        local before
        before=$(dd if="$disk" bs=512 skip="$first" count=64 status=none | shasum -a 256)
        boot "$log2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        [[ $(dd if="$disk" bs=512 skip="$first" count=64 status=none | shasum -a 256) == "$before" ]] \
            || echo "DAMAGED PARTITION REWRITTEN" >>"$log2"
        # storage.refuse_on_corruption is on in dev too: the VM stops.
        check "own-damaged-refused [$accel]" "$log2" "$status" \
            "storage: data partition is damaged, left as it is: BadChecksum; refusing to serve" \
            "NOT:storage: data disk formatted" "NOT:DAMAGED PARTITION REWRITTEN" "NOT:URMQTT READY"
    done
}

# S1: the offline tool against a disk the broker used. Phase 1 serves
# devices (retained message, persistent session, queued command, telemetry);
# QEMU is killed. Then `urmqtt-disk` verifies, exports the database (opened
# by the host's sqlite3) and the telemetry, and imports an allowlisted
# device. Phase 2 boots in allowlist mode: the import is in force.
disk_tool() {
    local tool="$ROOT/target/release/urmqtt-disk" d="$ROOT/deploy/dev"
    (cd "$ROOT" && cargo build --release --locked -q -p urmqtt-disk-tool) || tool=""
    if [[ -z "$tool" ]] || ! command -v sqlite3 >/dev/null || ! command -v mosquitto_pub >/dev/null; then
        echo "  ✗ disk-tool needs urmqtt-disk, sqlite3 and mosquitto clients"
        FAILED=$((FAILED + 1))
        return
    fi
    local serve="$OUT/disk-tool.raw" allow="$OUT/disk-tool-allow.raw"
    mkimg "$serve" "serve"
    mkimg "$allow" "serve registry=allowlist"
    for accel in $ACCELS; do
        local disk="$OUT/disk-tool-$accel.img" log1="$OUT/disk-tool-$accel-1.log"
        local log2="$OUT/disk-tool-$accel-2.log" out="$OUT/disk-tool-$accel.out" status=0
        fresh_disk "$serve" "$disk"
        start_vm "$log1" --disk "$disk" --accel "$accel" --fwd 18883:8883
        # Client output goes to its own file: QEMU writes the serial log at
        # its own offset, so appending there while it runs loses lines.
        rm -f "$log1.client" "$log2.client"
        if wait_log "$log1" "TLS 1.3 listener on port 8883"; then
            python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$d" --phase 1 >>"$log1.client" 2>&1 || status=1
            for v in 11 22 33; do
                mosquitto_pub -h 127.0.0.1 -p 18883 -V mqttv311 -i device-001 --cafile "$d/ca.pem" \
                    --cert "$d/devices/device-001.pem" --key "$d/devices/device-001.key" -q 1 \
                    -t devices/device-001/telemetry/disk-tool -m "v$v" >>"$log1.client" 2>&1 || status=1
            done
            sleep 1
        else
            status=124
        fi
        kill_vm
        cat "$log1.client" >>"$log1" 2>/dev/null || true
        local before
        before=$(shasum -a 256 "$disk" | cut -d' ' -f1)
        {
            "$tool" info "$disk" && "$tool" verify "$disk" && echo "tool: verify exit 0"
            "$tool" export-db "$disk" "$out.sqlite" &&
                echo "tool: sqlite3 $(sqlite3 "$out.sqlite" "PRAGMA integrity_check; SELECT count(*) FROM retained; SELECT count(*) FROM sessions;" | tr '\n' ' ')"
            "$tool" export-telemetry "$disk" --format jsonl --topic 'devices/+/telemetry/disk-tool'
            [[ $(shasum -a 256 "$disk" | cut -d' ' -f1) == "$before" ]] && echo "tool: read-only commands left the disk unchanged"
            printf 'device-002\n' >"$out.ids"
            "$tool" import-devices "$disk" "$out.ids" && echo "tool: import without --write refused"
            "$tool" import-devices "$disk" "$out.ids" --allowlist --write
        } >>"$log1" 2>&1
        check "disk-tool-offline [$accel]" "$log1" "$status" "client: persist-phase1 ok" \
            "urMQTT data \"urMQTT data\" LBA" "verify: ok" "tool: verify exit 0" \
            "tool: sqlite3 ok 1 1 " \
            '"topic":"devices/device-001/telemetry/disk-tool","payload":"v11"' \
            '"payload":"v22"' '"payload":"v33"' "export-telemetry: 3 record\(s\)" \
            "tool: read-only commands left the disk unchanged" "NOT:tool: import without --write refused" \
            "import-devices: 1 device\(s\) imported and allowlisted" "$NO_FAULT"
        status=0
        set_esp "$disk" "$allow"
        start_vm "$log2" --disk "$disk" --accel "$accel" --fwd 18883:8883
        if wait_log "$log2" "TLS 1.3 listener on port 8883"; then
            for id in device-002 device-003; do
                if mosquitto_pub -h 127.0.0.1 -p 18883 -V mqttv311 -i "$id" --cafile "$d/ca.pem" \
                    --cert "$d/devices/$id.pem" --key "$d/devices/$id.key" -q 1 \
                    -t "devices/$id/x" -m x >/dev/null 2>&1; then
                    echo "client: $id admitted" >>"$log2.client"
                else
                    echo "client: $id refused" >>"$log2.client"
                fi
            done
            sleep 0.5
        else
            status=124
        fi
        kill_vm
        cat "$log2.client" >>"$log2" 2>/dev/null || true
        check "disk-tool-import-in-force [$accel]" "$log2" "$status" \
            "registry allowlist, 1 allowlisted identity" "client: device-002 admitted" \
            "client: device-003 refused" "$NO_FAULT"
    done
}

# S1b (STORAGE-PLAN §2b): the ISO installs itself. Its install entry is the
# default here (no timeout, a 1 s countdown: dev test options), with an
# empty disk attached; the installed disk then boots on its own, through the
# ordinary first boot.
# mkinstall <iso> <install cmdline>: an ISO whose default entry installs.
mkinstall() {
    [[ -f "$1" ]] && return 0
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$1" --cmdline "smoke" \
        --install-cmdline "$2" --install-default >/dev/null
}

install_iso() {
    local iso="$OUT/install.iso" crash="$OUT/install-crash.iso" tool="$ROOT/target/release/urmqtt-disk"
    mkinstall "$iso" "install install-countdown=1"
    mkinstall "$crash" "install install-countdown=0 test=disk-fault:stop-after-write=4"
    (cd "$ROOT" && cargo build --release --locked -q -p urmqtt-disk-tool) || tool=""
    local iso_sum
    iso_sum=$(shasum -a 256 "$iso" | cut -d' ' -f1)
    for accel in $ACCELS; do
        local t="$OUT/install-target-$accel.img" t2="$OUT/install-second-$accel.img" status=0
        local log1="$OUT/install-vm-$accel.log" log2="$OUT/install-vm-boot-$accel.log"
        rm -f "$t" "$t2"
        truncate -s 64m "$t"
        boot "$log1" --iso "$iso" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile= \
            || status=$?
        [[ $(shasum -a 256 "$iso" | cut -d' ' -f1) == "$iso_sum" ]] || echo "ISO MODIFIED" >>"$log1"
        check "install-vm [$accel]" "$log1" "$status" "boot: from optical media" \
            "install: disk virtio-blk 00:0[0-9a-f]\.0: 64 MiB$" "install: ALL DATA ON virtio-blk" \
            "install: writing to virtio-blk 00:0[0-9a-f]\.0 in 1 s; power off now to cancel" \
            "install: done: 10 MiB written and verified" "NOT:URMQTT READY" "NOT:ISO MODIFIED" "$NO_FAULT"
        status=0
        boot "$log2" --disk "$t" --accel "$accel" --headless --no-net || status=$?
        check "install-vm-boots [$accel]" "$log2" "$status" "boot: from a GPT disk" \
            "gpt: backup table moved to the end of the 64 MiB disk" "created now, new disk GUID" \
            "storage: data disk formatted \(was blank\)" "^URMQTT READY$" "$NO_FAULT"

        # Two possible targets: refused, nothing written to either.
        local log="$OUT/install-two-disks-$accel.log" zero="$OUT/install-zero.img"
        rm -f "$t" "$t2" "$zero"
        truncate -s 64m "$t" "$t2" "$zero"
        local z
        z=$(shasum -a 256 "$zero" | cut -d' ' -f1)
        status=0
        boot "$log" --iso "$iso" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile= \
            -drive "if=none,id=t1,file=$t2,format=raw,cache=none" -device virtio-blk-pci,drive=t1,romfile= \
            || status=$?
        for f in "$t" "$t2"; do
            [[ $(shasum -a 256 "$f" | cut -d' ' -f1) == "$z" ]] || echo "A DISK WAS WRITTEN" >>"$log"
        done
        check "install-two-disks-refused [$accel]" "$log" "$status" \
            "install: 2 disks could be the target \(virtio-blk 00:0[0-9a-f]\.0, virtio-blk 00:0[0-9a-f]\.0\): refusing to guess" \
            "NOT:install: writing" "NOT:A DISK WAS WRITTEN" "$NO_FAULT"

        # The target as a virtio-scsi LUN next to the CD.
        log="$OUT/install-scsi-$accel.log"
        rm -f "$t"
        truncate -s 64m "$t"
        status=0
        boot "$log" --iso "$iso" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" \
            -device scsi-hd,drive=t0,bus=scsi0.0,scsi-id=1,lun=0 || status=$?
        check "install-scsi [$accel]" "$log" "$status" \
            "install: disk virtio-scsi 00:0[0-9a-f]\.0 target 1 lun 0: 64 MiB" \
            "install: done: 10 MiB written and verified" "$NO_FAULT"
        status=0
        boot "$log.boot" --disk "$t" --bus scsi --accel "$accel" --headless --no-net || status=$?
        check "install-scsi-boots [$accel]" "$log.boot" "$status" "blk: boot disk is scsi target 0 lun 0" \
            "storage: data disk formatted" "^URMQTT READY$" "$NO_FAULT"

        # A power cut during the installation: the disk does not boot (no
        # valid GPT); installing again works.
        log="$OUT/install-crash-$accel.log"
        rm -f "$t"
        truncate -s 64m "$t"
        status=0
        boot "$log" --iso "$crash" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile= \
            || status=$?
        if [[ -n "$tool" ]]; then
            "$tool" info "$t" >>"$log" 2>&1 || true
        fi
        check "install-crash [$accel]" "$log" "$status" \
            "disk-fault: power cut injected during the installation" "gpt: none \(not a urMQTT boot disk\)" \
            "NOT:install: done" "$NO_FAULT"
        status=0
        boot "$log.again" --iso "$iso" --accel "$accel" --headless --no-net \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile= \
            || status=$?
        check "install-crash-reinstalled [$accel]" "$log.again" "$status" \
            "install: done: 10 MiB written and verified" "$NO_FAULT"
    done
}

# A cloud without a hardware RNG: no virtio-rng, and a CPU without RNDR
# (TCG models the Ampere Altra core, Neoverse N1, which also has no PAC or
# BTI; HVF's host CPU has no RNDR either). The jitter fallback must pass its
# health tests, and every CPU must come online.
no_hw_rng() {
    local iso="$OUT/no-rng.raw"
    mkimg "$iso" "smoke"
    for accel in $ACCELS; do
        local log="$OUT/no-rng-$accel.log" data="$OUT/no-rng-$accel.img" status=0 cpu=() rng="RNDR"
        [[ $accel == tcg && $ARCH == aarch64 ]] && cpu=(--cpu neoverse-n1)
        # x86: no RDRAND/RDSEED either (the CPU model says so).
        [[ $ARCH == x86_64 ]] && { cpu=(--cpu "max,-rdrand,-rdseed"); rng="RDRAND/RDSEED"; }
        fresh_disk "$iso" "$data"
        boot "$log" --disk "$data" --accel "$accel" ${cpu[@]+"${cpu[@]}"} --no-rng --headless || status=$?
        check "no-hw-rng [$accel]" "$log" "$status" "NOT:entropy: [0-9]+ bytes from" \
            "entropy: no hardware source \(virtio-rng, $rng\): CPU jitter fallback .* health tests passed" \
            "entropy: ChaCha20 CSPRNG seeded" "smp: 4/4 cpus online" "^URMQTT READY$" "$NO_FAULT"
    done
}

# GICv2 (ADR-039), what KVM gives a guest on a GIC-400 host such as the
# Raspberry Pi 4/5. HVF cannot emulate a GICv2, so this runs under TCG:
# boot with ACPI and DT, then the TLS broker scenarios.
gicv2() {
    if [[ " $ACCELS " != *" tcg "* ]]; then
        echo "  - gicv2 skipped (needs tcg in --accels)"
        return
    fi
    local iso="$OUT/gicv2.raw" acpi
    mkimg "$iso" "smoke"
    for acpi in on off; do
        local log="$OUT/gicv2-$acpi.log" data="$OUT/gicv2-$acpi.img" status=0
        fresh_disk "$iso" "$data"
        boot "$log" --disk "$data" --accel tcg --gic 2 --acpi "$acpi" --headless || status=$?
        check "gicv2 boot acpi=$acpi [tcg]" "$log" "$status" \
            "platform summary: .* gicv2 gicd=0x8000000 gicc=0x8010000 msi=v2m@0x8020000" \
            "gic: v2 at gicd=0x8000000 gicc=0x8010000, [0-9]+ lines, msi via GICv2m frame" \
            "tick 10$" "irq latency \(wfi, 25 samples\)" "timer: 5[0-9] ticks in [0-9]+ ms" \
            "${DEV_OK[@]}" "${SMP4_OK[@]}" "${DB_OK[@]}" "msi-x: [0-9]+ blk completion interrupt" \
            "^URMQTT READY$" "$NO_FAULT"
    done
    command -v mosquitto_pub >/dev/null || return 0
    iso="$OUT/gicv2-serve.raw"
    mkimg "$iso" "serve"
    local log="$OUT/gicv2-mqtt-tls.log" data="$OUT/gicv2-mqtt-tls.img" status=0
    fresh_disk "$iso" "$data"
    start_vm "$log" --disk "$data" --accel tcg --gic 2 --fwd "18883:8883"
    if wait_log "$log" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" 18883 >"$log.client" 2>&1 || status=$?
    else
        status=124
    fi
    kill_vm
    cat "$log.client" >>"$log" 2>/dev/null || true
    check "gicv2 mqtt-tls [tcg]" "$log" "$status" "gic: v2 at" \
        "client: pubsub-wildcard ok" "client: retained ok" "client: lwt-forced-disconnect ok" \
        "client: qos1-after-reconnect ok" "client: tls-revoked-rejected ok" "NOT:FAILED" "$NO_FAULT"
}

[[ -f "$KERNEL" ]] || { echo "error: $KERNEL not found (make build)" >&2; exit 1; }
rm -f "$OUT"/*.iso "$OUT"/*.iso.disk "$OUT"/*.raw "$OUT"/*.raw.esp
[[ $ARCH != universal || -f "$KERNEL_X86" ]] || { echo "error: $KERNEL_X86 not found (make build ARCH=x86_64)" >&2; exit 1; }
echo "smoke: accelerators: $ACCELS"

NO_FAULT='NOT:EXCEPTION|PANIC'

# X2: the x86_64 boot and exception scenarios (TCG, or KVM on an x86 host).
# Each boots an ISO built by mkiso.sh --arch x86_64 (BIOS and UEFI capable)
# on the given machine and firmware, with the CPU model "-" for the
# accelerator's default (max under TCG, host under KVM).
#
# x86_scenario <name> <machine> <firmware> <cpu|-> <cmdline> <patterns...>
x86_scenario() {
    local name=$1 machine=$2 fw=$3 cpu=$4 cmdline=$5
    shift 5
    local iso="$OUT/$name.iso"
    "$ROOT/scripts/mkiso.sh" --arch x86_64 --kernel "$KERNEL" --out "$iso" --cmdline "$cmdline" >/dev/null
    for accel in $ACCELS; do
        local log="$OUT/$name-$accel.log" status=0
        local cpuargs=()
        [[ $cpu != - ]] && cpuargs=(--cpu "$cpu")
        boot "$log" --arch x86_64 --iso "$iso" --accel "$accel" --machine "$machine" --firmware "$fw" \
            ${cpuargs[@]+"${cpuargs[@]}"} --smp 2 --headless --no-net || status=$?
        check "$name [$accel]" "$log" "$status" "$@"
    done
}

# X10: the universal ISO. mkuniversal <out> <cmdline> [mkiso args]: the ISO and
# its raw disk image <out>.disk, built from both kernels (the kernels' names
# in the ISO are urmqtt-aarch64.elf and urmqtt-x86-64.elf).
mkuniversal() {
    local out=$1 cmdline=$2
    shift 2
    [[ -f "$out" ]] && return 0
    "$ROOT/scripts/mkiso.sh" --universal --kernel-aarch64 "$KERNEL_A64" --kernel-x86_64 "$KERNEL_X86" \
        --out "$out" --cmdline "$cmdline" --disk-out "$out.disk" "$@" >/dev/null
}

# machines: name -> run-qemu.sh arguments (the same ISO or disk goes to each).
u_run() { # u_run <aa64|x86-uefi|x86-bios> <accel> <log> <iso|disk> <file> [qemu args]
    local kind=$1 accel=$2 log=$3 how=$4 file=$5
    shift 5
    case $kind in
        aa64) boot "$log" "--$how" "$file" --accel "$accel" --headless --no-net --smp 4 "$@" ;;
        x86-uefi) boot "$log" --arch x86_64 "--$how" "$file" --accel tcg --headless --no-net --smp 2 "$@" ;;
        x86-bios) boot "$log" --arch x86_64 --machine pc --firmware bios "--$how" "$file" --accel tcg --headless --no-net --smp 2 "$@" ;;
    esac
}

universal_iso() {
    local iso="$OUT/universal.iso"
    mkuniversal "$iso" "smoke"
    local sum
    sum=$(shasum -a 256 "$iso" | cut -d' ' -f1)
    local aa64='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' x86='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
    local rows=("aa64-hvf|aa64|hvf|$aa64" "aa64-tcg|aa64|tcg|$aa64" "x86-q35-uefi|x86-uefi|tcg|$x86" "x86-pc-bios|x86-bios|tcg|$x86")
    local row
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel boot_line <<<"$row"
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        local log="$OUT/universal-iso-$name.log" status=0
        u_run "$kind" "$accel" "$log" iso "$iso" || status=$?
        [[ $(shasum -a 256 "$iso" | cut -d' ' -f1) == "$sum" ]] || echo "ISO MODIFIED" >>"$log"
        check "universal-iso-$name (sha256 ${sum:0:12}…)" "$log" "$status" "$boot_line" "bootloader=Limine" \
            "boot: from optical media \(CD/ISO\)" "live: RAM store of [0-9]+ MiB ready" \
            "EPHEMERAL: data is lost on reboot" "NOT:storage: no data partition" \
            "^URMQTT READY$" "NOT:ISO MODIFIED" "$NO_FAULT"
    done
}

# The raw disk image of the same build: the data partition is created on the
# first boot, whichever machine boots it.
universal_raw() {
    local iso="$OUT/universal.iso" row
    mkuniversal "$iso" "smoke"
    local aa64='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' x86='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
    local rows=("aa64|aa64|hvf|$aa64" "x86-uefi|x86-uefi|tcg|$x86" "x86-bios|x86-bios|tcg|$x86")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel boot_line <<<"$row"
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        local log="$OUT/universal-raw-$name.log" data="$OUT/universal-raw-$name.img" status=0
        fresh_disk "$iso.disk" "$data"
        u_run "$kind" "$accel" "$log" disk "$data" || status=$?
        check "universal-raw-$name" "$log" "$status" "$boot_line" "boot: from a GPT disk, disk GUID" \
            "gpt: backup table moved to the end of the 64 MiB disk" "created now, new disk GUID" \
            "storage: data disk formatted \(was blank\)" "^URMQTT READY$" "$NO_FAULT"
    done
}

# The installer of the universal ISO on each machine, then the installed
# disk booted by all three boot paths (aarch64 UEFI, x86 UEFI, x86 BIOS).
universal_install() {
    local iso="$OUT/universal-install.iso" row
    mkuniversal "$iso" "smoke" --install-cmdline "install install-countdown=1" --install-default
    local aa64='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' x86='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
    local rows=("aa64|aa64|hvf|$aa64" "x86-uefi|x86-uefi|tcg|$x86" "x86-bios|x86-bios|tcg|$x86")
    local installer
    for installer in "${rows[@]}"; do
        IFS='|' read -r iname ikind iaccel _ <<<"$installer"
        [[ -z "${SMOKE_INSTALLER:-}" || $iname == "$SMOKE_INSTALLER" ]] || continue
        [[ $ikind == aa64 && " $ACCELS " != *" $iaccel "* ]] && continue
        local t="$OUT/universal-install-$iname.img" status=0 log="$OUT/universal-install-$iname.log"
        rm -f "$t"
        truncate -s 64m "$t"
        u_run "$ikind" "$iaccel" "$log" iso "$iso" \
            -- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile= || status=$?
        check "universal-install via $iname" "$log" "$status" "boot: from optical media" \
            "install: installation image: boot disk image of [0-9]+ KiB for UEFI and BIOS" \
            "install: disk virtio-blk 00:0[0-9a-f]\.0: 64 MiB$" "install: ALL DATA ON virtio-blk" \
            "install: done: [0-9]+ MiB written and verified" "NOT:URMQTT READY" "$NO_FAULT"
        # Every boot path starts the disk the installer wrote.
        for row in "${rows[@]}"; do
            IFS='|' read -r name kind accel boot_line <<<"$row"
            [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
            local copy="$OUT/universal-install-$iname-on-$name.img" blog="$OUT/universal-install-$iname-on-$name.log"
            cp "$t" "$copy"
            status=0
            u_run "$kind" "$accel" "$blog" disk "$copy" || status=$?
            check "universal-install: disk written via $iname boots on $name" "$blog" "$status" "$boot_line" \
                "boot: from a GPT disk" "gpt: backup table moved to the end of the 64 MiB disk" \
                "storage: data disk formatted \(was blank\)" "^URMQTT READY$" "$NO_FAULT"
        done
    done
}

# Cross-architecture data disk: broker state written by a VM of one
# architecture is restored by a VM of the other on the same disk (retained
# message, persistent session with a queued command, one telemetry record).
# <from>/<to> are run-qemu kinds: aa64, x86-uefi, x86-bios.
cross_arch() {
    local from=$1 to=$2 faccel=$3 taccel=$4
    local iso="$OUT/universal-serve.iso"
    mkuniversal "$iso" "serve"
    local data="$OUT/cross-arch-$from-to-$to.img" status=0
    local l1="$OUT/cross-arch-$from-to-$to-1.log" l2="$OUT/cross-arch-$from-to-$to-2.log"
    fresh_disk "$iso.disk" "$data"
    # Phase 1 on <from>: the broker with the dev certificates, forwarded to 18883.
    start_vm_kind "$from" "$faccel" "$l1" "$data"
    if wait_log "$l1" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$ROOT/deploy/dev" --phase 1 >"$l1.client" 2>&1 || status=$?
    else
        status=124
    fi
    kill_vm
    cat "$l1.client" >>"$l1" 2>/dev/null || true
    check "cross-arch $from -> $to: written by $from" "$l1" "$status" "storage: data disk formatted" \
        "client: persist-phase1 ok" "NOT:FAILED" "$NO_FAULT"
    status=0
    start_vm_kind "$to" "$taccel" "$l2" "$data"
    if wait_log "$l2" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$ROOT/deploy/dev" --phase 2 >"$l2.client" 2>&1 || status=$?
    else
        status=124
    fi
    kill_vm
    cat "$l2.client" >>"$l2" 2>/dev/null || true
    check "cross-arch $from -> $to: restored by $to" "$l2" "$status" "storage: data disk opened" \
        "db: restored 1 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), 1 revoked serial\(s\), 3 known device\(s\)" \
        "telemetry: log recovered in [0-9]+ ms: 1 record\(s\)" \
        "client: persist-retained ok" "client: persist-queued ok" "NOT:FAILED" "$NO_FAULT"
}

# start_vm_kind <aa64|x86-uefi|x86-bios> <accel> <log> <disk>: a serving VM with the TLS port forwarded.
start_vm_kind() {
    local kind=$1 accel=$2 log=$3 disk=$4
    case $kind in
        aa64) start_vm "$log" --disk "$disk" --accel "$accel" --fwd 18883:8883 ;;
        x86-uefi) start_vm "$log" --arch x86_64 --disk "$disk" --accel tcg --fwd 18883:8883 ;;
        x86-bios) start_vm "$log" --arch x86_64 --machine pc --firmware bios --disk "$disk" --accel tcg --fwd 18883:8883 ;;
    esac
}

# O3 (ADR-054): the ISO's first ("live") entry runs the broker from RAM with
# no disk at all, serves MQTT over mTLS, and a reboot loses what it held.
# start_vm_iso <kind> <accel> <log> <iso> [run-qemu args]: a serving VM
# booted from the ISO (a CD) alone, TLS port forwarded to 18883.
start_vm_iso() {
    local kind=$1 accel=$2 log=$3 iso=$4
    shift 4
    case $kind in
        aa64) start_vm "$log" --iso "$iso" --accel "$accel" --fwd 18883:8883 "$@" ;;
        x86-uefi) start_vm "$log" --arch x86_64 --iso "$iso" --accel "$accel" --smp 2 --fwd 18883:8883 "$@" ;;
        x86-bios) start_vm "$log" --arch x86_64 --machine pc --firmware bios --iso "$iso" --accel "$accel" --smp 2 --fwd 18883:8883 "$@" ;;
    esac
}

LIVE_BOOT=("boot: from optical media \(CD/ISO\)" "live: RAM store [0-9]+ MiB = 10% of [0-9]+ MiB RAM"
    "live: RAM store of [0-9]+ MiB ready" "blk: self-test ok on the RAM store"
    "storage: RAM store \(EPHEMERAL: lost on reboot\) formatted \(was blank\)"
    "db: sqlite 3\.[0-9]+\.[0-9]+ on the RAM store \(EPHEMERAL\)"
    "^EPHEMERAL: data is lost on reboot$" "EPHEMERAL: data is lost on reboot \(live mode, [0-9]+ MiB RAM store\)"
    "^URMQTT READY$" "NOT:storage: no data partition" "NOT:WITHOUT persistence" "NOT:data disk" "NOT:FAILED" "$NO_FAULT")

# live_serve <name> <kind> <accel> <iso>: boot 1 stores a retained message
# and reads it back; boot 2 of the same ISO (new RAM) has none of it.
live_serve() {
    local name=$1 kind=$2 accel=$3 iso=$4
    local l1="$OUT/$name-$kind-$accel-1.log" l2="$OUT/$name-$kind-$accel-2.log" status=0
    start_vm_iso "$kind" "$accel" "$l1" "$iso"
    if wait_log "$l1" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$ROOT/deploy/dev" --phase live1 \
            >"$l1.client" 2>&1 || status=$?
    else
        status=124
    fi
    kill_vm
    cat "$l1.client" >>"$l1" 2>/dev/null || true
    check "$name: live entry serves from RAM, no disk [$kind $accel]" "$l1" "$status" "${LIVE_BOOT[@]}" \
        "db: restored 0 retained message\(s\)" "client: live-retained ok"
    status=0
    start_vm_iso "$kind" "$accel" "$l2" "$iso"
    if wait_log "$l2" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-persist.py" 18883 --tls "$ROOT/deploy/dev" --phase gone \
            >"$l2.client" 2>&1 || status=$?
    else
        status=124
    fi
    kill_vm
    cat "$l2.client" >>"$l2" 2>/dev/null || true
    check "$name: a reboot loses the data [$kind $accel]" "$l2" "$status" "${LIVE_BOOT[@]}" \
        "db: restored 0 retained message\(s\), 0 persistent session\(s\) with 0 queued message\(s\)" \
        "telemetry: log recovered in [0-9]+ ms: 0 record\(s\)" "client: live-gone ok"
}

# live_leaves_disks_alone <name> <kind> <accel> <iso>: with a writable disk
# attached, the live entry neither writes nor formats it.
live_leaves_disks_alone() {
    local name=$1 kind=$2 accel=$3 iso=$4
    local t="$OUT/$name-$kind-$accel-disk.img" log="$OUT/$name-$kind-$accel.log" status=0 z
    rm -f "$t"
    truncate -s 64m "$t"
    z=$(shasum -a 256 "$t" | cut -d' ' -f1)
    local extra=(-- -drive "if=none,id=t0,file=$t,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile=)
    case $kind in
        aa64) boot "$log" --iso "$iso" --accel "$accel" --headless --no-net "${extra[@]}" || status=$? ;;
        x86-uefi) boot "$log" --arch x86_64 --iso "$iso" --accel "$accel" --smp 2 --headless --no-net "${extra[@]}" || status=$? ;;
        x86-bios) boot "$log" --arch x86_64 --machine pc --firmware bios --iso "$iso" --accel "$accel" --smp 2 --headless --no-net "${extra[@]}" || status=$? ;;
    esac
    [[ $(shasum -a 256 "$t" | cut -d' ' -f1) == "$z" ]] || echo "A DISK WAS WRITTEN" >>"$log"
    check "$name: live entry leaves an attached disk untouched [$kind $accel]" "$log" "$status" \
        "is not the boot disk, left untouched" "^URMQTT READY$" "NOT:gpt:" "NOT:data disk" \
        "NOT:A DISK WAS WRITTEN" "$NO_FAULT"
}

# live_suite: the live entry of this architecture's ISO (aarch64 menu ISO, or
# the x86_64-only ISO built with --live), with and without a disk attached.
live_suite() {
    local serve="$OUT/live-serve.iso" smk="$OUT/live-smoke.iso" accel
    if [[ $ARCH == x86_64 ]]; then
        "$ROOT/scripts/mkiso.sh" --arch x86_64 --live --kernel "$KERNEL" --out "$serve" --cmdline "serve" >/dev/null
        "$ROOT/scripts/mkiso.sh" --arch x86_64 --live --kernel "$KERNEL" --out "$smk" --cmdline "smoke" >/dev/null
        for accel in $ACCELS; do
            live_serve live x86-uefi "$accel" "$serve"
            live_serve live x86-bios "$accel" "$serve"
            live_leaves_disks_alone live x86-uefi "$accel" "$smk"
        done
    else
        URMQTT_MENU_TIMEOUT=0 "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$serve" --cmdline "serve" >/dev/null
        URMQTT_MENU_TIMEOUT=0 "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$smk" --cmdline "smoke" >/dev/null
        for accel in $ACCELS; do
            live_serve live aa64 "$accel" "$serve"
            live_leaves_disks_alone live aa64 "$accel" "$smk"
        done
    fi
}

# O4 (ADR-063): the ISO's third entry, the diagnostic. It boots from the ISO
# (a CD) with disks attached, prints one JSON document on the serial port, and
# (dev, smoke) powers off. Checked: the keys and sane values (diag-check.py),
# that an installed disk stays byte-identical (nothing is written: no free
# space), that a blank disk stays untouched without a confirmation, and that
# a confirmed write test (dev: diag-confirm=WIPE) runs only on the blank disk
# and leaves it zeroed again.
DIAG_PATTERNS=("^URMQTT DIAG START" "^URMQTT-DIAG-JSON \{\"urmqtt_diag\":1," "^URMQTT DIAG DONE$"
    "NOT:^URMQTT READY$" "NOT:FAILED" "$NO_FAULT")

# diag_run <kind> <accel> <log> <iso> <disk>: boots the diagnostic with <disk> attached.
diag_run() {
    local kind=$1 accel=$2 log=$3 iso=$4 disk=$5
    u_run "$kind" "$accel" "$log" iso "$iso" \
        -- -drive "if=none,id=t0,file=$disk,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile=
}

# diag_check <name> <log> <status> <disk-state> <write> [extra patterns...]
diag_check() {
    local name=$1 log=$2 status=$3 state=$4 write=$5
    shift 5
    python3 -I "$ROOT/scripts/diag-check.py" "$log" --disk-state "$state" --write "$write" >>"$log" 2>&1 || true
    check "$name" "$log" "$status" "${DIAG_PATTERNS[@]}" "diag-json ok: disk $state, seq_write $write" "$@"
}

universal_diag() {
    local iso="$OUT/universal-diag.iso" row
    mkuniversal "$iso" "smoke" --diag-cmdline "diag smoke diag-confirm-timeout=2" --diag-default
    local iso_yes="$OUT/universal-diag-confirm.iso"
    mkuniversal "$iso_yes" "smoke" --diag-cmdline "diag smoke diag-confirm=WIPE" --diag-default
    local rows=("aa64|aa64|hvf|aa64" "x86-uefi|x86-uefi|tcg|x86" "x86-bios|x86-bios|tcg|x86")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel _ <<<"$row"
        [[ -z "${SMOKE_DIAG:-}" || $name == "$SMOKE_DIAG" ]] || continue
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        # An installed disk: the raw boot image booted once creates the data
        # partition and formats the store.
        local t="$OUT/universal-diag-$name.img" log status=0 before after
        rm -f "$t"
        cp "$iso.disk" "$t"
        truncate -s 64m "$t"
        log="$OUT/universal-diag-$name-format.log"
        u_run "$kind" "$accel" "$log" disk "$t" || status=$?
        check "universal-diag: format the test disk [$name]" "$log" "$status" "storage: data disk formatted" "^URMQTT READY$"
        before=$(shasum -a 256 "$t" | cut -d' ' -f1)
        log="$OUT/universal-diag-$name-installed.log" status=0
        diag_run "$kind" "$accel" "$log" "$iso" "$t" || status=$?
        after=$(shasum -a 256 "$t" | cut -d' ' -f1)
        [[ $before == "$after" ]] || echo "A DISK WAS WRITTEN" >>"$log"
        diag_check "universal-diag: installed disk, read-only, byte-identical [$name]" "$log" "$status" installed skipped \
            "\"reason\":\"no unallocated space" "contents installed" "NOT:A DISK WAS WRITTEN"
        # A blank disk, no confirmation typed: nothing is written.
        local b="$OUT/universal-diag-$name-blank.img"
        rm -f "$b"
        truncate -s 64m "$b"
        before=$(shasum -a 256 "$b" | cut -d' ' -f1)
        log="$OUT/universal-diag-$name-blank.log" status=0
        diag_run "$kind" "$accel" "$log" "$iso" "$b" || status=$?
        after=$(shasum -a 256 "$b" | cut -d' ' -f1)
        [[ $before == "$after" ]] || echo "A DISK WAS WRITTEN" >>"$log"
        diag_check "universal-diag: blank disk without confirmation is not written [$name]" "$log" "$status" blank skipped \
            "Type WIPE \+ Enter to write" "not confirmed on the keyboard" "NOT:A DISK WAS WRITTEN"
        # Confirmed (dev test seam): the write test runs, verifies, and zeroes its area.
        log="$OUT/universal-diag-$name-confirmed.log" status=0
        diag_run "$kind" "$accel" "$log" "$iso_yes" "$b" || status=$?
        after=$(shasum -a 256 "$b" | cut -d' ' -f1)
        [[ $before == "$after" ]] || echo "THE TEST AREA WAS NOT ZEROED" >>"$log"
        diag_check "universal-diag: confirmed write test on the blank disk [$name]" "$log" "$status" blank done \
            "sequential write [0-9]+ MiB/s" "NOT:THE TEST AREA WAS NOT ZEROED"
    done
}

# SMOKE_ONLY=live: just the live-mode scenarios of this architecture.
if [[ ${SMOKE_ONLY:-} == live && $ARCH != universal ]]; then
    live_suite
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=diag (universal): only the diagnostic scenarios; SMOKE_DIAG=<aa64|x86-uefi|x86-bios>
# limits which machine runs them.
if [[ ${SMOKE_ONLY:-} == diag && $ARCH == universal ]]; then
    universal_diag
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=install (universal): only the installer scenarios; SMOKE_INSTALLER=<aa64|x86-uefi|x86-bios>
# limits which machine runs the installer.
if [[ ${SMOKE_ONLY:-} == install && $ARCH == universal ]]; then
    universal_install
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

if [[ $ARCH == universal ]]; then
    universal_iso
    universal_raw
    universal_install
    universal_diag
    if command -v mosquitto_pub >/dev/null; then
        # One ISO, three machines, no disk.
        URMQTT_MENU_TIMEOUT=0 mkuniversal "$OUT/universal-live.iso" "serve"
        live_serve universal-live x86-uefi tcg "$OUT/universal-live.iso"
        live_serve universal-live x86-bios tcg "$OUT/universal-live.iso"
        for accel in $ACCELS; do
            live_serve universal-live aa64 "$accel" "$OUT/universal-live.iso"
        done
        URMQTT_MENU_TIMEOUT=0 mkuniversal "$OUT/universal-live-smoke.iso" "smoke"
        live_leaves_disks_alone universal-live x86-uefi tcg "$OUT/universal-live-smoke.iso"
        live_leaves_disks_alone universal-live x86-bios tcg "$OUT/universal-live-smoke.iso"
        live_leaves_disks_alone universal-live aa64 "${ACCELS%% *}" "$OUT/universal-live-smoke.iso"
    else
        echo "  ✗ live-mode scenarios need the mosquitto clients"
        FAILED=$((FAILED + 1))
    fi
    if command -v mosquitto_pub >/dev/null; then
        if [[ " $ACCELS " == *" hvf "* ]]; then
            cross_arch aa64 x86-uefi hvf tcg
            cross_arch x86-uefi aa64 tcg hvf
            cross_arch aa64 x86-bios hvf tcg
            cross_arch x86-bios aa64 tcg hvf
        else
            cross_arch aa64 x86-uefi tcg tcg
            cross_arch x86-uefi aa64 tcg tcg
        fi
    else
        echo "  ✗ cross-arch scenarios need the mosquitto clients"
        FAILED=$((FAILED + 1))
    fi
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

if [[ $ARCH == x86_64 ]]; then
    # X2: the ISO-based boot and exception scenarios.
    X86_BOOT=('^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
        'cpu: vendor=[A-Za-z]+ family=[0-9]+ model=0x[0-9a-f]+ stepping=[0-9]+ hypervisor=[A-Za-z]+'
        'cpu features: .*xcr0=0x[0-9a-f]+' 'bootloader=Limine' 'framebuffer: [0-9]+x[0-9]+ text console'
        'memmap 0x' '^URMQTT READY$')
    x86_scenario x86-boot-q35-uefi q35 uefi - "smoke" "${X86_BOOT[@]}" "$NO_FAULT"
    x86_scenario x86-boot-pc-bios pc bios - "smoke" "${X86_BOOT[@]}" "$NO_FAULT"
    # The smallest CPU that is still x86-64-v2: no AES-NI, no AVX.
    x86_scenario x86-boot-v2-minimal q35 uefi "qemu64,+ssse3,+sse4.1,+sse4.2,+popcnt,+cx16" "smoke" \
        "${X86_BOOT[@]}" "NOT:cpu features: .*(aes|avx2)" "$NO_FAULT"
    x86_scenario x86-baseline-refuse q35 uefi qemu64 "smoke" \
        "Missing: ssse3 sse4.1 sse4.2 popcnt" \
        'VM CPU type too old: use `host`, `x86-64-v2-AES` or newer in Proxmox/QEMU' \
        "NOT:URMQTT BOOT" "NOT:URMQTT READY"
    x86_scenario x86-fault-pf-null q35 uefi - "smoke test=null" \
        "EXCEPTION: #PF page fault" "page not present, read, supervisor mode" \
        "CR2=0x0000000000000008" "RIP=0xffffffff8" "RAX=0x[0-9a-f]+ RBX=" "R15=0x" \
        "on IST stack 4" "FAR is in: lower half" "fatal exception, stopping" "NOT:URMQTT READY"
    x86_scenario x86-fault-ud pc bios - "smoke test=undef" \
        "EXCEPTION: #UD invalid opcode" "vector=6" "on the interrupted stack" "NOT:URMQTT READY"
    x86_scenario x86-fault-gp q35 uefi - "smoke test=gp" \
        "EXCEPTION: #GP general protection" "no selector \(non-canonical address" \
        "RAX=0x8000000000000000" "NOT:URMQTT READY"
    x86_scenario x86-fault-df q35 uefi - "smoke test=df" \
        "EXCEPTION: #DF double fault" "vector=8" "on IST stack 1" "NOT:URMQTT READY"
    x86_scenario x86-brk-resume q35 uefi - "smoke test=brk" \
        "resumable brk at 0x" "test: resumed after brk" "^URMQTT READY$" "NOT:fatal exception"
    x86_scenario x86-panic q35 uefi - "smoke test=panic" \
        "PANIC: panicked at" "test panic requested on the command line" "NOT:URMQTT READY"
fi

# X8: the disk-based scenarios on x86_64 (q35, OVMF, the raw GPT image).
if [[ $ARCH == x86_64 ]]; then
BOOT_LINE='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=4 mem=[0-9]+$'

MEMORY_OK=("vm: switched to kernel tables" "selftest: frames ok" "page tables locked" "selftest: W\^X ok \([0-9]+ leaf mappings audited, 0 W\+X"
    "mm: protections nx=on wp=on smep=on smap=on umip=on")
TIME_OK=("apic: x2APIC mode, lapic at 0xfee00000, 1 I/O APIC\(s\)"
    "timer: tsc [0-9]+ Hz, local APIC timer vector 0x20 \((one-shot, calibrated|TSC-deadline)\), tick 10 ms"
    "tick 10$" "irq latency \(busy-poll, 25 samples\) min=[0-9]+" "irq latency \(wfi, 25 samples\) min=[0-9]+"
    "timer: 5[0-9] ticks in [0-9]+ ms")
DEV_OK=("pci: ECAM 0xe0000000 buses 0-255" "virtio-blk" "virtio-net" "virtio-rng"
    "entropy: [0-9]+ bytes from virtio-rng" "entropy: ChaCha20 CSPRNG seeded"
    "blk: self-test ok \(4 KiB random pattern written, flushed, read back" "net: gratuitous ARP sent"
    "net: rx ok, ARP reply from 52:55:0a:00:02:02")
DB_OK=("storage: data disk formatted \(was blank\)" "db: sqlite 3\.[0-9]+\.[0-9]+ on the data disk: WAL, exclusive locking, quick_check ok"
    "telemetry: log recovered in [0-9]+ ms: 0 record\(s\)"
    "db: restored 0 retained" "db: DB core is cpu 3" "db: worker running on cpu 3")
# X9: AES-NI, PCLMULQDQ, SHA-NI and SSE4.2 CRC (QEMU's TCG CPU offers them
# all); the known-answer tests, long vectors included, pass on them. The
# boot also prints the handshake profile and the calibrated watchdog budget.
DISPATCH_OK=("cpu dispatch: detected [a-z0-9 ]*aes pmull sha2 crc32, disabled none"
    "crypto: aes-gcm=aesni ghash=pclmulqdq chacha=sse2 sha256=sha-ni crc32c=sse4.2 toeplitz=bitwise"
    "crypto: known-answer tests passed \(AES-128-GCM, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256, CRC-32C\)"
    "crypto-profile: x25519-base=[0-9]+\.[0-9]+us .*ecdsa-verify=[0-9]+\.[0-9]+us .* => handshake~[0-9]+\.[0-9]+us \([0-9]+% public-key\)"
    "watchdog: handshake budget [0-9]+ ms \(calibrated\), other handlers 10 ms, stuck-core reset at 1000 ms")
SMP4_OK=("cpu 1 online" "cpu 3 online" "smp: 4/4 cpus online" "ipi: 12/12 ordered pairs ping-pong ok"
    "smp: 4/4 cpus ticking on their own timer")

scenario x86-disk-q35 "smoke" on \
    "$BOOT_LINE" "platform: discovered via Acpi" "acpi: lapic=0xfee00000 ioapic=1\[0@0xfec00000\+0\]" \
    "time: tsc [0-9]+ Hz from " "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${DEV_OK[@]}" "${SMP4_OK[@]}" "${DB_OK[@]}" \
    "${DISPATCH_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario x86-fault-unmapped-mmio "smoke test=data-abort" on \
    "EXCEPTION: #PF page fault" "page not present, read, supervisor mode" "NOT:URMQTT READY"
SMP=8 scenario x86-smp8 "smoke" on \
    "cpu=8 mem=" "cpu 7 online" "smp: 8/8 cpus online" "ipi: 56/56 ordered pairs ping-pong ok" \
    "smp: 8/8 cpus ticking on their own timer" "^URMQTT READY$" "$NO_FAULT"

# X3: W^X, NX, guard pages and the sealed page, through the locked tables.
scenario x86-wx-write-text "smoke test=write-text" on \
    "${MEMORY_OK[@]}" "page fault error code 0x3: protection violation, write, supervisor mode" "NOT:URMQTT READY"
scenario x86-nx-exec-heap "smoke test=exec-heap" on \
    "protection violation, read, supervisor mode, instruction fetch" "NOT:URMQTT READY"
scenario x86-guard-overflow "smoke test=stack-overflow" on \
    "page not present, write, supervisor mode" "FAR is in: main stack guard page \(stack overflow\)" \
    "NOT:URMQTT READY"
scenario x86-sealed-write "smoke test=sealed-write" on \
    "test: writing the sealed cpu dispatch at 0x" "protection violation, write, supervisor mode" \
    "NOT:URMQTT READY"
for accel in $ACCELS; do
    log="$OUT/x86-sealed-write-$accel.log"
    at=$(clean "$log" | grep -Eo 'sealed cpu dispatch at 0x[0-9a-f]+' | grep -Eo '0x[0-9a-f]+$')
    far=$(clean "$log" | grep -Eo 'CR2=0x[0-9a-f]+' | head -1 | cut -d= -f2)
    if [[ -n "$at" && $((at)) -eq $((far)) ]]; then
        echo "  ✓ sealed-write faulted on the sealed page itself ($far) [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ sealed-write: CR2 ${far:-?} is not the sealed address ${at:-?} [$accel]"
        FAILED=$((FAILED + 1))
    fi
done
scenario x86-crypto-soft "smoke cpu-disable=aes,pmull,sha2,crc32" on \
    "disabled aes pmull sha2 crc32" "crypto: aes-gcm=soft ghash=soft chacha=sse2 sha256=soft crc32c=table" \
    "crypto: known-answer tests passed" "^URMQTT READY$" "$NO_FAULT"
scenario x86-crypto-bench "smoke test=crypto-bench" on \
    "crypto-bench: AES-128-GCM [0-9]+ MiB/s, ChaCha20-Poly1305 [0-9]+ MiB/s, SHA-256 [0-9]+ MiB/s, CRC-32C [0-9]+ MiB/s.*aes-gcm=aesni" \
    "^URMQTT READY$" "$NO_FAULT"
scenario x86-simd-irq "smoke test=simd-irq" on \
    "simd-irq: [0-9]+ known-answer rounds on 4 cores in 10 s with [0-9]+ IPIs and the tick: 0 mismatches" \
    "^URMQTT READY$" "$NO_FAULT"
else
BOOT_LINE='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$'

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
# ADR-041/X0b: the dispatch is sealed with nothing disabled and picks the
# ARMv8 backends (QEMU's `max` and HVF's host CPU offer all of them); the
# known-answer tests pass on the chosen backends before anything uses them.
DISPATCH_OK=("cpu dispatch: detected [a-z0-9 ]*aes pmull[a-z0-9 ]*, disabled none"
    "crypto: aes-gcm=armv8-aes ghash=armv8-pmull chacha=neon sha256=armv8-sha2 crc32c=armv8-crc toeplitz=bitwise"
    "crypto: known-answer tests passed \(AES-128-GCM, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256, CRC-32C\)"
    "crypto-profile: x25519-base=[0-9]+\.[0-9]+us .*ecdsa-verify=[0-9]+\.[0-9]+us .* => handshake~[0-9]+\.[0-9]+us \([0-9]+% public-key\)"
    "watchdog: handshake budget [0-9]+ ms \(calibrated\), other handlers 10 ms, stuck-core reset at 1000 ms")
SMP4_OK=("cpu 1 online" "cpu 3 online" "smp: 4/4 cpus online" "ipi: 12/12 ordered pairs ping-pong ok"
    "smp: 4/4 cpus ticking on their own timer")

scenario boot-acpi "smoke" on \
    "$BOOT_LINE" "platform: discovered via Acpi" "console: pl011 at 0x9000000" "psci 1\.[0-9]+ via hvc" \
    "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${DEV_OK[@]}" "${SMP4_OK[@]}" "${DB_OK[@]}" "${DISPATCH_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario boot-dtb "smoke" off \
    "$BOOT_LINE" "platform: discovered via DeviceTree" "console: pl011 at 0x9000000" "${MEMORY_OK[@]}" \
    "${TIME_OK[@]}" "${DEV_OK[@]}" "${DISPATCH_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
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

# X0b: the portable backends when the features are taken out, the sealed
# choice is read-only, and FP/SIMD state survives interrupts on every core.
scenario crypto-soft "smoke cpu-disable=aes,pmull,sha2,crc32" on \
    "disabled aes pmull sha2 crc32" \
    "crypto: aes-gcm=soft ghash=soft chacha=neon sha256=soft crc32c=table toeplitz=bitwise" \
    "crypto: known-answer tests passed" "^URMQTT READY$" "$NO_FAULT"
scenario sealed-write "smoke test=sealed-write" on \
    "test: writing the sealed cpu dispatch at 0x" "data abort \(same EL\), write, permission fault, level 3" \
    "NOT:URMQTT READY"
for accel in $ACCELS; do
    log="$OUT/sealed-write-$accel.log"
    at=$(clean "$log" | grep -Eo 'sealed cpu dispatch at 0x[0-9a-f]+' | grep -Eo '0x[0-9a-f]+$')
    far=$(clean "$log" | grep -Eo 'FAR=0x[0-9a-f]+' | head -1 | cut -d= -f2)
    if [[ -n "$at" && $((at)) -eq $((far)) ]]; then
        echo "  ✓ sealed-write faulted on the sealed page itself ($far) [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ sealed-write: FAR ${far:-?} is not the sealed address ${at:-?} [$accel]"
        FAILED=$((FAILED + 1))
    fi
done
scenario simd-irq "smoke test=simd-irq" on \
    "simd-irq: [0-9]+ known-answer rounds on 4 cores in 10 s with [0-9]+ IPIs and the tick: 0 mismatches" \
    "^URMQTT READY$" "$NO_FAULT"
scenario crypto-bench "smoke test=crypto-bench" on \
    "crypto-bench: AES-128-GCM [0-9]+ MiB/s, ChaCha20-Poly1305 [0-9]+ MiB/s, SHA-256 [0-9]+ MiB/s, CRC-32C [0-9]+ MiB/s" \
    "^URMQTT READY$" "$NO_FAULT"

fi

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
        "client: qos1-after-reconnect ok" "client: acl-subscribe-denied ok" "client: retained-limit ok" \
        "broker: 1 retained message\(s\) not retained on core [0-9]+ \(1 over an identity's limit of 32" "NOT:FAILED" "$NO_FAULT"
    # M10: the same scenarios over TLS 1.3 with mutual TLS, plus the four
    # handshakes/CONNECTs that must be refused.
    SERVICE_PORT=8883 service mqtt-tls "serve" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" -- \
        "client: pubsub-wildcard ok" "client: retained ok" "client: lwt-forced-disconnect ok" \
        "client: qos1-after-reconnect ok" "client: acl-subscribe-denied ok" "client: retained-limit ok" \
        "client: tls-wrong-ca-rejected ok" "client: tls-expired-rejected ok" \
        "client: tls-client-id-mismatch-rejected ok" "client: tls-revoked-rejected ok" \
        "tls: device-001 authenticated \(TLS13_" "invalid peer certificate: UnknownIssuer" \
        "certificate expired" "invalid peer certificate: Revoked" "NOT:FAILED" "$NO_FAULT"
else
    echo "  ✗ mosquitto clients not installed (brew install mosquitto / apt install mosquitto-clients)"
    FAILED=$((FAILED + 1))
fi

# O2: `reboot` resets the machine (QEMU runs with -no-reboot, so the reset
# ends the VM) after the command was accepted and audit-logged.
sys_reboot() {
    local iso="$OUT/sys-reboot.raw"
    mkimg "$iso" "serve"
    for accel in $ACCELS; do
        local log="$OUT/sys-reboot-$accel.log" data="$OUT/sys-reboot-$accel.img" status=0 waited=0
        fresh_disk "$iso" "$data"
        start_vm "$log" --disk "$data" --accel "$accel" --fwd 18883:8883
        if wait_log "$log" "TLS 1.3 listener"; then
            python3 -I "$ROOT/scripts/sys-scenarios.py" reboot "$ROOT/deploy/dev" 18883 >"$log.client" 2>&1 || status=1
            until ! kill -0 "$VM_PID" 2>/dev/null; do
                if (( waited >= 300 )); then
                    echo "client: the VM did not reset within 30 s" >>"$log.client"
                    status=124
                    break
                fi
                sleep 0.1
                waited=$((waited + 1))
            done
        else
            status=124
        fi
        kill_vm
        cat "$log.client" >>"$log" 2>/dev/null || true
        check "sys-reboot [$accel]" "$log" "$status" "client: console-reboot-accepted ok" \
            "console: operator ran \"reboot\"" "console: rebooting at the request of operator" \
            "NOT:the VM did not reset" "NOT:FAILED" "$NO_FAULT"
    done
}

# ADR-072: the `sys` step of the output handler never waits for the log. With
# every log line made slow (like a hypervisor's serial port or a scrolling
# framebuffer) and an operator subscribed, no output handler may be reported
# over budget in step `sys`.
if command -v mosquitto_pub >/dev/null; then
    SERVICE_PORT=8883 service sys-slow-log "serve test=slow-log:4000" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/sys-scenarios.py" watch "$ROOT/deploy/dev" -- \
        "client: sys-watch ok" "NOT:\(step sys\)" "NOT:FAILED" "$NO_FAULT"
fi

# O1, O2: an operator with mutual TLS reads `$SYS/broker/#` (retained, every
# 10 s), asks `$SYS/query/info`, reads the console and runs the fixed command
# set; devices and the backend service cannot reach any of it. Every command
# is audit-logged on the serial console.
if command -v mosquitto_pub >/dev/null && command -v mosquitto_sub >/dev/null; then
    SERVICE_PORT=8883 service sys-operator "serve" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/sys-scenarios.py" "$ROOT/deploy/dev" -- \
        "client: sys-broker-topics ok" "client: sys-refresh ok" "client: sys-cpu-busy-per-core ok" \
        "client: sys-retained-flag ok" "client: sys-query-info ok" "client: console-replays-the-log ok" \
        "client: console-help ok" "client: console-status ok" "client: console-log-level ok" \
        "client: console-refuses-unknown-and-malformed ok" "client: console-audit-on-the-console ok" \
        "client: console-rate-limited ok" "client: console-no-command-chaining ok" \
        "client: console-restores-log-level ok" "client: sys-denied-to-device-001 ok" \
        "client: sys-denied-to-backend ok" "client: console-out-denied-to-device-001 ok" \
        "client: console-out-denied-to-backend ok" "client: console-unaffected-by-others ok" \
        "client: sys-topics-cannot-be-forged ok" \
        "console: operator ran \"status\"" "console: operator ran \"log level info\"" \
        "console: operator command refused \(unknown command\): \"bogus\"" \
        "console: operator command refused: rate limit" \
        "NOT:console: rebooting" "NOT:FAILED" "$NO_FAULT"
    sys_reboot
fi

# H2: session tickets under random per-boot keys. With a 20 s rotation, a
# ticket issued late in the first interval resumes after the rotation (the
# previous key), and a ticket from before a reboot does not.
SERVICE_PORT=8883 service ticket-rotation "serve test=ticket-rotate:20" 18883 "TLS 1.3 listener on port 8883" \
    python3 -I "$ROOT/scripts/ticket-scenarios.py" "$ROOT/deploy/dev" rotation 20 -- \
    "tls: session tickets under random per-boot keys, rotated every 20 s of uptime \(ticket lifetime 20 s\)" \
    "client: ticket-resume ok" "client: ticket-previous-key ok" \
    "tls: session-ticket keys rotated \(1 key change\(s\) since boot\)" "NOT:FAILED" "$NO_FAULT"
ticket_restart

# H1: the control channel, the registry and the trust roles, with the
# real `urmqtt-control` tool and mosquitto clients.
CONTROL_TOOL="$ROOT/target/release/urmqtt-control"
(cd "$ROOT" && cargo build --release --locked -q -p urmqtt-control-tool) || CONTROL_TOOL=""
# Ed25519 keys need OpenSSL >= 3 (macOS's LibreSSL has none).
for c in "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" openssl; do
    if command -v "$c" >/dev/null && "$c" version | grep -q '^OpenSSL [3-9]'; then
        export OPENSSL=$c
        break
    fi
done
if [[ -n "$CONTROL_TOOL" ]] && command -v mosquitto_pub >/dev/null && [[ -n "${OPENSSL:-}" ]]; then
    SERVICE_PORT=8883 service control "serve" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/control-scenarios.py" "$ROOT/deploy/dev" "$CONTROL_TOOL" -- \
        "client: control-revoke-live ok" "client: control-unrevoke ok" "client: control-forged ok" \
        "client: control-replay ok" "client: control-expired ok" "client: control-from-device ok" \
        "client: bootstrap-role ok" "client: ca-rotation ok" \
        "control: seq [0-9]+ from operator: revoke of 1 item\(s\) applied" \
        "control: core [0-9]+: 1 live connection\(s\) closed" "invalid peer certificate: Revoked" \
        "control: seq [0-9]+ from operator: unrevoke of 1 item\(s\) applied" \
        "control: message from operator rejected: bad_signature" \
        "control: message from operator rejected: replay" \
        "control: message from operator rejected: expired" \
        "publish\(es\) to \\\$urmqtt/ by identities without control rights dropped" \
        "tls: device-006 authenticated \(TLS13_[A-Z0-9_]+, bootstrap role\)" \
        "tls: device-005 authenticated" "NOT:FAILED" "$NO_FAULT"
    SERVICE_PORT=8883 service registry-allowlist "serve registry=allowlist" 18883 "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/control-scenarios.py" "$ROOT/deploy/dev" "$CONTROL_TOOL" --allowlist -- \
        "client: registry-allowlist ok" "registry allowlist, 0 allowlisted identities" \
        "registry: device-001 is not on the allowlist, refused" \
        "control: seq [0-9]+ from operator: allow of 1 item\(s\) applied" \
        "control: seq [0-9]+ from operator: disallow of 1 item\(s\) applied" \
        "control: core [0-9]+: 1 live connection\(s\) closed" "NOT:FAILED" "$NO_FAULT"
    control_persist
else
    echo "  ✗ control scenarios need urmqtt-control, mosquitto clients and OpenSSL >= 3"
    FAILED=$((FAILED + 1))
fi
# H7 lower bound: a clock before the image's build time is unknown time;
# certificate checks then refuse every handshake.
time_before_build

# M11: SQLite on the data disk: batched write throughput, crash
# consistency after SIGKILL, broker state across a restart.
scenario db-bench "smoke test=db-bench" on \
    "db-bench: 5000 inserts in 50 transactions: [0-9]+ ops/s" "5100 rows verified" "^URMQTT READY$" "$NO_FAULT"
# M16: a handler overrunning its budget is reported from the tick.
scenario watchdog "smoke test=watchdog" on \
    "watchdog: core 0 self-test handler \(step -\) for conn 42 over budget: [0-9]+ ms > 10 ms \(action: Log" \
    "^URMQTT READY$" "$NO_FAULT"
# ADR-071: a handshake step has a budget of its own. The self-test spends half
# of it (not reported although far over the ordinary 10 ms), then overruns it.
scenario watchdog-handshake "smoke test=watchdog-handshake" on \
    "watchdog: core 0 handshake handler \(step -\) for conn 43 over budget: [0-9]+ ms > ([5-9][0-9]|[1-9][0-9]{2}) ms \(action: Log" \
    "NOT:conn 43 over budget: [0-9]+ ms > 10 ms" "^URMQTT READY$" "$NO_FAULT"
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
attack_raw
attack_app
observability
first_boot
first_boot_crash
scsi_boot
iso_as_cd
if command -v mosquitto_pub >/dev/null; then
    live_suite
else
    echo "  ✗ live-mode scenarios need the mosquitto clients"
    FAILED=$((FAILED + 1))
fi
own_damaged
disk_tool
[[ $ARCH == aarch64 ]] && install_iso
no_hw_rng
[[ $ARCH == aarch64 ]] && gicv2

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
BOOT_SCENARIO=boot-acpi
[[ $ARCH == x86_64 ]] && BOOT_SCENARIO=x86-disk-q35
for accel in $ACCELS; do
    if pcap_has_garp "$OUT/$BOOT_SCENARIO-$accel.log.pcap"; then
        echo "  ✓ gratuitous ARP from 52:54:00:12:34:56 found in pcap [$accel]"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ gratuitous ARP missing from $OUT/$BOOT_SCENARIO-$accel.log.pcap"
        FAILED=$((FAILED + 1))
    fi
done

# M5: DTB and ACPI must describe the same machine identically.
for accel in $ACCELS; do
    [[ $ARCH == aarch64 ]] || break
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
