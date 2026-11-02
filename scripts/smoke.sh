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
# Host port the scenarios forward the broker's TLS port to (SMOKE_PORT picks
# another one when other QEMU jobs run on this machine).
PORT=${SMOKE_PORT:-18883}
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

# boot_until <log> <pattern> <run-qemu args...>: boots in the background, waits
# for <pattern> in the serial log, then stops QEMU. For images that do not end
# by themselves (a production kernel serves; after a fatal error it shows the
# message for a minute before it resets). Returns 124 if the pattern never came.
boot_until() {
    local log=$1 pat=$2 waited=0 status=0 pid
    shift 2
    rm -f "$log"
    "$ROOT/scripts/run-qemu.sh" --serial "$log" --headless "$@" >"$log.qemu" 2>&1 &
    pid=$!
    until clean "$log" 2>/dev/null | grep -Eq -- "$pat"; do
        if ! kill -0 "$pid" 2>/dev/null || (( waited >= TIMEOUT * 10 )); then status=124; break; fi
        sleep 0.1
        waited=$((waited + 1))
    done
    sleep 1
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return $status
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
    "$ROOT/scripts/mkiso.sh" --kernel "$KERNEL" --out "$out.iso" --cmdline "$cmdline" --esp-out "$out.esp" \
        ${MKIMG_EXTRA[@]+"${MKIMG_EXTRA[@]}"} >/dev/null
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
            # The clients that check the serial log itself read it from here.
            SMOKE_LOG="$log" "${client[@]}" "$port" >"$log.client" 2>&1 || status=$?
            sleep 0.5
        fi
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        cat "$log.client" >>"$log" 2>/dev/null || true
        check "$name [$accel]" "$log" "$status" "$@"
    done
}

# want <function>: with SMOKE_SCENARIOS=<regex> the groups of scenarios that
# are functions (storm, attack_app, ...) run only if their name matches too.
want() { [[ -z ${SMOKE_SCENARIOS:-} || $1 =~ $SMOKE_SCENARIOS ]]; }

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
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd $PORT:8883
        if wait_log "$log1" "TLS 1.3 listener"; then
            python3 -I "$ROOT/scripts/ticket-scenarios.py" "$ROOT/deploy/dev" restart "$go" $PORT \
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
            start_vm "$log2" --disk "$data" --accel "$accel" --fwd $PORT:8883
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
    local tls=(--port "$PORT" --ca "$d/ca.pem" --client-cert "$d/services/operator.pem" --client-key "$d/services/operator.key")
    for accel in $ACCELS; do
        local log1="$OUT/control-persist-$accel-1.log" log2="$OUT/control-persist-$accel-2.log"
        local data="$OUT/control-persist-$accel.img" status=0
        rm -f "$msg" "$log2.client"
        fresh_disk "$iso" "$data"
        start_vm "$log1" --disk "$data" --accel "$accel" --fwd $PORT:8883
        if wait_log "$log1" "TLS 1.3 listener"; then
            "$CONTROL_TOOL" revoke --cert "$d/devices/device-002.pem" --env dev --key "$d/control.key" \
                --out "$msg" "${tls[@]}" >>"$log1.client" 2>&1 || status=1
            wait_log "$log1" "revoke of 1 item\(s\) applied" || status=124
        else
            status=124
        fi
        kill_vm
        if [[ $status -eq 0 ]]; then
            start_vm "$log2" --disk "$data" --accel "$accel" --fwd $PORT:8883
            if wait_log "$log2" "TLS 1.3 listener"; then
                "$CONTROL_TOOL" publish-file "$msg" "${tls[@]}" >>"$log2.client" 2>&1 || status=1
                wait_log "$log2" "rejected: replay" || status=124
                if mosquitto_pub -h 127.0.0.1 -p $PORT -V mqttv311 -i device-002 --cafile "$d/ca.pem" \
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "${SNTP_FWD:-$PORT}:8883" \
            -- -rtc base=2020-01-01T00:00:00
        if wait_log "$log" "TLS 1.3 listener"; then
            if mosquitto_pub -h 127.0.0.1 -p "${SNTP_FWD:-$PORT}" -V mqttv311 -i device-001 --cafile "$d/ca.pem" \
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

# T1 (ADR-100): SNTP against a responder on the host (QEMU user net, 10.0.2.2),
# dev only. (1) The RTC is before the build time (unknown clock): the
# responder's answer sets the clock once, and a device handshake then
# succeeds. (2) The responder claims 1970: refused, the clock stays unknown
# and the handshake is refused. (3) The responder sends a kiss-of-death.
# (4) Unsolicited / forged answers (a wrong origin) never set the clock.
# SNTP_PORT (UDP, host) and SNTP_FWD (TCP, host) pick the host ports.
time_sntp() {
    local port=${SNTP_PORT:-12123} fwd=${SNTP_FWD:-28883}
    local iso="$OUT/time-sntp.raw"
    mkimg "$iso" "serve sntp=10.0.2.2:$port"
    local d="$ROOT/deploy/dev"
    for accel in $ACCELS; do
        local mode
        for mode in ok past kod wrongorigin; do
            local log="$OUT/time-sntp-$mode-$accel.log" data="$OUT/time-sntp-$mode-$accel.img" status=0
            rm -f "$log.client" "$log.sntp"
            fresh_disk "$iso" "$data"
            python3 -I "$ROOT/scripts/sntp-responder.py" "$port" "$mode" 60 "$log.sntp" &
            local responder=$!
            sleep 0.5
            start_vm "$log" --disk "$data" --accel "$accel" --fwd "$fwd:8883" \
                -- -rtc base=2020-01-01T00:00:00
            local want_log="time: sntp (set|stepped|adjusted)"
            [[ $mode == ok ]] || want_log="time: sntp round failed|time: sntp offset .* refused"
            if wait_log "$log" "$want_log" && wait_log "$log" "TLS 1.3 listener"; then
                local ok=0
                mosquitto_pub -h 127.0.0.1 -p "$fwd" -V mqttv311 -i device-001 --cafile "$d/ca.pem" \
                    --cert "$d/devices/device-001.pem" --key "$d/devices/device-001.key" \
                    -t devices/device-001/x -m x >/dev/null 2>&1 && ok=1
                if [[ $mode == ok && $ok -eq 1 ]]; then
                    echo "client: handshake accepted with the SNTP clock" >>"$log.client"
                elif [[ $mode != ok && $ok -eq 1 ]]; then
                    echo "client: handshake ACCEPTED without a trustworthy clock" >>"$log.client"
                fi
                sleep 0.5
            else
                status=124
            fi
            kill_vm
            kill "$responder" 2>/dev/null || true
            wait "$responder" 2>/dev/null || true
            cat "$log.client" "$log.sntp" >>"$log" 2>/dev/null || true
            case $mode in
                ok) check "time-sntp-ok [$accel]" "$log" "$status" \
                    "date at boot: unix 15[0-9]+ is before this image was built" \
                    "time: sntp servers \[10\.0\.2\.2:$port\]" \
                    "time: sntp set \(first synchronisation\) the clock \(it was unknown\) \(1 of 1 server" \
                    "client: handshake accepted with the SNTP clock" "sntp-responder: request" \
                    "NOT:handshake ACCEPTED" "$NO_FAULT" ;;
                past) check "time-sntp-past [$accel]" "$log" "$status" \
                    "time: sntp offset -?[0-9]+ ms refused: result below the image build time" \
                    "tls: connection refused" "NOT:handshake ACCEPTED" "NOT:sntp set" "$NO_FAULT" ;;
                kod) check "time-sntp-kod [$accel]" "$log" "$status" \
                    "time: sntp round failed: 0 of 1" "tls: connection refused" \
                    "NOT:handshake ACCEPTED" "NOT:sntp set" "$NO_FAULT" ;;
                wrongorigin) check "time-sntp-wrongorigin [$accel]" "$log" "$status" \
                    "time: sntp round failed: 0 of 1" "tls: connection refused" \
                    "NOT:handshake ACCEPTED" "NOT:sntp set" "$NO_FAULT" ;;
            esac
        done
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
            "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in the [0-9]+ newest segment\(s\) read of [0-9]+, [0-9]+ torn tail\(s\) truncated" \
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
            "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in the 1 newest segment\(s\) read of [0-9]+, 1 torn tail\(s\) truncated" \
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
            start_vm "$log" --disk "$data" --accel "$accel" --fwd "$PORT:8883"
            if wait_log "$log" "TLS 1.3 listener on port 8883"; then
                python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$ROOT/deploy/dev" --phase "$phase" \
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "$PORT:8883"
        if wait_log "$log" "TLS 1.3 listener on port 8883"; then
            (cd "$ROOT" && "$loadgen" storm --port $PORT --clients 3000 --threads 8 --rounds 3 \
                --retry-s 30 --subscribe 1 --min-connected 500) >"$log.client" 2>&1 || status=$?
            # Memory left by the last round is returned within 10 s.
            sleep 12
        else
            status=124
        fi
        kill_vm
        grep -v '^loadgen: bench-' "$log.client" >>"$log" 2>/dev/null || true
        check "storm [$accel]" "$log" "$status" "loadgen: storm round 3: [0-9]+ of 3000 connected" \
            "admission: [0-9]+ (connection\(s\) refused|SYN\(s\) dropped without an answer on core [0-9]+): heap below the free reserve" \
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "$PORT:8883"
        if wait_log "$log" "TLS 1.3 listener on port 8883"; then
            local c=(--port "$PORT" --certs "$ROOT/deploy/dev")
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
            "admission: [0-9]+ (connection\(s\) refused|SYN\(s\) dropped without an answer on core [0-9]+): too many handshakes in flight" \
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd "$PORT:8883"
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
        # Flip one byte inside the region table of both superblock slots (A at
        # sector 0, B at sector 24): since S5 the first boot has written the
        # upgraded layout to slot B and left the old one valid in slot A, so
        # damaging only one of them is survived by design (A/B superblock).
        printf '\xff' | dd of="$disk" bs=1 seek=$((first * 512 + 100)) conv=notrunc status=none
        printf '\xff' | dd of="$disk" bs=1 seek=$(((first + 24) * 512 + 100)) conv=notrunc status=none
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
        start_vm "$log1" --disk "$disk" --accel "$accel" --fwd $PORT:8883
        # Client output goes to its own file: QEMU writes the serial log at
        # its own offset, so appending there while it runs loses lines.
        rm -f "$log1.client" "$log2.client"
        if wait_log "$log1" "TLS 1.3 listener on port 8883"; then
            python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$d" --phase 1 >>"$log1.client" 2>&1 || status=1
            for v in 11 22 33; do
                mosquitto_pub -h 127.0.0.1 -p $PORT -V mqttv311 -i device-001 --cafile "$d/ca.pem" \
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
        start_vm "$log2" --disk "$disk" --accel "$accel" --fwd $PORT:8883
        if wait_log "$log2" "TLS 1.3 listener on port 8883"; then
            for id in device-002 device-003; do
                if mosquitto_pub -h 127.0.0.1 -p $PORT -V mqttv311 -i "$id" --cafile "$d/ca.pem" \
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

# S2 (STORAGE-PLAN, ADR-140): the block topology a disk reports shapes the
# layout and every write: QEMU is given a 4 KiB physical block and optimal I/O
# sizes; the kernel must read them (virtio-blk F_TOPOLOGY, virtio-scsi READ
# CAPACITY (16) and the Block Limits VPD page), align its regions, and send no
# write that is not a whole physical block (the debug counter misaligned_writes,
# checked after the in-guest database benchmark). 4096-byte logical blocks (4Kn)
# cannot boot an image whose GPT is in 512-byte sectors, so that case is a host
# test on a strict device (crates/store, writes_cover_whole_physical_blocks).
storage_topology() {
    local img="$OUT/topology.raw" row
    mkimg "$img" "smoke test=db-bench"
    for accel in $ACCELS; do
        # bus | QEMU properties | physical | optimal I/O | alignment unit (KiB)
        for row in "blk||512|0|1024" \
            "blk|physical_block_size=4096,min_io_size=4096,opt_io_size=262144|4096|262144|1024" \
            "blk|physical_block_size=4096,opt_io_size=2097152|4096|2097152|2048" \
            "scsi|physical_block_size=4096,min_io_size=4096,opt_io_size=1048576|4096|1048576|1024"; do
            IFS='|' read -r bus props phys opt align <<<"$row"
            local tag="$bus-${phys}-${opt}" disk="$OUT/topology-$accel.img" log status=0
            log="$OUT/topology-$tag-$accel.log"
            fresh_disk "$img" "$disk"
            boot "$log" --disk "$disk" --bus "$bus" ${props:+--blk-props "$props"} --accel "$accel" --headless --no-net || status=$?
            check "topology $bus phys=$phys opt=$opt [$accel]" "$log" "$status" \
                "blk: topology: logical 512 B, physical $phys B, alignment offset 0 B, minimum I/O [0-9]+ B, optimal I/O $opt B" \
                "storage: data disk formatted \(was blank\)" "telemetry partition\(s\), aligned to $align KiB, generation 2" \
                "storage: misaligned_writes=0 of [0-9]+ device writes after startup \(physical block $phys B, write granularity $phys B, optimal I/O $opt B\)" \
                "db-bench: .* 5100 rows verified" \
                "storage: misaligned_writes=0 of [0-9]+ device writes after db-bench \(physical block $phys B" \
                "NOT:misaligned_writes=[1-9]" "^URMQTT READY$" "$NO_FAULT"
        done
    done
}

# The host tool, built once (also by disk_tool).
DISK_TOOL=""
build_disk_tool() {
    [[ -n $DISK_TOOL ]] && return 0
    (cd "$ROOT" && cargo build --release --locked -q -p urmqtt-disk-tool) || return 1
    DISK_TOOL="$ROOT/target/release/urmqtt-disk"
}

# S7 end to end (ADR-240): encryption at rest. A dev configuration with
# storage.encryption = "aes-256-xts" and a key file:
#   1. a blank disk is formatted encrypted, the self-test (database, backup)
#      runs on it, and the disk image holds no SQLite header afterwards;
#   2. a second boot opens it again with the same key;
#   3. a configuration with another key, and one without encryption, are
#      refused with a reason (nothing is converted at boot);
#   4. the host tool opens it with the key, refuses without, and `decrypt`
#      gives a disk the plain configuration boots.
storage_encrypted() {
    build_disk_tool || {
        echo "  ✗ storage-encrypted needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL dir="$OUT/enc" tool="$ROOT/target/debug/urmqtt-config"
    rm -rf "$dir"
    mkdir -p "$dir/root"
    (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool)
    cp "$ROOT"/deploy/dev/* "$dir/root/" 2>/dev/null || true
    python3 -I - "$dir" <<'PY'
import sys
d = sys.argv[1]
open(d + "/k1.hex", "w").write("".join("%02x" % ((i * 7 + 3) & 255) for i in range(64)) + "\n")
open(d + "/k2.hex", "w").write("".join("%02x" % ((i * 11 + 5) & 255) for i in range(64)) + "\n")
PY
    local k
    for k in 1 2; do
        cp "$dir/k$k.hex" "$dir/root/disk.key"
        sed -e 's/^\[storage\]/[storage]\nencryption = "aes-256-xts"\ndisk_key = "disk.key"/' \
            "$ROOT/deploy/dev/config.toml" >"$dir/config$k.toml"
        "$tool" pack "$dir/config$k.toml" --env dev --root "$dir/root" --out "$dir/enc$k.blob" >/dev/null ||
            { echo "  ✗ storage-encrypted: packing failed"; FAILED=$((FAILED + 1)); return; }
    done
    sed -e 's/^handler_budget_ms = 10/handler_budget_ms = 10/' "$ROOT/deploy/dev/config.toml" >"$dir/plain.toml"
    "$tool" pack "$dir/plain.toml" --env dev --root "$ROOT/deploy/dev" --out "$dir/plain.blob" >/dev/null
    local name
    for name in enc1-fill:enc1:test=db-backup enc1-plain:enc1: enc2:enc2: plain:plain:; do
        local img=${name%%:*} rest=${name#*:}
        local blob=${rest%%:*} test=${rest#*:}
        MKIMG_EXTRA=(--config "$dir/$blob.blob")
        mkimg "$OUT/enc-$img.raw" "smoke${test:+ $test}"
        MKIMG_EXTRA=()
    done
    local accel
    for accel in $ACCELS; do
        local disk="$OUT/enc-$accel.img" status=0 l
        fresh_disk "$OUT/enc-enc1-fill.raw" "$disk"
        l="$OUT/enc-$accel-1.log"
        boot "$l" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "encrypted-first-boot [$accel]" "$l" "$status" \
            "storage: encryption aes-256-xts \(key check ok" \
            "db-backup: 100 selftest rows in snapshot seq 1" "db-backup: 50 more rows committed after the snapshot \(150 in all\)" \
            "^URMQTT READY$" "NOT:refusing to serve" "$NO_FAULT"
        {
            # The data partition only: the ESP holds the kernel, which embeds SQLite.
            dd if="$disk" of="$disk.data" bs=512 skip=18432 status=none
            if grep -aq "SQLite format 3" "$disk.data"; then echo "image: plaintext SQLite header FOUND"; else echo "image: no plaintext SQLite header"; fi
            if grep -aq "selftest" "$disk.data"; then echo "image: table name FOUND"; else echo "image: no plaintext table name"; fi
        } >"$l.scan"
        check "encrypted-no-plaintext-at-rest [$accel]" "$l.scan" 0 "image: no plaintext SQLite header" "image: no plaintext table name"

        status=0
        set_esp "$disk" "$OUT/enc-enc1-plain.raw"
        l="$OUT/enc-$accel-2.log"
        boot "$l" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "encrypted-second-boot [$accel]" "$l" "$status" "storage: encryption aes-256-xts" "storage: data disk opened" \
            "db: sqlite .* quick_check ok" "^URMQTT READY$" "NOT:RESTORED" "NOT:refusing to serve" "$NO_FAULT"

        status=0
        set_esp "$disk" "$OUT/enc-enc2.raw"
        l="$OUT/enc-$accel-3.log"
        boot_until "$l" "refusing to serve" --disk "$disk" --accel "$accel" --fwd none || status=$?
        check "encrypted-wrong-key-refused [$accel]" "$l" "$status" \
            "storage.disk_key does not match the data partition's key check" "NOT:URMQTT READY"

        status=0
        set_esp "$disk" "$OUT/enc-plain.raw"
        l="$OUT/enc-$accel-4.log"
        boot_until "$l" "refusing to serve" --disk "$disk" --accel "$accel" --fwd none || status=$?
        check "encrypted-without-config-refused [$accel]" "$l" "$status" \
            "the data partition is encrypted but the configuration has no storage.encryption" "NOT:URMQTT READY"

        {
            "$ud" verify "$disk" 2>&1 || echo "tool: verify without key refused"
            "$ud" verify "$disk" --key "$dir/k2.hex" 2>&1 || echo "tool: verify with the wrong key refused"
            "$ud" verify "$disk" --key "$dir/k1.hex" 2>&1 && echo "tool: verify with the key exit 0"
            "$ud" decrypt "$disk" --key "$dir/k1.hex" --write 2>&1 | tail -1
            "$ud" verify "$disk" 2>&1 && echo "tool: verify of the decrypted disk exit 0"
        } >"$disk.tool" 2>&1
        check "encrypted-disk-tool [$accel]" "$disk.tool" 0 \
            "the data partition is encrypted: give its key with --key FILE" "tool: verify without key refused" \
            "the key does not match this disk" "tool: verify with the wrong key refused" \
            "tool: verify with the key exit 0" "the disk is now plain" "tool: verify of the decrypted disk exit 0"

        status=0
        set_esp "$disk" "$OUT/enc-plain.raw"
        l="$OUT/enc-$accel-5.log"
        boot "$l" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "decrypted-disk-boots-plain [$accel]" "$l" "$status" "storage: data disk opened" \
            "db: sqlite .* quick_check ok" "^URMQTT READY$" "NOT:encryption" "NOT:refusing to serve" "$NO_FAULT"
    done
}

# S7 measurement (not a pass/fail check): the in-guest database benchmark and
# the boot with encryption off and on, interleaved, SMOKE_BENCH_RUNS (5) runs
# each. Reads the numbers out of the serial logs.
storage_encrypted_bench() {
    local dir="$OUT/encb" tool="$ROOT/target/debug/urmqtt-config" runs=${SMOKE_BENCH_RUNS:-5}
    rm -rf "$dir"
    mkdir -p "$dir/root"
    (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool)
    cp "$ROOT"/deploy/dev/* "$dir/root/" 2>/dev/null || true
    python3 -I -c 'print("".join("%02x" % ((i * 7 + 3) & 255) for i in range(64)))' >"$dir/root/disk.key"
    sed -e 's/^\[storage\]/[storage]\nencryption = "aes-256-xts"\ndisk_key = "disk.key"/' "$ROOT/deploy/dev/config.toml" >"$dir/enc.toml"
    "$tool" pack "$dir/enc.toml" --env dev --root "$dir/root" --out "$dir/enc.blob" >/dev/null
    "$tool" pack "$ROOT/deploy/dev/config.toml" --env dev --root "$ROOT/deploy/dev" --out "$dir/plain.blob" >/dev/null
    local mode
    for mode in plain enc; do
        MKIMG_EXTRA=(--config "$dir/$mode.blob")
        mkimg "$OUT/encb-$mode.raw" "smoke test=db-bench"
        MKIMG_EXTRA=()
    done
    local accel i
    for accel in $ACCELS; do
        for i in $(seq 1 "$runs"); do
            for mode in plain enc; do
                local disk="$OUT/encb-$mode-$accel.img" l="$OUT/encb-$mode-$accel-$i.log" status=0
                fresh_disk "$OUT/encb-$mode.raw" "$disk"
                boot "$l" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
                echo "bench $mode [$accel] run $i: $(clean "$l" | sed -n 's/.*db-bench: 5000 inserts in 50 transactions: \([0-9]*\) ops\/s (\([0-9]*\) us per commit).*/\1 ops\/s, \2 us per commit/p' | tail -1); ready at $(clean "$l" | sed -n 's/^\[ *\([0-9.]*\)\].*URMQTT READY.*/\1/p' | tail -1) s"
            done
        done
    done
}

# S2 + S3 end to end (ADR-141, ADR-142). A layout-v1 data partition holding
# real broker state (the host tool builds it: no v1 kernel exists any more):
#   1. the kernel refuses it and writes nothing (the disk's hash is the same
#      before and after, the self-test is skipped);
#   2. urmqtt-disk migrate: dry run first (nothing written), then --write, the
#      tool's own verification (integrity, row counts, telemetry records);
#   3. the kernel boots the migrated disk and restores the same state;
#   4. the disk file is made larger: the next boot extends the partition and
#      grows the layout, data intact; the boot after that does nothing;
#   5. a power cut at five writes of that grow, each followed by a normal boot
#      that ends in the grown layout with all the data.
layout_v1() {
    build_disk_tool || {
        echo "  ✗ layout-v1 needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL img="$OUT/layout-v1.raw" good="$OUT/layout-v1-ok.raw" spec
    mkimg "$img" "smoke"
    mkimg "$good" "smoke"
    local restored='db: restored 2 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), [0-9]+ revoked serial\(s\), 40 known device\(s\)'
    local telemetry='telemetry: log recovered in [0-9]+ ms: 600 record\(s\)'
    for accel in $ACCELS; do
        local disk="$OUT/layout-v1-$accel.img" rb="$OUT/layout-v1-$accel.rollback"
        local l1="$OUT/layout-v1-refused-$accel.log" tl="$OUT/layout-v1-tool-$accel.log"
        local l2="$OUT/layout-v1-migrated-$accel.log" l3="$OUT/layout-v1-grown-$accel.log"
        local l4="$OUT/layout-v1-grown-again-$accel.log" status=0 before after
        fresh_disk "$img" "$disk"
        rm -f "$rb"
        "$ud" fixture-v1 "$disk" --populate --write >"$tl.fixture" 2>&1 || { echo "  ✗ fixture-v1 failed"; cat "$tl.fixture"; FAILED=$((FAILED + 1)); continue; }
        before=$(shasum -a 256 "$disk" | cut -d' ' -f1)
        boot "$l1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        after=$(shasum -a 256 "$disk" | cut -d' ' -f1)
        [[ $before == "$after" ]] || echo "THE DISK WAS WRITTEN" >>"$l1"
        check "layout-v1-refused [$accel]" "$l1" "$status" \
            "data disk is layout v1; this image needs v2: run urmqtt-disk migrate \(docs/DEPLOY.md\)" \
            "storage: refused reason=layout-v1" "blk: self-test skipped" \
            "NOT:storage: data disk formatted" "NOT:URMQTT READY" "NOT:THE DISK WAS WRITTEN" "$NO_FAULT"

        status=0
        {
            "$ud" info "$disk"
            "$ud" migrate "$disk" && echo "tool: dry run exit 0"
            [[ $(shasum -a 256 "$disk" | cut -d' ' -f1) == "$before" ]] && echo "tool: the dry run left the disk unchanged"
            "$ud" migrate "$disk" --write --rollback-file "$rb" || echo "tool: MIGRATE FAILED"
            [[ -s $rb ]] && echo "tool: rollback file written"
            "$ud" verify "$disk" && echo "tool: verify exit 0"
            "$ud" info "$disk"
        } >"$tl" 2>&1
        check "layout-v1-migrate-tool [$accel]" "$tl" "$status" \
            "data: layout v1 \(the kernel refuses it" "layout v1 -> v2" "new regions:" \
            "dry run: nothing was written" "tool: the dry run left the disk unchanged" \
            "migrate: v1 superblock saved, state planned" "migrate: v2 superblock written to slot B: the disk is v2" \
            "verify: telemetry identical \(600 record" "verify: sqlite integrity_check ok; row counts identical" \
            "migrate: done" "tool: rollback file written" "tool: verify exit 0" "verify: ok" \
            "data: layout v2 generation 2" "NOT:MIGRATE FAILED"

        status=0
        boot "$l2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "layout-v1-migrated-boots [$accel]" "$l2" "$status" "storage: data disk opened" \
            "8 telemetry partition\(s\), aligned to 1024 KiB, generation 3" "$restored" "$telemetry" \
            "storage: misaligned_writes=0 of" "^URMQTT READY$" "NOT:storage: grew" "$NO_FAULT"

        # S3: the disk gets larger (a cloud volume resize). The next boot
        # moves the backup table, extends the data partition, grows the layout.
        cp "$disk" "$OUT/layout-v2-base-$accel.img"
        truncate -s 192m "$disk"
        status=0
        boot "$l3" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "grow-boot [$accel]" "$l3" "$status" \
            "gpt: backup table moved to the end of the 192 MiB disk" \
            "gpt: data partition extended to the end of the 192 MiB disk" \
            "storage: grew the layout from [0-9]+ MiB to [0-9]+ MiB \(generation 4\): database \+[0-9]+ MiB, telemetry \+[0-9]+ MiB, split 50% database" \
            "storage: data disk opened" "$restored" "$telemetry" "^URMQTT READY$" "NOT:THE DISK" "$NO_FAULT"
        status=0
        boot "$l4" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "grow-again-noop [$accel]" "$l4" "$status" "storage: data disk opened" "$restored" "$telemetry" \
            "generation 4" "NOT:storage: grew" "NOT:gpt: data partition extended" "NOT:gpt: backup table moved" \
            "^URMQTT READY$" "$NO_FAULT"
        "$ud" verify "$disk" >"$tl.final" 2>&1 && echo "tool: final verify exit 0" >>"$tl.final"
        check "grow-tool-verify [$accel]" "$tl.final" 0 "verify: ok" "tool: final verify exit 0" "layout: ok"

        # A power cut at writes of the grow: the kernel's writes are the nine
        # of the GPT steps (backup moved, partition extended), the one of the
        # boot self-test, then the superblock write (the 11th). Each cut is
        # followed by an ordinary boot that must end in the grown layout with
        # all the data.
        for spec in stop-after-write=3 stop-after-write=5 stop-after-write=8 stop-after-write=9 \
            stop-after-write=10 stop-after-write=11 tear-write=9:1 tear-write=11:1; do
            local fimg="$OUT/grow-crash-${spec//[=:]/-}.raw" fdisk="$OUT/grow-crash-$accel.img"
            local lf="$OUT/grow-crash-${spec//[=:]/-}-$accel.log" lr="$OUT/grow-crash-${spec//[=:]/-}-$accel-2.log"
            mkimg "$fimg" "smoke test=disk-fault:$spec"
            cp "$OUT/layout-v2-base-$accel.img" "$fdisk"
            truncate -s 192m "$fdisk"
            set_esp "$fdisk" "$fimg"
            status=0
            boot "$lf" --disk "$fdisk" --accel "$accel" --headless --no-net || status=$?
            check "grow-crash $spec [$accel]" "$lf" "$status" \
                "disk-fault: power cut injected|fatal: blk (write|flush) failed" "NOT:URMQTT READY" "NOT:PANIC|EXCEPTION"
            set_esp "$fdisk" "$good"
            status=0
            boot "$lr" --disk "$fdisk" --accel "$accel" --headless --no-net || status=$?
            check "grow-crash $spec recovered [$accel]" "$lr" "$status" \
                "storage: data disk opened \([0-9]{3} MiB" "$restored" "$telemetry" "^URMQTT READY$" "$NO_FAULT"
        done
    done
}

# S3 (ADR-143): online grow. A serving VM on a layout-v2 disk that holds data;
# the host enlarges the disk with QEMU's block_resize over QMP while it runs.
# virtio-blk raises a configuration-change interrupt, the DB core asks the
# device for its size, extends the partition, grows the layout and takes up the
# new telemetry band, without a reboot. Needs layout_v1 to have built the base
# disk. The QMP socket lives in a short path (a Unix socket name is limited).
grow_online() {
    build_disk_tool || return 0
    local ud=$DISK_TOOL serve="$OUT/grow-online-serve.raw" restored telemetry
    restored='db: restored 2 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), [0-9]+ revoked serial\(s\), 40 known device\(s\)'
    telemetry='telemetry: log recovered in [0-9]+ ms: 600 record\(s\)'
    mkimg "$serve" "serve"
    for accel in $ACCELS; do
        # aarch64 TCG gives the guest a GICv3 with an ITS, which the kernel does not use
        # for MSI-X (HVF has the GICv2m frame): the disk is polled, no resize notification.
        if [[ $ARCH == aarch64 && $accel == tcg ]]; then
            echo "  - grow-online [tcg] skipped: no MSI-X (ITS) on aarch64 TCG, the grown disk is taken up at the next boot"
            continue
        fi
        local base="$OUT/layout-v2-base-$accel.img" disk="$OUT/grow-online-$accel.img"
        local log="$OUT/grow-online-$accel.log" log2="$OUT/grow-online-again-$accel.log" status=0
        if [[ ! -f $base ]]; then
            echo "  ✗ grow-online needs the layout_v1 scenario to run first (no $base)"
            FAILED=$((FAILED + 1))
            continue
        fi
        cp "$base" "$disk"
        set_esp "$disk" "$serve"
        local qdir sock
        qdir=$(mktemp -d "${TMPDIR:-/tmp}/urmqtt-qmp.XXXXXX") || continue
        sock="$qdir/q.sock"
        start_vm "$log" --disk "$disk" --accel "$accel" --fwd none -- -qmp "unix:$sock,server=on,wait=off"
        if wait_log "$log" '^URMQTT READY$'; then
            local after
            python3 -I - "$sock" $((192 * 1048576)) >"$log.qmp" 2>&1 <<'PY' || status=1
import json, socket, sys, time
s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect(sys.argv[1]); break
    except OSError:
        time.sleep(0.1)
f = s.makefile("rw")
f.readline()
def cmd(c):
    f.write(json.dumps(c) + "\n"); f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
cmd({"execute": "qmp_capabilities"})
print("qmp: block_resize", cmd({"execute": "block_resize", "arguments": {"device": "boot0", "size": int(sys.argv[2])}}))
PY
            wait_log "$log" 'storage: grew the layout online' || status=124
            sleep 1
            after=$(clean "$log" | grep -c 'storage: grew the layout online' || true)
            echo "grow-online: $after online grow(s) logged" >>"$log"
        else
            status=124
        fi
        kill_vm
        rm -rf "$qdir"
        # The client's output is added after QEMU stopped writing the log.
        cat "$log.qmp" >>"$log" 2>/dev/null || true
        check "grow-online [$accel]" "$log" "$status" \
            "blk: resize notification \(configuration-change interrupt\): armed" \
            "qmp: block_resize \{'return': \{\}\}" \
            "storage: grew the layout online from [0-9]+ MiB to 1[0-9]{2} MiB \(generation 4\)" \
            "grow-online: 1 online grow\(s\) logged" "NOT:online grow failed" "NOT:taking up the grown layout failed" \
            "storage: discard: requests=[1-9][0-9]* ranges=[1-9][0-9]* released=[1-9][0-9]* KiB \(queued: telemetry 0 KiB, truncate [0-9]+ KiB, grow [1-9][0-9]* KiB\)" \
            "NOT:storage: discard failed" "$NO_FAULT"
        "$ud" verify "$disk" >"$log.verify" 2>&1 && echo "tool: verify exit 0" >>"$log.verify"
        "$ud" info "$disk" >>"$log.verify" 2>&1
        check "grow-online-disk [$accel]" "$log.verify" 0 "verify: ok" "tool: verify exit 0" \
            "data: layout v2 generation 4" "telemetry: ok, 600 record\(s\)" \
            "urMQTT data \"urMQTT data\" LBA [0-9]+\.\.[0-9]+ \(1[0-9]{2} MiB\)"
        # An ordinary reboot sees the grown layout and all the data.
        set_esp "$disk" "$OUT/layout-v1-ok.raw"
        status=0
        boot "$log2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "grow-online-reboot [$accel]" "$log2" "$status" "storage: data disk opened \(1[0-9]{2} MiB" \
            "$restored" "$telemetry" "generation 4" "NOT:storage: grew" "^URMQTT READY$" "$NO_FAULT"
    done
}

# qcow2_alloc <file>: "<bytes the qcow2 maps as data> <bytes the host file
# occupies>" (st_blocks), of an image no VM has open.
qcow2_alloc() {
    python3 -I - "$1" <<'PY'
import json, os, subprocess, sys
f = sys.argv[1]
m = json.loads(subprocess.check_output(["qemu-img", "map", "--output=json", f]))
data = sum(e["length"] for e in m if e.get("data") and not e.get("zero"))
print(data, os.stat(f).st_blocks * 512)
PY
}

# S4 (ADR-150): the guest releases space and the host image shrinks. A qcow2
# disk attached with discard=unmap holds 16 telemetry segments (2 per
# partition) that are 40 days old, written by `test=discard-fill`. The next
# boot's retention retires them, the kernel sends the device's discard (virtio-blk
# DISCARD, or SCSI UNMAP on the scsi bus) and then flushes; the host measures
# what the qcow2 maps as data (and the file's allocated blocks) before and
# after, once QEMU has quit cleanly. A third boot recovers: the retired segments
# are gone, the active ones remain, whatever the device holds in the freed
# ranges. Also: discard = "off" in a boot of its own does nothing.
discard_qcow2() {
    command -v qemu-img >/dev/null || { echo "  ✗ discard-qcow2 needs qemu-img"; FAILED=$((FAILED + 1)); return; }
    local fill="$OUT/discard-fill.raw" ret="$OUT/discard-retire.raw" ver="$OUT/discard-verify.raw" bus
    mkimg "$fill" "smoke test=discard-fill"
    mkimg "$ret" "smoke serve"
    mkimg "$ver" "smoke"
    for accel in $ACCELS; do
        for bus in blk scsi; do
            local tag="discard-qcow2-$bus-$accel" disk="$OUT/discard-qcow2-$bus-$accel.qcow2" raw="$OUT/discard-qcow2-$bus-$accel.img"
            local l1="$OUT/$tag-1.log" l2="$OUT/$tag-2.log" l3="$OUT/$tag-3.log" status=0
            # The first boot writes the old records to a raw (sparse) disk.
            fresh_disk "$fill" "$raw" 512m
            boot "$l1" --disk "$raw" --bus "$bus" --accel "$accel" --headless --no-net || status=$?
            check "discard-fill [$bus, $accel]" "$l1" "$status" \
                "storage: discard: auto, (device discard|write-zeroes with unmap) \([0-9]+ KiB per range at most" \
                "discard-fill: [0-9]+ record\(s\) dated 40 days ago durable in 8 partition\(s\)" \
                "NOT:segment\(s\) past retention" "NOT:storage: discard: requests=" "^URMQTT READY$" "$NO_FAULT"
            # The same disk as a qcow2 (only the data is allocated), measured.
            set_esp "$raw" "$ret"
            rm -f "$disk"
            qemu-img convert -f raw -O qcow2 "$raw" "$disk"
            local qopts=(--disk "$disk" --disk-format qcow2 --discard unmap --bus "$bus" --accel "$accel")
            local before blocks_before after blocks_after
            read -r before blocks_before < <(qcow2_alloc "$disk")

            # Retention: the next boot retires and releases. QEMU is quit
            # through QMP so the qcow2 is closed and flushed.
            status=0
            local qdir sock
            qdir=$(mktemp -d "${TMPDIR:-/tmp}/urmqtt-qmp.XXXXXX") || continue
            sock="$qdir/q.sock"
            start_vm "$l2" "${qopts[@]}" --fwd none -- -qmp "unix:$sock,server=on,wait=off"
            if wait_log "$l2" 'storage: discard: requests=[1-9][0-9]* ranges='; then
                sleep 0.5
            else
                status=124
            fi
            python3 -I - "$sock" >"$l2.qmp" 2>&1 <<'PY' || true
import json, socket, sys, time
s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect(sys.argv[1]); break
    except OSError:
        time.sleep(0.1)
f = s.makefile("rw")
f.readline()
f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n"); f.flush(); f.readline()
f.write(json.dumps({"execute": "quit"}) + "\n"); f.flush()
print("qmp: quit")
PY
            local waited=0
            while kill -0 "$VM_PID" 2>/dev/null && (( waited < 100 )); do sleep 0.1; waited=$((waited + 1)); done
            kill_vm
            rm -rf "$qdir"
            read -r after blocks_after < <(qcow2_alloc "$disk")
            local released
            released=$(clean "$l2" | grep -Eo 'released=[0-9]+ KiB' | tail -1 | grep -Eo '[0-9]+')
            {
                echo "discard-qcow2: mapped data before $before B, after $after B (guest reported ${released:-0} KiB released)"
                echo "discard-qcow2: host file blocks before $blocks_before B, after $blocks_after B"
            } >>"$l2"
            check "discard-retention [$bus, $accel]" "$l2" "$status" \
                "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in the [0-9]+ newest segment\(s\) read of 24" \
                "telemetry: 16 segment\(s\) past retention \(30 days\) retired, 8 still in use" \
                "storage: discard: requests=[1-9][0-9]* ranges=[1-9][0-9]* released=[1-9][0-9]* KiB \(queued: telemetry [1-9][0-9]* KiB, truncate [0-9]+ KiB, grow [0-9]+ KiB\) cancelled=0 KiB dropped=0 KiB failed=0" \
                "NOT:discard failed" "NOT:discard stopped" "^URMQTT READY$" "$NO_FAULT"
            # 16 segments of 2.9 MiB are released; the image must shrink by
            # nearly that much (the qcow2 clusters are freed).
            if [[ -n $before && -n $after && -n $released ]] && (( before - after >= released * 1024 * 8 / 10 )); then
                echo "  ✓ qcow2 allocation shrank: $((before >> 20)) MiB -> $((after >> 20)) MiB mapped, host file $((blocks_before >> 20)) MiB -> $((blocks_after >> 20)) MiB [$bus, $accel]"
                PASSED=$((PASSED + 1))
            else
                echo "  ✗ qcow2 allocation did not shrink as reported: mapped ${before:-?} -> ${after:-?}, released ${released:-?} KiB [$bus, $accel]"
                FAILED=$((FAILED + 1))
            fi

            status=0
            rm -f "$raw"
            qemu-img convert -f qcow2 -O raw "$disk" "$raw"
            set_esp "$raw" "$ver"
            boot "$l3" --disk "$raw" --bus "$bus" --accel "$accel" --headless --no-net || status=$?
            check "discard-recovered [$bus, $accel]" "$l3" "$status" \
                "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in the [0-9]+ newest segment\(s\) read of 8, 0 torn tail\(s\) truncated" \
                "storage: data disk opened" "quick_check ok" "^URMQTT READY$" "NOT:telemetry log rejected" "$NO_FAULT"
        done
    done
}

# S5 (ADR-160 to ADR-164): the in-disk database backup, end to end.
#   1. `test=db-backup` fills 100 selftest rows, takes a backup (adding the
#      backup region to the fresh layout first: one superblock write), writes
#      50 more rows. The host tool sees the intact snapshot, and the snapshot
#      is an SQLite file with exactly 100 rows.
#   2. `test=db-corrupt` damages the database file; the same boot finds it
#      corrupt, restores the snapshot, logs the lost window loudly and
#      carries on with the first 100 rows.
#   3. A plain boot afterwards restores nothing.
#   4. The power is cut inside a second backup (test=disk-fault, at two
#      points of its writes): the first snapshot is still intact, the disk
#      verifies, and the next boot with a damaged database restores it.
db_backup() {
    build_disk_tool || {
        echo "  ✗ db-backup needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL fill="$OUT/db-backup-fill.raw" cor="$OUT/db-backup-corrupt.raw" plain="$OUT/db-backup-plain.raw"
    mkimg "$fill" "smoke test=db-backup"
    mkimg "$cor" "smoke test=db-corrupt"
    mkimg "$plain" "smoke"
    local restored='storage: DATABASE RESTORED FROM BACKUP: snapshot seq 1 from slot 0 \([0-9]+ KiB, schema v[0-9]+\); [0-9]+ s of changes \(since unix [0-9]+\) are LOST; reason: .+'
    for accel in $ACCELS; do
        local disk="$OUT/db-backup-$accel.img" base="$OUT/db-backup-base-$accel.img" status=0
        local l1="$OUT/db-backup-$accel-1.log" l2="$OUT/db-backup-$accel-2.log" l3="$OUT/db-backup-$accel-3.log"
        fresh_disk "$fill" "$disk"
        boot "$l1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "db-backup-snapshot [$accel]" "$l1" "$status" \
            "storage: backup region added \(layout v2.1\): [0-9]+ MiB, two slots of [0-9]+ KiB, carved from the database's unused tail" \
            "backup: every 60 min into the backup region; newest snapshot: seq 1" \
            "db-backup: device writes before the backup [0-9]+, after [0-9]+" \
            "db-backup: 100 selftest rows in snapshot seq 1 \(slot 0, [0-9]+ KiB, [0-9]+ step\(s\), longest [0-9]+ us\)" \
            "db-backup: 50 more rows committed after the snapshot \(150 in all\)" "^URMQTT READY$" "NOT:backup: FAILED" "$NO_FAULT"
        local w0 w1
        w0=$(clean "$l1" | sed -n 's/.*db-backup: device writes before the backup \([0-9]*\), after \([0-9]*\)/\1/p' | tail -1)
        w1=$(clean "$l1" | sed -n 's/.*db-backup: device writes before the backup \([0-9]*\), after \([0-9]*\)/\2/p' | tail -1)
        {
            "$ud" info "$disk"
            "$ud" verify "$disk" && echo "tool: verify exit 0"
            "$ud" backup-extract "$disk" "$disk.snap.sqlite" && echo "tool: extract exit 0"
            if command -v sqlite3 >/dev/null; then
                echo "tool: snapshot has $(sqlite3 "$disk.snap.sqlite" "PRAGMA integrity_check; SELECT count(*) FROM selftest;" | tr '\n' ' ')selftest rows"
            fi
        } >"$l1.tool" 2>&1
        check "db-backup-tool [$accel]" "$l1.tool" 0 "backup: region [0-9]+ MiB, two slots of [0-9]+ KiB" \
            "backup slot 0: seq 1 \(newest\), taken at unix [0-9]+, [0-9]+ KiB, schema v[0-9]+, intact" \
            "backup slot 1: empty or invalid" "tool: verify exit 0" "tool: extract exit 0" \
            "$(command -v sqlite3 >/dev/null && echo 'tool: snapshot has ok 100 selftest rows' || echo 'tool: extract exit 0')"
        cp "$disk" "$base"

        status=0
        set_esp "$disk" "$cor"
        boot "$l2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "db-corrupt-restored [$accel]" "$l2" "$status" \
            "db-corrupt: the database file's first two pages are now garbage" "$restored" \
            "db-corrupt: after boot the database holds 100 selftest rows, consistent" \
            "db: sqlite .* quick_check ok" "^URMQTT READY$" "NOT:refusing to serve" "NOT:INCONSISTENT" "$NO_FAULT"

        status=0
        set_esp "$disk" "$plain"
        boot "$l3" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "db-restored-then-plain-boot [$accel]" "$l3" "$status" "storage: data disk opened" \
            "backup: every 60 min into the backup region; newest snapshot: seq 1" "db: sqlite .* quick_check ok" \
            "^URMQTT READY$" "NOT:RESTORED" "NOT:refusing to serve" "$NO_FAULT"
        "$ud" verify "$disk" >"$l3.tool" 2>&1 && echo "tool: verify exit 0" >>"$l3.tool"
        check "db-restored-verify [$accel]" "$l3.tool" 0 "verify: ok" "tool: verify exit 0"

        # The calibration run: a second backup with no fault, to learn how
        # many device writes it takes.
        local lb="$OUT/db-backup-$accel-b0.log" bdisk="$OUT/db-backup-b-$accel.img"
        cp "$base" "$bdisk"
        status=0
        boot "$lb" --disk "$bdisk" --accel "$accel" --headless --no-net || status=$?
        check "db-backup-second [$accel]" "$lb" "$status" "db-backup: 100 selftest rows in snapshot seq 2 \(slot 1," "^URMQTT READY$" "$NO_FAULT"
        local b0 b1 n spec
        b0=$(clean "$lb" | sed -n 's/.*db-backup: device writes before the backup \([0-9]*\), after \([0-9]*\)/\1/p' | tail -1)
        b1=$(clean "$lb" | sed -n 's/.*db-backup: device writes before the backup \([0-9]*\), after \([0-9]*\)/\2/p' | tail -1)
        if [[ -z $b0 || -z $b1 ]]; then
            echo "  ✗ db-backup: the write counts were not logged [$accel]"
            FAILED=$((FAILED + 1))
            continue
        fi
        # The kernel's fault counter also sees the boot self-test's write.
        for n in $((b0 + 1 + (b1 - b0) / 3)) $((b1)); do
            spec="stop-after-write=$n"
            local fimg="$OUT/db-backup-fault-$n.raw" fdisk="$OUT/db-backup-f-$accel.img"
            local lf="$OUT/db-backup-$accel-fault-$n.log" lr="$OUT/db-backup-$accel-recover-$n.log"
            mkimg "$fimg" "smoke test=db-backup test=disk-fault:$spec"
            cp "$base" "$fdisk"
            set_esp "$fdisk" "$fimg"
            status=0
            boot "$lf" --disk "$fdisk" --accel "$accel" --headless --no-net || status=$?
            check "db-backup-cut $spec [$accel]" "$lf" "$status" "db-backup: backup failed" "NOT:EXCEPTION|PANIC"
            {
                "$ud" info "$fdisk"
                "$ud" verify "$fdisk" && echo "tool: verify exit 0"
            } >"$lf.tool" 2>&1
            check "db-backup-cut-disk $spec [$accel]" "$lf.tool" 0 \
                "backup slot 0: seq 1( \(newest\))?, taken at unix [0-9]+, [0-9]+ KiB, schema v[0-9]+, intact" \
                "tool: verify exit 0" "NOT:PAYLOAD CRC MISMATCH"
            set_esp "$fdisk" "$cor"
            status=0
            boot "$lr" --disk "$fdisk" --accel "$accel" --headless --no-net || status=$?
            check "db-backup-cut-restores $spec [$accel]" "$lr" "$status" "$restored" \
                "db-corrupt: after boot the database holds 100 selftest rows, consistent" "^URMQTT READY$" "$NO_FAULT"
        done
    done
}

# S5 (ADR-160): a disk formatted before S5 (layout v2.0: here made by the
# host tool's migration of a populated layout-v1 image) is upgraded by the
# kernel's boot with one superblock write; the broker state is all there.
# `urmqtt-disk backup` then takes a snapshot offline, and a boot that finds
# the database damaged restores it.
backup_upgrade() {
    build_disk_tool || {
        echo "  ✗ backup-upgrade needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL img="$OUT/backup-upgrade.raw" cor="$OUT/backup-upgrade-corrupt.raw"
    mkimg "$img" "smoke"
    mkimg "$cor" "smoke test=db-corrupt"
    local state='db: restored 2 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), [0-9]+ revoked serial\(s\), 40 known device\(s\)'
    local telemetry='telemetry: log recovered in [0-9]+ ms: 600 record\(s\)'
    for accel in $ACCELS; do
        local disk="$OUT/backup-upgrade-$accel.img" rb="$OUT/backup-upgrade-$accel.rollback" tl="$OUT/backup-upgrade-$accel.tool"
        local l1="$OUT/backup-upgrade-$accel-1.log" l2="$OUT/backup-upgrade-$accel-2.log" l3="$OUT/backup-upgrade-$accel-3.log" status=0
        fresh_disk "$img" "$disk"
        rm -f "$rb"
        {
            "$ud" fixture-v1 "$disk" --populate --write &&
                "$ud" migrate "$disk" --write --rollback-file "$rb" >/dev/null && "$ud" info "$disk"
        } >"$tl" 2>&1 || { echo "  ✗ backup-upgrade: could not build the v2.0 disk"; cat "$tl"; FAILED=$((FAILED + 1)); continue; }
        check "backup-upgrade-v2.0-disk [$accel]" "$tl" 0 "data: layout v2 generation 2" \
            "backup: none \(layout v2.0; the kernel adds the region at its next boot"
        boot "$l1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "backup-upgrade-boot [$accel]" "$l1" "$status" \
            "storage: backup region added \(layout v2.1\): [0-9]+ MiB, two slots of [0-9]+ KiB" \
            "8 telemetry partition\(s\), aligned to 1024 KiB, generation 3" "$state" "$telemetry" \
            "^URMQTT READY$" "NOT:running WITHOUT in-disk backups" "$NO_FAULT"
        {
            "$ud" info "$disk"
            "$ud" verify "$disk" && echo "tool: verify exit 0"
            "$ud" backup "$disk" && echo "tool: dry run exit 0"
            "$ud" backup "$disk" --write && echo "tool: backup exit 0"
            "$ud" verify "$disk" && echo "tool: verify after exit 0"
        } >"$tl.2" 2>&1
        check "backup-upgrade-tool [$accel]" "$tl.2" 0 "data: layout v2 generation 3" \
            "backup: region [0-9]+ MiB, two slots of [0-9]+ KiB" "backup slot 0: empty or invalid" \
            "tool: verify exit 0" "dry run: nothing was changed; add --write" "tool: dry run exit 0" \
            "backup: snapshot seq 1 in slot 0: [0-9]+ KiB, schema v[0-9]+, CRC [0-9a-f]{8}" "tool: backup exit 0" \
            "tool: verify after exit 0" "backup slot 0: seq 1 \(newest\)"
        status=0
        set_esp "$disk" "$cor"
        boot "$l2" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "backup-upgrade-restore [$accel]" "$l2" "$status" \
            "storage: DATABASE RESTORED FROM BACKUP: snapshot seq 1 from slot 0" "$state" "$telemetry" \
            "^URMQTT READY$" "NOT:refusing to serve" "$NO_FAULT"
    done
}

# S5 (ADR-162): the periodic backup in a serving kernel. 10 s after boot,
# with no snapshot yet, the DB core takes one in bounded steps; the host tool
# then finds it intact on the disk of the killed VM.
backup_scheduled() {
    build_disk_tool || {
        echo "  ✗ backup-scheduled needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL img="$OUT/backup-scheduled.raw"
    mkimg "$img" "smoke serve"
    for accel in $ACCELS; do
        local disk="$OUT/backup-scheduled-$accel.img" log="$OUT/backup-scheduled-$accel.log" status=0
        fresh_disk "$img" "$disk"
        start_vm "$log" --disk "$disk" --accel "$accel" --fwd none
        wait_log "$log" "backup: snapshot seq 1 written to slot 0" || status=$?
        kill_vm
        check "backup-scheduled [$accel]" "$log" "$status" "backup: every 60 min into the backup region; no snapshot yet" \
            "backup: snapshot seq 1 written to slot 0: [0-9]+ page\(s\), [0-9]+ KiB, schema v[0-9]+, [0-9]+ step\(s\) over [0-9]+ ms, longest step [0-9]+ us" \
            "NOT:backup: FAILED" "$NO_FAULT"
        "$ud" verify "$disk" >"$log.tool" 2>&1 && echo "tool: verify exit 0" >>"$log.tool"
        "$ud" info "$disk" >>"$log.tool" 2>&1
        check "backup-scheduled-disk [$accel]" "$log.tool" 0 "verify: ok" "tool: verify exit 0" \
            "backup slot 0: seq 1 \(newest\), taken at unix [0-9]+, [0-9]+ KiB, schema v[0-9]+, intact"
    done
}

# S5 (ADR-164): what a backup costs the DB core, measured in the guest. A
# database of about 24 MiB, a writer committing every millisecond, first
# alone and then while a backup runs in 16-page steps between the commits;
# the longest step against the longest single call of the same copy done in
# one go (the stall VACUUM INTO would cause). The numbers go to the log; the
# check is that bounded steps keep the longest stall at a fraction of it.
backup_bench() {
    local img="$OUT/backup-bench.raw"
    mkimg "$img" "smoke test=db-backup-bench"
    for accel in $ACCELS; do
        local disk="$OUT/backup-bench-$accel.img" log="$OUT/backup-bench-$accel.log" status=0
        fresh_disk "$img" "$disk" 1g
        boot "$log" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "backup-bench [$accel]" "$log" "$status" \
            "backup-bench: [0-9]+ pages \([0-9]+ MiB\), snapshot seq 1 slot 0; commits alone: [0-9]+ in 1 s, mean [0-9]+ us, max [0-9]+ us; commits during the backup: [0-9]+ in [0-9]+ ms, mean [0-9]+ us, max [0-9]+ us; backup steps of 16 pages: [0-9]+, mean [0-9]+ us, longest [0-9]+ us; the whole copy as one call: longest call [0-9]+ us of [0-9]+ us in all" \
            "^URMQTT READY$" "NOT:backup-bench: incomplete" "NOT:backup-bench: step failed" "$NO_FAULT"
        local line step one
        line=$(clean "$log" | grep 'backup-bench: [0-9]* pages' | tail -1)
        step=$(sed -n 's/.*longest \([0-9]*\) us; the whole.*/\1/p' <<<"$line")
        one=$(sed -n 's/.*longest call \([0-9]*\) us of.*/\1/p' <<<"$line")
        echo "  backup-bench [$accel]: ${line#*backup-bench: }"
        if [[ -n $step && -n $one ]] && (( step * 4 < one )); then
            echo "  ✓ bounded steps: the longest step ${step} us is under a quarter of the single-call copy (${one} us) [$accel]"
            PASSED=$((PASSED + 1))
        else
            echo "  ✗ the longest bounded step (${step:-?} us) is not well under the single-call copy (${one:-?} us) [$accel]"
            FAILED=$((FAILED + 1))
        fi
    done
}

# flip_bit <file> <byte offset> <mask>: inverts bits of one byte of a file.
flip_bit() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import sys
path, off, mask = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with open(path, "r+b") as f:
    f.seek(off)
    b = f.read(1)
    f.seek(off)
    f.write(bytes([b[0] ^ mask]))
PY
}

# S6 (ADR-164, ADR-165): the scrubber finds rot. A ring written by
# `test=log-fill` (about 2.5 segments in each of 8 partitions) gets two bits
# flipped on the host, as a failing medium would do it: one inside a record of
# partition 0's first segment (the records after it are fine), one in the
# header of partition 1's second segment. A kernel with `test=scrub` reports
# both, with where they are; the host tool finds the same on the same bytes;
# before the flips the tool finds nothing. The recovery line of the scrub
# boot shows the bounded boot (G8): the newest segment of each partition is
# read, the others are known by their headers.
scrub_flip() {
    build_disk_tool || {
        echo "  ✗ scrub-flip needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL fill="$OUT/scrub-fill.raw" run="$OUT/scrub-run.raw"
    mkimg "$fill" "smoke test=log-fill"
    mkimg "$run" "smoke serve test=scrub"
    for accel in $ACCELS; do
        local disk="$OUT/scrub-flip-$accel.img" l1="$OUT/scrub-flip-$accel-1.log" l2="$OUT/scrub-flip-$accel-2.log"
        local tl="$OUT/scrub-flip-$accel.tool" status=0
        fresh_disk "$fill" "$disk"
        boot "$l1" --disk "$disk" --accel "$accel" --headless --no-net || status=$?
        check "scrub-fill [$accel]" "$l1" "$status" \
            "log-fill: [0-9]+ record\(s\) dated now durable in 8 partition\(s\)" \
            "scrub: every 24 h, at most 8 MB/s; the first pass 600 s after boot" "^URMQTT READY$" "NOT:scrub: pass" "$NO_FAULT"
        # Where the ring is, from the tool.
        local info first tel parts segs kib base segb
        info=$("$ud" info "$disk" 2>&1)
        first=$(sed -n 's/.*urMQTT data "urMQTT data" LBA \([0-9]*\)\.\..*/\1/p' <<<"$info" | head -1)
        tel=$(sed -n 's/.*region Telemetry: LBA \([0-9]*\)\.\..*/\1/p' <<<"$info" | head -1)
        read -r parts segs kib < <(sed -n 's/.*telemetry ring: \([0-9]*\) partition(s) of \([0-9]*\) segment(s) of \([0-9]*\) KiB.*/\1 \2 \3/p' <<<"$info" | head -1)
        if [[ -z $first || -z $tel || -z $kib ]]; then
            echo "  ✗ scrub-flip: could not read the ring geometry from the tool [$accel]"
            echo "$info" | sed 's/^/    | /'
            FAILED=$((FAILED + 1))
            continue
        fi
        base=$(((first + tel) * 512 + 4096))
        segb=$((kib * 1024))
        {
            "$ud" scrub "$disk" && echo "tool: clean disk exit 0"
        } >"$tl" 2>&1
        check "scrub-tool-clean [$accel]" "$tl" 0 "scrub: ok" "tool: clean disk exit 0" "telemetry [0-9]+ segment\(s\), [0-9]+ record\(s\), 0 damaged, 0 bad tail\(s\), 0 bad header\(s\)"
        # Partition 0, segment 0: a bit of record 0's payload. Partition 1,
        # segment 1: a bit of the header's sequence number.
        flip_bit "$disk" $((base + 0 * segb * segs + 512 + 300)) 8
        flip_bit "$disk" $((base + (1 * segs + 1) * segb + 17)) 4
        status=0
        set_esp "$disk" "$run"
        start_vm "$l2" --disk "$disk" --accel "$accel" --fwd none
        wait_log "$l2" "scrub: pass 1 done" || status=$?
        sleep 0.3
        kill_vm
        check "scrub-finds-the-flips [$accel]" "$l2" "$status" \
            "telemetry: log recovered in [0-9]+ ms: [0-9]+ record\(s\) in the 8 newest segment\(s\) read of 23, 0 torn tail\(s\) truncated" \
            "scrub: pass 1 started \(budget 8 MB/s\)" \
            "scrub: telemetry partition 0 segment 0 \(seq 1\): DAMAGED record at byte 512, valid records resume at byte [0-9]+" \
            "scrub: telemetry partition 1 segment 1: segment header DAMAGED" \
            "scrub: pass 1 done in [0-9]+ ms \([0-9]+ step\(s\)\): [0-9]+ KiB read, [0-9]+ KiB/s against a budget of 8192 KiB/s" \
            "scrub: pass 1: database [0-9]+ table\(s\) checked, 0 problem\(s\); backup [01] slot\(s\) intact, 0 bad" \
            "scrub: pass 1: telemetry 23 segment\(s\), [0-9]+ record\(s\) checked, 1 damaged, 0 bad tail\(s\), 1 bad header\(s\)" \
            "scrub: pass 1 FOUND 2 problem\(s\)" "$NO_FAULT"
        status=0
        "$ud" scrub "$disk" >"$tl.2" 2>&1 || status=$?
        [[ $status -ne 0 ]] && echo "tool: found damage, exit $status" >>"$tl.2"
        check "scrub-tool-finds-the-flips [$accel]" "$tl.2" 0 "TelemetryDamaged \{ partition: 0, index: 0" \
            "TelemetryBadHeader \{ partition: 1, index: 1 \}" "tool: found damage, exit 1" "NOT:^scrub: ok"
    done
}

# S6 (ADR-164): the scrub's I/O against its budget under load. The telemetry
# writers of `log-crash` keep every data core appending while the first pass
# runs (6 s in). The pass reads the ring the writers have made so far; the
# bytes it reads over its duration, as the kernel measures them, stay within
# the budget of 8192 KiB/s (the busy-mode floor of one 256 KiB step per
# 100 ms is lower still).
scrub_load() {
    local img="$OUT/scrub-load.raw"
    mkimg "$img" "smoke serve test=scrub-load"
    for accel in $ACCELS; do
        local disk="$OUT/scrub-load-$accel.img" log="$OUT/scrub-load-$accel.log" status=0
        fresh_disk "$img" "$disk"
        start_vm "$log" --disk "$disk" --accel "$accel" --fwd none
        wait_log "$log" "scrub: pass 1 done" || status=$?
        local last
        last=$(clean "$log" | grep -E 'log-crash: core [0-9]+ writing' | wc -l | tr -d ' ')
        kill_vm
        check "scrub-under-load [$accel]" "$log" "$status" "log-crash: core 0 writing" \
            "scrub: pass 1 started \(budget 8 MB/s\)" \
            "scrub: pass 1 done in [0-9]+ ms \([0-9]+ step\(s\)\): [0-9]+ KiB read, [0-9]+ KiB/s against a budget of 8192 KiB/s" \
            "NOT:FOUND" "$NO_FAULT"
        local line ms kib rate
        line=$(clean "$log" | grep 'scrub: pass 1 done' | tail -1)
        ms=$(sed -n 's/.*done in \([0-9]*\) ms.*/\1/p' <<<"$line")
        kib=$(sed -n 's/.*): \([0-9]*\) KiB read.*/\1/p' <<<"$line")
        rate=$(sed -n 's/.* \([0-9]*\) KiB\/s against.*/\1/p' <<<"$line")
        echo "  scrub-load [$accel]: ${kib:-?} KiB in ${ms:-?} ms = ${rate:-?} KiB/s with $last writer core(s) running; ${line#*scrub: }" | cut -c1-260
        # The budget plus the 256 KiB burst, over the pass: rate <= 8192 + 256 * 1000 / ms.
        if [[ -n $ms && -n $kib && -n $rate ]] && (( kib * 1000 <= 8192 * ms + 256 * 1000 )) && (( kib >= 1024 )); then
            echo "  ✓ scrub I/O within its budget under load: $kib KiB in $ms ms ($rate KiB/s against 8192) [$accel]"
            PASSED=$((PASSED + 1))
        else
            echo "  ✗ scrub I/O outside its budget (or nothing read): ${kib:-?} KiB in ${ms:-?} ms [$accel]"
            FAILED=$((FAILED + 1))
        fi
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
        local ifp
        ifp=$(clean "$log1" | grep -o 'config: fingerprint [0-9a-f]*' | head -1 | cut -d' ' -f3)
        check "install-vm [$accel]" "$log1" "$status" "boot: from optical media" "config: fingerprint [0-9a-f]{64} " \
            "install: disk virtio-blk 00:0[0-9a-f]\.0: 64 MiB$" "install: ALL DATA ON virtio-blk" \
            "install: writing to virtio-blk 00:0[0-9a-f]\.0 in 1 s; power off now to cancel" \
            "install: done: 10 MiB written and verified" "NOT:URMQTT READY" "NOT:ISO MODIFIED" "$NO_FAULT"
        status=0
        boot "$log2" --disk "$t" --accel "$accel" --headless --no-net || status=$?
        check "install-vm-boots [$accel]" "$log2" "$status" "boot: from a GPT disk" \
            "config: fingerprint ${ifp:-missing} \([0-9]+ bytes, unsigned\), env=dev" "NOT:slot is empty" \
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

# C1b (ADR-216): the kernel is the same for every configuration; the
# configuration is the slot the bootloader loads. This packs a non-default
# configuration with the host tool (TOML plus the dev certificates), boots it
# and checks the fingerprint line and settings that differ from the defaults
# and from the dev image; then the signed form, a tampered slot (fail closed),
# and the empty template (boots, refuses to serve, says why).
# make_cfg_blobs: $OUT/cfgpack/{plain,signed}.blob, a configuration that
# differs from the dev image's (watchdog budget 37 ms, heap 16 MiB, log level
# info); sets CFG_FP (its fingerprint) and CFG_SIGNER (the signer's id).
make_cfg_blobs() {
    local dir="$OUT/cfgpack" tool="$ROOT/target/debug/urmqtt-config"
    mkdir -p "$dir"
    (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool)
    # The dev files are read from deploy/dev (--root).
    sed -e 's/^handler_budget_ms = 10/handler_budget_ms = 37/' \
        -e 's/^kernel_heap_mb = 32 /kernel_heap_mb = 16 /' \
        -e 's/^log_level = "debug"/log_level = "info"/' \
        "$ROOT/deploy/dev/config.toml" >"$dir/config.toml"
    CFG_FP=$("$tool" pack "$dir/config.toml" --env dev --root "$ROOT/deploy/dev" --out "$dir/plain.blob" | grep -o 'fingerprint [0-9a-f]*' | cut -d' ' -f2)
    "$tool" pack "$dir/config.toml" --env dev --root "$ROOT/deploy/dev" --sign "$ROOT/deploy/dev/control.key" --out "$dir/signed.blob" >/dev/null
    CFG_SIGNER=$("$tool" show "$dir/signed.blob" | grep -o 'signer key [0-9a-f]*' | cut -d' ' -f3)
}

config_packed() {
    local dir="$OUT/cfgpack"
    make_cfg_blobs
    local fp=$CFG_FP signer=$CFG_SIGNER
    local name iso accel
    for name in plain signed; do
        iso="$OUT/cfg-$name.raw"
        MKIMG_EXTRA=(--config "$dir/$name.blob")
        mkimg "$iso" "smoke"
        MKIMG_EXTRA=()
        local want_sig="unsigned"
        [[ $name == signed ]] && want_sig="signed by key $signer"
        for accel in $ACCELS; do
            local log="$OUT/cfg-$name-$accel.log" data="$OUT/cfg-$name-$accel.img" status=0
            fresh_disk "$iso" "$data"
            boot "$log" --disk "$data" --accel "$accel" --headless || status=$?
            check "config-packed-$name [$accel]" "$log" "$status" \
                "config: fingerprint $fp \([0-9]+ bytes, $want_sig\), env=dev" \
                "watchdog: handshake budget [0-9]+ ms \(calibrated\), other handlers 37 ms" \
                "heap 16 MiB" "^URMQTT READY$" "$NO_FAULT"
        done
    done
    # A slot with one flipped payload byte: refused, never defaults.
    iso="$OUT/cfg-tampered.raw"
    MKIMG_EXTRA=(--config "$dir/plain.blob")
    mkimg "$iso" "smoke"
    MKIMG_EXTRA=()
    python3 -I - "$iso" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, "rb").read())
i = d.find(b"URMQTT-CFG-SLOT\0" + b"URMQCFG\0")  # the kernel holds the marker alone
assert i > 0
d[i + 16 + 20] ^= 0x01  # inside the payload
open(path, "wb").write(d)
PY
    for accel in $ACCELS; do
        local log="$OUT/cfg-tampered-$accel.log" data="$OUT/cfg-tampered-$accel.img" status=0
        fresh_disk "$iso" "$data"
        boot_until "$log" "resetting in 60 s" --disk "$data" --accel "$accel" --fwd none || status=$?
        check "config-tampered-refused [$accel]" "$log" "$status" \
            "(fatal: configuration refused: blob: fingerprint mismatch|Blake2b hash for URI .boot\(\):/boot/urmqtt.cfg. does not match)" "NOT:URMQTT READY" "NOT:config: fingerprint"
    done
    # The empty template: boots, but will not serve.
    iso="$OUT/cfg-empty.raw"
    MKIMG_EXTRA=(--empty-config)
    mkimg "$iso" "smoke"
    MKIMG_EXTRA=()
    for accel in $ACCELS; do
        local log="$OUT/cfg-empty-$accel.log" data="$OUT/cfg-empty-$accel.img" status=0
        fresh_disk "$iso" "$data"
        boot_until "$log" "resetting in 60 s" --disk "$data" --accel "$accel" --fwd none || status=$?
        check "config-empty-refuses-to-serve [$accel]" "$log" "$status" \
            "config: fingerprint [0-9a-f]{64} \(49 bytes, unsigned\), env=prod" \
            "config: the configuration slot is empty" \
            "fatal: refusing to serve: no server certificate and key \(tls.cert, tls.key\)" "NOT:URMQTT READY"
    done
}

# C1b (ADR-216): the RELEASE kernel (any ENV but dev, built once for everyone)
# refuses what only a dev kernel may run, and serves with a production
# configuration. Needs a release kernel of this architecture:
#   SMOKE_RELEASE_KERNEL=<ELF built with URMQTT_ENV=release> scripts/smoke.sh ...
# (the Makefile builds one for the template ISO: `make template`).
release_kernel() {
    local rk=${SMOKE_RELEASE_KERNEL:-}
    if [[ -z $rk || ! -f $rk ]]; then
        echo "  - release-kernel skipped (SMOKE_RELEASE_KERNEL=<a release kernel ELF of this architecture>)"
        return
    fi
    make_cfg_blobs
    local dir="$OUT/cfgpack" tool="$ROOT/target/debug/urmqtt-config" dev_kernel=$KERNEL iso accel
    KERNEL=$rk
    # 1. A dev configuration (env = dev: plaintext port, durability shortcuts).
    iso="$OUT/rel-dev.raw"
    MKIMG_EXTRA=(--config "$dir/plain.blob")
    mkimg "$iso" "smoke"
    MKIMG_EXTRA=()
    for accel in $ACCELS; do
        local log="$OUT/rel-dev-$accel.log" data="$OUT/rel-dev-$accel.img" status=0
        fresh_disk "$iso" "$data"
        boot_until "$log" "resetting in 60 s" --disk "$data" --accel "$accel" --fwd none || status=$?
        check "release-kernel-refuses-dev-config [$accel]" "$log" "$status" \
            "fatal: configuration refused: env: the dev environment is refused by a release kernel" \
            "NOT:URMQTT READY" "NOT:PLAINTEXT" "NOT:config: development kernel"
    done
    # 2. A production configuration that nevertheless asks for the plaintext
    # port (made by hand: the packer refuses to build it).
    iso="$OUT/rel-plain.raw"
    "$tool" pack "$ROOT/deploy/prod/config.toml" --root "$ROOT/deploy/dev" --out "$dir/prod.blob" >/dev/null
    MKIMG_EXTRA=(--config "$dir/prod.blob")
    mkimg "$iso" "smoke"
    MKIMG_EXTRA=()
    python3 -I - "$iso" <<'PY'
import hashlib, struct, sys
path = sys.argv[1]
d = bytearray(open(path, "rb").read())
i = d.find(b"URMQTT-CFG-SLOT\0" + b"URMQCFG\0")
assert i > 0
# env prod (the default), the plaintext port 1883 (tag 15, u16), a certificate-less blob
payload = struct.pack("<HI", 15, 2) + struct.pack("<H", 1883)
head = b"URMQCFG\0" + struct.pack("<HHI", 1, 0, len(payload)) + payload
blob = head + hashlib.sha256(b"urmqtt-cfg-v1" + head).digest() + b"\0"
d[i + 16 : i + 262144] = blob + bytes(262144 - 16 - len(blob))
open(path, "wb").write(d)
PY
    for accel in $ACCELS; do
        local log="$OUT/rel-plain-$accel.log" data="$OUT/rel-plain-$accel.img" status=0
        fresh_disk "$iso" "$data"
        boot_until "$log" "resetting in 60 s" --disk "$data" --accel "$accel" --fwd none || status=$?
        check "release-kernel-refuses-plaintext-port [$accel]" "$log" "$status" \
            "fatal: configuration refused: network.mqtt_plain_port: (development option|plaintext)" \
            "NOT:URMQTT READY" "NOT:PLAINTEXT"
    done
    # 3. The production configuration itself: serves TLS, no plaintext. (Its kernel
    # heap is 1 GiB: the VM gets 2 GiB.)
    iso="$OUT/rel-prod.raw"
    MKIMG_EXTRA=(--config "$dir/prod.blob")
    mkimg "$iso" "serve"
    MKIMG_EXTRA=()
    for accel in $ACCELS; do
        local log="$OUT/rel-prod-$accel.log" data="$OUT/rel-prod-$accel.img" status=0
        fresh_disk "$iso" "$data"
        boot_until "$log" "^URMQTT READY$" --disk "$data" --accel "$accel" --fwd none --mem 2G || status=$?
        check "release-kernel-serves-production-config [$accel]" "$log" "$status" \
            "config: fingerprint [0-9a-f]{64} \([0-9]+ bytes, unsigned\), env=prod" \
            "mqtt: TLS 1.3 listener on port 8883" "^URMQTT READY$" \
            "NOT:PLAINTEXT" "NOT:config: development kernel" "NOT:net: tcp echo service" "$NO_FAULT"
    done
    KERNEL=$dev_kernel
}

# P1 (ADR-229, ADR-230): plaintext MQTT for trusted networks. The dev image's
# configuration plus a [plaintext] section, packed with the host tool (the same
# blob the builder page makes), one image per mode. QEMU's user networking
# makes every host client appear as 10.0.2.2, so "the allowed source" is a
# configuration that lists 10.0.2.0/24 and "the refused source" one that does
# not. scripts/plain-scenarios.py plays the clients (raw packets, and the real
# mosquitto tools); the serial log is checked for what the kernel says.
#   password   default clients, ACL by login, the refusals, limits, retain,
#              client ids, the operator's counters; then the TLS scenarios
#              (mqtt-scenarios.py) on the same VM: TLS works alongside
#   lockout    failed logins lock the address out, then it recovers
#   refused    a source outside allow_from gets no answer
#   anonymous / ip / limits / registry   the other modes and limits
plaintext() {
    [[ -z ${SMOKE_SCENARIOS:-} || plaintext =~ $SMOKE_SCENARIOS ]] || return 0
    command -v mosquitto_pub >/dev/null || { echo "  ✗ plaintext scenarios need the mosquitto clients"; FAILED=$((FAILED + 1)); return 0; }
    local dir="$OUT/plain" tool="$ROOT/target/debug/urmqtt-config" ppt=${SMOKE_PLAIN_PORT:-$((PORT + 1))}
    mkdir -p "$dir"
    (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool) || { echo "  ✗ urmqtt-config build failed"; FAILED=$((FAILED + 1)); return 0; }
    local h1 h2 users
    h1=$(printf '%s\n' alpha-secret | "$tool" hash-password --iterations 3000)
    h2=$(printf '%s\n' beta-secret | "$tool" hash-password --iterations 3000)
    users="users = [{ id = \"sensor-1\", password_hash = \"$h1\" }, { id = \"sensor-2\", password_hash = \"$h2\" }]"
    # The dev configuration without its development plaintext port (the new
    # section is the way in), and a copy with the allowlist registry.
    sed -e 's/^mqtt_plain_port = 1883 .*/mqtt_plain_port = 0/' "$ROOT/deploy/dev/config.toml" >"$dir/base.toml"
    sed -e 's/^mode = "open" .*/mode = "allowlist"/' "$dir/base.toml" >"$dir/base-registry.toml"
    local allow='allow_from = ["10.0.2.0/24"]'
    mk() { # mk <name> <base> <[plaintext] lines...>
        local name=$1 base=$2
        shift 2
        { cat "$dir/$base.toml"; printf '\n[plaintext]\nenabled = true\n'; printf '%s\n' "$@"; } >"$dir/$name.toml"
        "$tool" pack "$dir/$name.toml" --env dev --root "$ROOT/deploy/dev" --out "$dir/$name.blob" >/dev/null
    }
    mk password base "$allow" "$users" 'max_failed_auths_per_ip = 1000' 'max_packet_size = 256'
    mk lockout base "$allow" "$users" 'max_failed_auths_per_ip = 3' 'lockout_s = 10'
    mk refused base 'allow_from = ["192.0.2.0/24"]' "$users"
    mk anonymous base "$allow" 'auth = "anonymous"' 'acl_publish = ["home/#"]' 'acl_subscribe = ["home/#"]'
    mk ip base "$allow" 'auth = "ip"' 'ip_identities = [{ from = "10.0.2.2/32", id = "gateway" }]'
    mk limits base "$allow" "$users" 'max_connections_per_ip = 3'
    mk registry base-registry "$allow" "$users"
    # ADR-233: the TLS listener off (network.mqtt_tls_port = 0), plaintext only.
    sed -e 's/^mqtt_tls_port = .*/mqtt_tls_port = 0/' "$dir/base.toml" >"$dir/base-notls.toml"
    mk plainonly base-notls "$allow" 'auth = "anonymous"' 'acl_publish = ["home/#"]' 'acl_subscribe = ["home/#"]'
    local common=("mqtt: PLAINTEXT listener on port 1883 \(NOT ENCRYPTED\)" "config: plaintext MQTT is ON \(port 1883" "^URMQTT READY$" "NOT:client: .* FAILED" "$NO_FAULT")
    local name
    for name in password lockout refused anonymous ip limits registry plainonly; do
        local extra=() iso="$OUT/plain-$name.raw"
        case $name in
            password) extra=("plaintext: one password check costs about [0-9]+ us \(3000 iterations" "plaintext: login refused for 10\.0\.2\.2 \(wrong password\), 1 so far"
                "control: 1 publish\(es\) to \\\$urmqtt/ by identities without control rights dropped"
                "client: default-client-publishes ok" "client: default-client-receives-a-command ok" "client: acl-publish-only-own-topics ok"
                "client: acl-subscribe-only-own-commands ok" "client: no-sys-subscribe ok" "client: stored-session-refused ok" "client: client-id-with-a-slash-is-fine ok" "client: empty-client-id-is-named-by-the-broker ok" "client: empty-client-id-with-a-stored-session-refused ok"
                "client: retained-publish-not-retained ok" "client: packet-limit ok" "client: one-login-many-client-ids ok"
                "client: publish-rate-limited ok" "client: operator-reads-the-plaintext-counters ok"
                "client: pubsub-wildcard ok" "client: retained ok" "client: lwt-forced-disconnect ok" "client: qos1-after-reconnect ok"
                "client: tls-revoked-rejected ok") ;;
            lockout) extra=("plaintext: 10\.0\.2\.2 is locked out for 10 s after 3 failed login\(s\)" "plaintext: 1 SYN\(s\) from locked-out addresses dropped without an answer"
                "client: locked-out-address-gets-no-answer ok" "client: login-works-again-after-the-lockout ok" "client: tls-is-not-locked-out ok") ;;
            refused) extra=("plaintext: 1 SYN\(s\) from addresses outside plaintext\.allow_from dropped without an answer"
                "client: refused-source-gets-no-answer ok" "client: tls-works-beside-a-refused-plaintext-source ok" "NOT:login refused") ;;
            anonymous) extra=("mqtt: plaintext.auth = \"anonymous\"" "client: anonymous-default-clients ok" "client: anonymous-acl ok") ;;
            ip) extra=("mqtt: plaintext.auth = \"ip\"" "client: ip-mode-identity-is-the-networks ok") ;;
            limits) extra=("client: per-address-connection-limit ok" "client: a-closed-connection-makes-room ok") ;;
            plainonly) extra=("mqtt: TLS listener off \(plaintext only" "NOT:TLS 1\.3 listener on port" "client: anonymous-default-clients ok" "client: no-tls-listener ok") ;;
            registry) extra=("registry: plaintext login sensor-1 is not on the allowlist, refused" "client: not-on-the-allowlist-refused ok") ;;
        esac
        MKIMG_EXTRA=(--config "$dir/$name.blob")
        mkimg "$iso" "serve log=info"
        MKIMG_EXTRA=()
        for accel in $ACCELS; do
            local log="$OUT/plain-$name-$accel.log" data="$OUT/plain-$name-$accel.img" status=0
            fresh_disk "$iso" "$data"
            start_vm "$log" --disk "$data" --accel "$accel" --fwd "$PORT:8883,$ppt:1883"
            if wait_log "$log" "^URMQTT READY$"; then
                python3 -I "$ROOT/scripts/plain-scenarios.py" "$name" "$ppt" "$PORT" "$ROOT/deploy/dev" >"$log.client" 2>&1 || status=$?
                if [[ $name == password ]]; then
                    # TLS beside it: the standard device and backend scenarios on the same VM.
                    python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" "$PORT" >>"$log.client" 2>&1 || status=$?
                fi
                sleep 1
            else
                status=124
            fi
            kill_vm
            cat "$log.client" >>"$log" 2>/dev/null || true
            check "plaintext-$name [$accel]" "$log" "$status" "${common[@]}" "${extra[@]}"
        done
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
    start_vm "$log" --disk "$data" --accel tcg --gic 2 --fwd "$PORT:8883"
    if wait_log "$log" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" $PORT >"$log.client" 2>&1 || status=$?
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
# C1b: the configuration the dev image boots with is identified at boot.
CONFIG_OK=("config: fingerprint [0-9a-f]{64} \([0-9]+ bytes, unsigned\), env=dev")

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

# u_args <kind> <accel> <iso|disk> <file>: the run-qemu.sh arguments of a machine (as u_run).
u_args() {
    case $1 in
        aa64) echo "--$3 $4 --accel $2 --smp 4" ;;
        x86-uefi) echo "--arch x86_64 --$3 $4 --accel tcg --smp 2" ;;
        x86-bios) echo "--arch x86_64 --machine pc --firmware bios --$3 $4 --accel tcg --smp 2" ;;
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

# S2 and X8: a migrated layout-v1 disk is architecture independent. The host
# tool builds a v1 disk with real broker state and migrates it; then the
# universal image's disk is booted by x86_64 UEFI (the first boot there grows
# it: the disk file was made larger), then aarch64, then x86_64 BIOS. Each one
# restores the same retained messages, session, devices and 600 telemetry
# records from the same bytes, and no one grows it again.
universal_migrated() {
    build_disk_tool || {
        echo "  ✗ universal-migrated needs urmqtt-disk"
        FAILED=$((FAILED + 1))
        return
    }
    local ud=$DISK_TOOL iso="$OUT/universal.iso" row first=1
    mkuniversal "$iso" "smoke"
    local disk="$OUT/universal-migrated.img" rb="$OUT/universal-migrated.rollback" tl="$OUT/universal-migrated-tool.log"
    local restored='db: restored 2 retained message\(s\), 1 persistent session\(s\) with 1 queued message\(s\), [0-9]+ revoked serial\(s\), 40 known device\(s\)'
    local telemetry='telemetry: log recovered in [0-9]+ ms: 600 record\(s\)'
    fresh_disk "$iso.disk" "$disk"
    rm -f "$rb"
    {
        "$ud" fixture-v1 "$disk" --populate --write &&
            "$ud" migrate "$disk" --write --rollback-file "$rb" || echo "tool: FAILED"
    } >"$tl" 2>&1
    check "universal-migrated-tool" "$tl" 0 "migrate: done" "verify: telemetry identical \(600 record" "NOT:tool: FAILED"
    truncate -s 128m "$disk"
    local rows=("x86-uefi|x86-uefi|tcg" "aa64|aa64|hvf" "x86-bios|x86-bios|tcg")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel <<<"$row"
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        local log="$OUT/universal-migrated-$name.log" status=0
        u_run "$kind" "$accel" "$log" disk "$disk" || status=$?
        if [[ $first -eq 1 ]]; then
            check "universal-migrated: first boot on $name grows the disk" "$log" "$status" \
                "storage: grew the layout from [0-9]+ MiB to [0-9]+ MiB \(generation 4\)" "storage: data disk opened" \
                "$restored" "$telemetry" "^URMQTT READY$" "$NO_FAULT"
            first=0
        else
            check "universal-migrated: $name reads it" "$log" "$status" "storage: data disk opened \(1[0-9]{2} MiB" \
                "generation 4" "$restored" "$telemetry" "NOT:storage: grew" "^URMQTT READY$" "$NO_FAULT"
        fi
    done
}

# C1d (ADR-218): the template ISO (empty configuration) configured by
# `urmqtt-config pack --iso` is byte for byte the ISO mkiso builds directly with
# that configuration, and it boots on all three machines with that
# configuration (fingerprint and a non-default setting).
universal_config() {
    local tool="$ROOT/target/debug/urmqtt-config" tpl="$OUT/universal-template.iso" row
    make_cfg_blobs
    mkuniversal "$tpl" "smoke" --empty-config
    local direct="$OUT/universal-config-direct.iso" patched="$OUT/universal-config-patched.iso"
    mkuniversal "$direct" "smoke" --config "$OUT/cfgpack/signed.blob"
    local status=0 out="$OUT/universal-config-pack.log"
    "$tool" pack "$OUT/cfgpack/config.toml" --env dev --root "$ROOT/deploy/dev" \
        --sign "$ROOT/deploy/dev/control.key" --iso "$tpl" --out "$patched" >"$out" 2>&1 || status=$?
    if [[ $status -eq 0 ]] && cmp -s "$direct" "$patched"; then
        echo "  ✓ universal-config: pack --iso on the template == the ISO built with that configuration"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ universal-config: the patched template differs from the direct build (pack status $status)"
        sed 's/^/    | /' "$out" | tail -5
        FAILED=$((FAILED + 1))
    fi
    "$tool" verify "$patched" --dev >"$out" 2>&1 || status=$?
    check "universal-config-verify" "$out" "$status" "ok: fingerprint $CFG_FP, signed, complete" \
        "slot copies identical, [0-9]+ module hash reference\(s\) match"
    local aa64='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' x86='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
    local rows=("aa64-hvf|aa64|hvf|$aa64" "x86-q35-uefi|x86-uefi|tcg|$x86" "x86-pc-bios|x86-bios|tcg|$x86")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel boot_line <<<"$row"
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        local log="$OUT/universal-config-$name.log"
        status=0
        u_run "$kind" "$accel" "$log" iso "$patched" || status=$?
        check "universal-config-boots-$name" "$log" "$status" "$boot_line" \
            "config: fingerprint $CFG_FP \([0-9]+ bytes, signed by key $CFG_SIGNER\), env=dev" \
            "watchdog: handshake budget [0-9]+ ms \(calibrated\), other handlers 37 ms" "^URMQTT READY$" "$NO_FAULT"
    done
}

# C1d: the template ISO as released (`make template`, release kernels, empty
# configuration), SMOKE_TEMPLATE_ISO=<file>. Unconfigured it boots, says so and
# does not serve; configured with a production configuration by `pack --iso` it
# serves TLS (no plaintext) on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS.
universal_template() {
    local tpl=${SMOKE_TEMPLATE_ISO:-}
    if [[ -z $tpl || ! -f $tpl ]]; then
        echo "  - universal-template skipped (SMOKE_TEMPLATE_ISO=<the template ISO>)"
        return
    fi
    local tool="$ROOT/target/debug/urmqtt-config" dir="$OUT/template" row
    mkdir -p "$dir"
    (cd "$ROOT" && cargo build -q --locked -p urmqtt-config-tool)
    local status=0 out="$dir/pack.log" sum
    sum=$(shasum -a 256 "$tpl" | cut -d' ' -f1)
    "$tool" verify "$tpl" >"$out" 2>&1 || status=$?
    check "universal-template-verify" "$out" "$status" "ok: fingerprint [0-9a-f]{64}, unsigned, no certificate" \
        "slot copies identical, [0-9]+ module hash reference\\(s\\) match"
    # The production template of the repository with the dev certificates.
    status=0
    "$tool" pack "$ROOT/deploy/prod/config.toml" --root "$ROOT/deploy/dev" --iso "$tpl" --out "$dir/prod.iso" >"$out" 2>&1 || status=$?
    check "universal-template-pack" "$out" "$status" "configured: 2 copies of the slot replaced" "ok: fingerprint [0-9a-f]{64}, unsigned, complete"
    local fp
    fp=$(grep -o 'fingerprint [0-9a-f]*' "$out" | tail -1 | cut -d' ' -f2)
    [[ $(shasum -a 256 "$tpl" | cut -d' ' -f1) == "$sum" ]] || { echo "  ✗ the template was modified"; FAILED=$((FAILED + 1)); }
    local aa64='^URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' x86='^URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$'
    local rows=("aa64-hvf|aa64|hvf|$aa64" "x86-q35-uefi|x86-uefi|tcg|$x86" "x86-pc-bios|x86-bios|tcg|$x86")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel boot_line <<<"$row"
        [[ $kind == aa64 && " $ACCELS " != *" $accel "* ]] && continue
        # Unconfigured: boots, refuses to serve.
        local log="$dir/empty-$name.log" qargs
        status=0
        qargs=$(u_args "$kind" "$accel" iso "$tpl")
        # shellcheck disable=SC2086 # the arguments contain no spaces
        boot_until "$log" "resetting in 60 s" $qargs --fwd none || status=$?
        check "universal-template-empty-$name" "$log" "$status" "$boot_line" "config: the configuration slot is empty" \
            "fatal: refusing to serve: no server certificate and key" "NOT:URMQTT READY"
        # Configured: serves. (The ISO's first entry is live mode, from RAM.)
        log="$dir/prod-$name.log"
        status=0
        qargs=$(u_args "$kind" "$accel" iso "$dir/prod.iso")
        # shellcheck disable=SC2086
        boot_until "$log" "^URMQTT READY$" $qargs --fwd none --mem 2G || status=$?
        check "universal-template-configured-serves-$name" "$log" "$status" "$boot_line" \
            "config: fingerprint $fp \\([0-9]+ bytes, unsigned\\), env=prod" "mqtt: TLS 1.3 listener on port 8883" \
            "^URMQTT READY$" "NOT:PLAINTEXT" "NOT:config: development kernel" "$NO_FAULT"
    done
}

# The installer of the universal ISO on each machine, then the installed
# disk booted by all three boot paths (aarch64 UEFI, x86 UEFI, x86 BIOS).
universal_install() {
    local iso="$OUT/universal-install.iso" row
    # A packed non-default configuration, signed: the installer copies the
    # slot it booted with into the installed disk (C1c, ADR-217).
    make_cfg_blobs
    mkuniversal "$iso" "smoke" --install-cmdline "install install-countdown=1" --install-default \
        --config "$OUT/cfgpack/signed.blob"
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
            "config: fingerprint $CFG_FP " "install: done: [0-9]+ MiB written and verified" "NOT:URMQTT READY" "$NO_FAULT"
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
                "config: fingerprint $CFG_FP \([0-9]+ bytes, signed by key $CFG_SIGNER\), env=dev" \
                "watchdog: handshake budget [0-9]+ ms \(calibrated\), other handlers 37 ms" \
                "storage: data disk formatted \(was blank\)" "^URMQTT READY$" "NOT:slot is empty" "$NO_FAULT"
        done
    done
}

# H8 (ADR-250, ADR-251): boot integrity. A modified kernel, configuration module or limine.conf
# in a built image is refused by the loader itself, on each of the three machines the universal
# image boots (aarch64 UEFI, x86_64 UEFI, x86_64 BIOS). The refusal is read from Limine's own
# message: the test images are built with URMQTT_LIMINE_SERIAL=1 (Limine's messages on the
# serial port; never set for a release image). Every refusal has a control that boots: the same
# image with the kernel of the OTHER architecture changed (that machine does not read it), and,
# for the configuration, the same edit in an image built with --no-enroll.
#
# integrity_refused <label> <kind> <accel> <iso|disk> <file> <wait-for> <patterns...>
integrity_refused() {
    local label=$1 kind=$2 accel=$3 how=$4 file=$5 pat=$6
    shift 6
    local log="$OUT/integrity-$label.log" status=0
    if [[ $pat == - ]]; then
        # The BIOS stage reads limine.conf before it knows to use the serial port, so a refused
        # configuration is on the screen only: the machine must simply not boot in the time the
        # control needs (SMOKE_REFUSE_WAIT, default 45 s), and the controls show it would.
        # shellcheck disable=SC2046
        TIMEOUT=${SMOKE_REFUSE_WAIT:-45} boot_until "$log" 'URMQTT BOOT' $(u_args "$kind" "$accel" "$how" "$file") --no-net || status=$?
        [[ $status -eq 124 ]] && status=0 || status=1
        check "integrity: $label refused (does not boot; message on screen only)" "$log" "$status" "NOT:URMQTT BOOT" "NOT:URMQTT READY" "$@"
        return 0
    fi
    # shellcheck disable=SC2046 # u_args prints a word list
    boot_until "$log" "$pat" $(u_args "$kind" "$accel" "$how" "$file") --no-net || status=$?
    check "integrity: $label refused" "$log" "$status" "$pat" "NOT:URMQTT BOOT" "NOT:URMQTT READY" \
        "NOT:bootloader=Limine" "$@"
}

# integrity_boots <label> <kind> <accel> <iso|disk> <file>: the control, it boots.
integrity_boots() {
    local label=$1 kind=$2 accel=$3 how=$4 file=$5
    local log="$OUT/integrity-$label.log" status=0
    # A raw image is booted from a copy on a larger disk (the data partition is created at the first boot).
    if [[ $how == disk ]]; then
        fresh_disk "$file" "$OUT/integrity-boot-$kind.img"
        file="$OUT/integrity-boot-$kind.img"
    fi
    u_run "$kind" "$accel" "$log" "$how" "$file" || status=$?
    check "integrity: $label boots" "$log" "$status" 'URMQTT BOOT [^ ]+ (arch=x86_64 )?cpu=[0-9]+ mem=[0-9]+$' \
        "bootloader=Limine" "^URMQTT READY$" "NOT:CHECKSUM MISMATCH" "NOT:does not match"
}

universal_integrity() {
    local base="$OUT/integrity-base.iso" noenr="$OUT/integrity-noenroll.iso" cfg="$OUT/integrity-urmqtt.cfg"
    local tamper="$ROOT/scripts/tamper.py"
    URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0 mkuniversal "$base" "smoke"
    URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0 mkuniversal "$noenr" "smoke" --no-enroll
    # The ISO's configuration module, as a file, to find its copies in the image.
    rm -f "$cfg"
    xorriso -osirrox on -indev "$base" -extract /boot/urmqtt.cfg "$cfg" >/dev/null 2>&1 || true
    if [[ ! -s "$cfg" ]]; then
        echo "  ✗ integrity: cannot extract /boot/urmqtt.cfg from the ISO"
        FAILED=$((FAILED + 1))
        return 0
    fi
    local t_a64="$OUT/integrity-tampered-aarch64.iso" t_x86="$OUT/integrity-tampered-x86.iso"
    local t_cfg="$OUT/integrity-tampered-module.iso" t_conf="$OUT/integrity-tampered-conf.iso"
    local t_conf_ne="$OUT/integrity-tampered-conf-noenroll.iso"
    local d_a64="$OUT/integrity-tampered-aarch64.img" d_x86="$OUT/integrity-tampered-x86.img" d_conf="$OUT/integrity-tampered-conf.img"
    python3 -I "$tamper" "$base" --file "$KERNEL_A64" --out "$t_a64" >/dev/null
    python3 -I "$tamper" "$base" --file "$KERNEL_X86" --out "$t_x86" >/dev/null
    python3 -I "$tamper" "$base" --file "$cfg" --offset 5000 --out "$t_cfg" >/dev/null
    # An attacker re-enabling the menu editor: a same-length edit of the one line that disables it.
    python3 -I "$tamper" "$base" --replace "editor_enabled: no" "editor_enabled: on" --out "$t_conf" >/dev/null
    python3 -I "$tamper" "$noenr" --replace "editor_enabled: no" "editor_enabled: on" --out "$t_conf_ne" >/dev/null
    # The raw disk image (the installed disk: ESP with the no-menu configuration).
    python3 -I "$tamper" "$base.disk" --file "$KERNEL_A64" --out "$d_a64" >/dev/null
    python3 -I "$tamper" "$base.disk" --file "$KERNEL_X86" --out "$d_x86" >/dev/null
    python3 -I "$tamper" "$base.disk" --replace 'timeout: 0\nquiet: yes' 'timeout: 5\nquiet: yes' --out "$d_conf" >/dev/null
    local row name kind accel
    local rows=("aa64|aa64|${ACCELS%% *}" "x86-uefi|x86-uefi|tcg" "x86-bios|x86-bios|tcg")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel <<<"$row"
        [[ -z "${SMOKE_INTEGRITY:-}" || $name == "$SMOKE_INTEGRITY" ]] || continue
        local mine other_iso other_disk mine_iso mine_disk elf
        if [[ $kind == aa64 ]]; then
            mine_iso=$t_a64 mine_disk=$d_a64 other_iso=$t_x86 other_disk=$d_x86 elf=aarch64
        else
            mine_iso=$t_x86 mine_disk=$d_x86 other_iso=$t_a64 other_disk=$d_a64 elf=x86-64
        fi
        local kpat="PANIC: Blake2b hash for URI \`boot\(\):/boot/urmqtt-$elf\.elf\` does not match"
        integrity_refused "kernel-iso-$name" "$kind" "$accel" iso "$mine_iso" "$kpat"
        integrity_boots "kernel-iso-$name control (other architecture's kernel changed)" "$kind" "$accel" iso "$other_iso"
        integrity_refused "kernel-disk-$name" "$kind" "$accel" disk "$mine_disk" "$kpat"
        integrity_boots "kernel-disk-$name control (other architecture's kernel changed)" "$kind" "$accel" disk "$other_disk"
        integrity_refused "module-iso-$name" "$kind" "$accel" iso "$t_cfg" \
            'PANIC: Blake2b hash for URI `boot\(\):/boot/urmqtt\.cfg` does not match'
        local cpat='CHECKSUM MISMATCH FOR CONFIG FILE'
        [[ $kind == x86-bios ]] && cpat=-
        integrity_refused "conf-iso-$name" "$kind" "$accel" iso "$t_conf" "$cpat"
        integrity_boots "conf-iso-$name control (same edit, config not enrolled)" "$kind" "$accel" iso "$t_conf_ne"
        integrity_refused "conf-disk-$name" "$kind" "$accel" disk "$d_conf" "$cpat"
    done
}

# H8 (ADR-251): UEFI Secure Boot, on x86_64 only. OVMF's Secure Boot build (SMM, q35) with the
# development PK, KEK and db enrolled (scripts/sign-loaders.sh gen-keys, ovmf-vars) must boot the
# universal ISO whose loaders are signed with the db key, and must refuse: the same image unsigned,
# one signed with another key, and a signed image whose loader was changed after signing (what
# `urmqtt-config pack --iso` does to an enrolled hash, so a signed ISO is configured BEFORE it is
# signed). Under Secure Boot Limine still refuses a modified kernel or limine.conf, and it
# refuses the installed disk, whose configuration module has no hash (ADR-217): a known limit,
# asserted here so that a change of it is noticed. Needs openssl, sbsign or osslsigncode,
# virt-fw-vars (pip install virt-firmware; PATH or URMQTT_VIRT_FW_VARS) and an OVMF with Secure
# Boot (QEMU's edk2-x86_64-secure-code.fd, or OVMF_CODE.secboot.fd; URMQTT_FIRMWARE_SECURE and
# URMQTT_FIRMWARE_VARS point elsewhere). Skipped, and said so, when one is missing;
# SMOKE_REQUIRE_SB=1 (CI) turns that into a failure. aarch64: the AArch64 edk2 of this machine
# does not enforce Secure Boot (an unsigned ISO boots with keys enrolled), so only the signature of
# BOOTAA64.EFI is checked offline and the signed ISO is booted with Secure Boot off.
universal_secureboot() {
    local missing="" sbfw="" vars="" c
    command -v openssl >/dev/null || missing="openssl"
    command -v sbsign >/dev/null || command -v osslsigncode >/dev/null || missing="$missing sbsign-or-osslsigncode"
    command -v "${URMQTT_VIRT_FW_VARS:-virt-fw-vars}" >/dev/null || missing="$missing virt-fw-vars"
    for c in "${URMQTT_FIRMWARE_SECURE:-}" "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-x86_64-secure-code.fd" \
        /usr/share/qemu/edk2-x86_64-secure-code.fd /usr/share/OVMF/OVMF_CODE.secboot.fd \
        /usr/share/OVMF/OVMF_CODE_4M.secboot.fd /usr/share/edk2/ovmf/OVMF_CODE.secboot.fd; do
        [[ -n "$c" && -f "$c" ]] && { sbfw=$c; break; }
    done
    [[ -n "$sbfw" ]] || missing="$missing ovmf-secure-boot-firmware"
    for c in "${URMQTT_FIRMWARE_VARS:-}" "$(dirname "${sbfw:-/nonexistent}")/edk2-i386-vars.fd" \
        /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/ovmf/OVMF_VARS.fd; do
        [[ -n "$c" && -f "$c" ]] && { vars=$c; break; }
    done
    [[ -n "$vars" ]] || missing="$missing ovmf-vars"
    if [[ -n "$missing" ]]; then
        if [[ -n "${SMOKE_REQUIRE_SB:-}" ]]; then
            echo "  ✗ universal-secureboot: missing:$missing"
            FAILED=$((FAILED + 1))
        else
            echo "  - universal-secureboot skipped (missing:$missing); NOT tested"
        fi
        return 0
    fi
    local sb="$ROOT/scripts/sign-loaders.sh" keys="$OUT/secureboot-keys" other="$OUT/secureboot-other"
    rm -rf "$keys" "$other"
    "$sb" gen-keys "$keys" >/dev/null
    "$sb" gen-keys "$other" >/dev/null
    local svars="$OUT/secureboot-vars.fd"
    cp "$vars" "$svars"
    "$sb" ovmf-vars "$keys" "$vars" "$svars" 2>/dev/null
    local signed="$OUT/sb-signed.iso" unsigned="$OUT/sb-unsigned.iso" wrongkey="$OUT/sb-wrongkey.iso" tpl="$OUT/sb-template.iso"
    export URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0
    rm -f "$signed" "$signed.disk" "$unsigned" "$wrongkey" "$tpl"
    mkuniversal "$signed" "smoke" --sb-key "$keys/db.key" --sb-cert "$keys/db.crt"
    mkuniversal "$unsigned" "smoke"
    mkuniversal "$wrongkey" "smoke" --sb-key "$other/db.key" --sb-cert "$other/db.crt"
    mkuniversal "$tpl" "smoke" --empty-config --sb-key "$keys/db.key" --sb-cert "$keys/db.crt"
    unset URMQTT_LIMINE_SERIAL URMQTT_MENU_TIMEOUT
    # The same ISO signed twice is the same bytes (the signing time is SOURCE_DATE_EPOCH).
    local again="$OUT/sb-signed-again.iso"
    rm -f "$again"
    URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0 mkuniversal "$again" "smoke" --sb-key "$keys/db.key" --sb-cert "$keys/db.crt"
    if cmp -s "$signed" "$again"; then
        echo "  ✓ secureboot: the signed ISO is reproducible (same key, same bytes)"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ secureboot: two builds of the signed ISO differ"
        FAILED=$((FAILED + 1))
    fi
    rm -f "$again" "$again.disk"
    # The configured-after-signing image: the enrolled hash of the menu changes, the signature breaks.
    make_cfg_blobs
    local patched="$OUT/sb-configured-after-signing.iso" tool="$ROOT/target/debug/urmqtt-config"
    "$tool" pack "$OUT/cfgpack/config.toml" --env dev --root "$ROOT/deploy/dev" \
        --sign "$ROOT/deploy/dev/control.key" --iso "$tpl" --out "$patched" >/dev/null 2>&1 \
        || { echo "  ✗ secureboot: pack --iso failed"; FAILED=$((FAILED + 1)); }
    # Tampered copies of the signed ISO.
    local t_kernel="$OUT/sb-tampered-kernel.iso" t_conf="$OUT/sb-tampered-conf.iso"
    python3 -I "$ROOT/scripts/tamper.py" "$signed" --file "$KERNEL_X86" --out "$t_kernel" >/dev/null
    python3 -I "$ROOT/scripts/tamper.py" "$signed" --replace "editor_enabled: no" "editor_enabled: on" --out "$t_conf" >/dev/null

    local x86='URMQTT BOOT [^ ]+ arch=x86_64 cpu=2 mem=[0-9]+$' status log
    sb_boot() { # sb_boot <label> <file> <how iso|disk>
        local label=$1 file=$2 how=${3:-iso}
        log="$OUT/secureboot-$label.log" status=0
        u_run x86-uefi tcg "$log" "$how" "$file" --secure-vars "$svars" || status=$?
    }
    sb_refused() { # sb_refused <label> <file> <pattern> [iso|disk]
        local label=$1 file=$2 pat=$3 how=${4:-iso}
        log="$OUT/secureboot-$label.log" status=0
        boot_until "$log" "$pat" --arch x86_64 "--$how" "$file" --accel tcg --smp 2 --no-net --secure-vars "$svars" || status=$?
        check "secureboot: $label refused" "$log" "$status" "$pat" "NOT:URMQTT BOOT" "NOT:URMQTT READY"
    }
    sb_boot signed "$signed"
    check "secureboot: signed ISO boots with Secure Boot enforced" "$log" "$status" "$x86" "bootloader=Limine" "^URMQTT READY$" "NOT:Access Denied"
    sb_refused unsigned "$unsigned" "Access Denied"
    sb_refused wrong-key "$wrongkey" "Access Denied"
    sb_refused configured-after-signing "$patched" "Access Denied"
    sb_refused tampered-kernel "$t_kernel" 'PANIC: Blake2b hash for URI `boot\(\):/boot/urmqtt-x86-64\.elf` does not match'
    sb_refused tampered-conf "$t_conf" "CHECKSUM MISMATCH FOR CONFIG FILE"
    local d="$OUT/secureboot-disk.img"
    fresh_disk "$signed.disk" "$d"
    sb_refused installed-disk-known-limit "$d" 'Secure Boot is active and URI `boot\(\):/boot/urmqtt\.cfg` has no associated hash' disk
    # Without Secure Boot a signed loader is an ordinary one; BOOTAA64.EFI's signature checks offline.
    local a64="${ACCELS%% *}" log2="$OUT/secureboot-aarch64-signed.log" st2=0
    u_run aa64 "$a64" "$log2" iso "$signed" || st2=$?
    check "secureboot: signed ISO boots on aarch64 (Secure Boot not enforced by this firmware)" "$log2" "$st2" \
        'URMQTT BOOT [^ ]+ cpu=4 mem=[0-9]+$' "^URMQTT READY$"
    local efi="$OUT/secureboot-BOOTAA64.EFI"
    rm -f "$efi"
    xorriso -osirrox on -indev "$signed" -extract /EFI/BOOT/BOOTAA64.EFI "$efi" >/dev/null 2>&1 || true
    if [[ -s "$efi" ]] && "$sb" verify "$keys/db.crt" "$efi" && ! "$sb" verify "$other/db.crt" "$efi"; then
        echo "  ✓ secureboot: BOOTAA64.EFI is signed by the db key and by no other (offline check)"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ secureboot: BOOTAA64.EFI signature check failed"
        FAILED=$((FAILED + 1))
    fi
}

# H8 (ADR-253): the installer entry's rules. The installer erases a disk, so what may start it matters.
#  * A production kernel honours three command-line words, install, live and diag (ADR-052, ADR-054,
#    ADR-063; host tests production_honours_*), and only install writes to a disk. It does nothing
#    without the installation image: no module, no write ("install: no installation image").
#  * The image is a module that Limine checks against the blake2b in the ISO menu: a changed copy is
#    refused before the kernel runs, and nothing is written.
#  * Adding install to another entry means editing limine.conf, which the loaders refuse (ADR-250).
# Each case runs with a blank 64 MiB disk attached, whose bytes must be the same afterwards. The control
# of the first is the same edit in an image built with --no-enroll: the kernel gets the word and, with
# no module, refuses to write.
universal_install_rules() {
    local base="$OUT/integrity-base.iso" noenr="$OUT/integrity-noenroll.iso" inst="$OUT/install-rules-default.iso"
    URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0 mkuniversal "$base" "smoke"
    URMQTT_LIMINE_SERIAL=1 URMQTT_MENU_TIMEOUT=0 mkuniversal "$noenr" "smoke" --no-enroll
    URMQTT_LIMINE_SERIAL=1 mkuniversal "$inst" "smoke" --install-default --install-cmdline "install install-countdown=1"
    local t_word="$OUT/install-rules-word.iso" t_word_ne="$OUT/install-rules-word-noenroll.iso" t_img="$OUT/install-rules-image.iso"
    local img="$OUT/install-rules-disk.img"
    rm -f "$img"
    xorriso -osirrox on -indev "$inst" -extract /disk.img "$img" >/dev/null 2>&1 || true
    if [[ ! -s "$img" ]]; then
        echo "  ✗ install-rules: cannot extract /disk.img from the ISO"
        FAILED=$((FAILED + 1))
        return 0
    fi
    chmod u+rw "$img"
    local tamper="$ROOT/scripts/tamper.py"
    # "live smoke" and "install no" are the same length: a same-length edit of the first entry's command line.
    python3 -I "$tamper" "$base" --replace "cmdline: live smoke" "cmdline: install no" --out "$t_word" >/dev/null
    python3 -I "$tamper" "$noenr" --replace "cmdline: live smoke" "cmdline: install no" --out "$t_word_ne" >/dev/null
    python3 -I "$tamper" "$inst" --file "$img" --offset 100000 --out "$t_img" >/dev/null
    local row name kind accel target before after status log
    local rows=("aa64|aa64|${ACCELS%% *}" "x86-uefi|x86-uefi|tcg" "x86-bios|x86-bios|tcg")
    for row in "${rows[@]}"; do
        IFS='|' read -r name kind accel <<<"$row"
        [[ -z "${SMOKE_INTEGRITY:-}" || $name == "$SMOKE_INTEGRITY" ]] || continue
        target="$OUT/install-rules-target-$name.img"
        local drive=(-- -drive "if=none,id=t0,file=$target,format=raw,cache=none" -device virtio-blk-pci,drive=t0,romfile=)
        # 1. A word added to the first entry: refused by the loader (BIOS: the message is on the screen only).
        rm -f "$target"; truncate -s 64m "$target"; before=$(shasum -a 256 "$target" | cut -d' ' -f1)
        log="$OUT/install-rules-word-$name.log"; status=0
        if [[ $kind == x86-bios ]]; then
            # shellcheck disable=SC2046
            TIMEOUT=${SMOKE_REFUSE_WAIT:-45} boot_until "$log" 'install: ' $(u_args "$kind" "$accel" iso "$t_word") --no-net "${drive[@]}" || status=$?
            [[ $status -eq 124 ]] && status=0 || status=1
            after=$(shasum -a 256 "$target" | cut -d' ' -f1)
            [[ $after == "$before" ]] || echo "DISK CHANGED" >>"$log"
            check "install-rules: a word added to limine.conf is refused [$name]" "$log" "$status" "NOT:install: " "NOT:DISK CHANGED"
        else
            # shellcheck disable=SC2046
            boot_until "$log" 'CHECKSUM MISMATCH FOR CONFIG FILE' $(u_args "$kind" "$accel" iso "$t_word") --no-net "${drive[@]}" || status=$?
            after=$(shasum -a 256 "$target" | cut -d' ' -f1)
            [[ $after == "$before" ]] || echo "DISK CHANGED" >>"$log"
            check "install-rules: a word added to limine.conf is refused [$name]" "$log" "$status" \
                "CHECKSUM MISMATCH FOR CONFIG FILE" "NOT:install: " "NOT:URMQTT" "NOT:DISK CHANGED"
        fi
        # 2. Control: the same edit, config not enrolled. The kernel gets install, has no module, writes nothing.
        rm -f "$target"; truncate -s 64m "$target"; before=$(shasum -a 256 "$target" | cut -d' ' -f1)
        log="$OUT/install-rules-word-control-$name.log"; status=0
        u_run "$kind" "$accel" "$log" iso "$t_word_ne" "${drive[@]}" || status=$?
        after=$(shasum -a 256 "$target" | cut -d' ' -f1)
        [[ $after == "$before" ]] || echo "DISK CHANGED" >>"$log"
        check "install-rules: with install but no installation image nothing is written [$name]" "$log" "$status" \
            "install: no installation image" "NOT:install: ALL DATA ON" "NOT:install: done" "NOT:URMQTT READY" "NOT:DISK CHANGED"
        # 3. The installation image changed by one bit: Limine refuses it, nothing is written.
        rm -f "$target"; truncate -s 64m "$target"; before=$(shasum -a 256 "$target" | cut -d' ' -f1)
        log="$OUT/install-rules-image-$name.log"; status=0
        # shellcheck disable=SC2046
        boot_until "$log" 'PANIC: Blake2b hash for URI `boot\(\):/disk\.img` does not match' $(u_args "$kind" "$accel" iso "$t_img") --no-net "${drive[@]}" || status=$?
        after=$(shasum -a 256 "$target" | cut -d' ' -f1)
        [[ $after == "$before" ]] || echo "DISK CHANGED" >>"$log"
        check "install-rules: a changed installation image is refused [$name]" "$log" "$status" \
            'PANIC: Blake2b hash for URI `boot\(\):/disk\.img` does not match' "NOT:install: " "NOT:DISK CHANGED"
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
    # Phase 1 on <from>: the broker with the dev certificates, forwarded to $PORT.
    start_vm_kind "$from" "$faccel" "$l1" "$data"
    if wait_log "$l1" "TLS 1.3 listener on port 8883"; then
        python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$ROOT/deploy/dev" --phase 1 >"$l1.client" 2>&1 || status=$?
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
        python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$ROOT/deploy/dev" --phase 2 >"$l2.client" 2>&1 || status=$?
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
        aa64) start_vm "$log" --disk "$disk" --accel "$accel" --fwd $PORT:8883 ;;
        x86-uefi) start_vm "$log" --arch x86_64 --disk "$disk" --accel tcg --fwd $PORT:8883 ;;
        x86-bios) start_vm "$log" --arch x86_64 --machine pc --firmware bios --disk "$disk" --accel tcg --fwd $PORT:8883 ;;
    esac
}

# O3 (ADR-054): the ISO's first ("live") entry runs the broker from RAM with
# no disk at all, serves MQTT over mTLS, and a reboot loses what it held.
# start_vm_iso <kind> <accel> <log> <iso> [run-qemu args]: a serving VM
# booted from the ISO (a CD) alone, TLS port forwarded to $PORT.
start_vm_iso() {
    local kind=$1 accel=$2 log=$3 iso=$4
    shift 4
    case $kind in
        aa64) start_vm "$log" --iso "$iso" --accel "$accel" --fwd $PORT:8883 "$@" ;;
        x86-uefi) start_vm "$log" --arch x86_64 --iso "$iso" --accel "$accel" --smp 2 --fwd $PORT:8883 "$@" ;;
        x86-bios) start_vm "$log" --arch x86_64 --machine pc --firmware bios --iso "$iso" --accel "$accel" --smp 2 --fwd $PORT:8883 "$@" ;;
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
        python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$ROOT/deploy/dev" --phase live1 \
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
        python3 -I "$ROOT/scripts/mqtt-persist.py" $PORT --tls "$ROOT/deploy/dev" --phase gone \
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

# H4 KASLR (ADR-173): the same image booted three times must place every
# region somewhere else each time. A dev image logs the addresses on one line
# ("kaslr (dev only): image X (slide S), heap H, bookkeeping B, stacks K,
# page-table alias A, mmio M"); a region passes if at least two of the three
# boots differ (the narrowest placement has 9 bits, so three equal boots by
# chance are 1 in 262144). The line is dev only: no other line may carry a
# kernel address of those regions.
kaslr_differs() {
    local iso="$OUT/kaslr-differs.raw" n=3 accel i
    mkimg "$iso" "smoke"
    for accel in $ACCELS; do
        local data="$OUT/kaslr-differs-$accel.img" ok=1 why=""
        for i in $(seq "$n"); do
            local log="$OUT/kaslr-differs-$accel-$i.log" status=0
            fresh_disk "$iso" "$data"
            boot "$log" --disk "$data" --accel "$accel" --smp 2 --headless --no-net || status=$?
            clean "$log" >"$log.clean"
            if [[ $status -ne 0 ]] || ! grep -q "^URMQTT READY$" "$log.clean"; then
                ok=0; why="$why boot $i did not reach READY (status $status);"
            fi
            grep -E "kaslr \(dev only\): image " "$log.clean" | head -1 \
                | sed -E 's/.*image (0x[0-9a-f]+) \(slide (0x[0-9a-f]+)\), heap (0x[0-9a-f]+), bookkeeping (0x[0-9a-f]+), stacks (0x[0-9a-f]+), page-table alias (0x[0-9a-f]+), mmio (0x[0-9a-f]+).*/\1 \3 \4 \5 \6 \7/' \
                >"$OUT/kaslr-differs-$accel-$i.vals"
            if ! grep -Eq "^(0x[0-9a-f]+ ){5}0x[0-9a-f]+$" "$OUT/kaslr-differs-$accel-$i.vals"; then
                ok=0; why="$why boot $i printed no placement line;"
            fi
        done
        local names=(image heap bookkeeping stacks alias mmio) f
        for f in 1 2 3 4 5 6; do
            local distinct
            distinct=$(for i in $(seq "$n"); do cut -d' ' -f"$f" "$OUT/kaslr-differs-$accel-$i.vals"; done | sort -u | wc -l | tr -d ' ')
            # The image slides where the kernel is position independent and the
            # bootloader applies KASLR: both architectures (ADR-173).
            if [[ $distinct -lt 2 ]]; then
                ok=0; why="$why ${names[$((f - 1))]} was the same in all $n boots;"
            fi
        done
        # The production line has bit counts and no addresses.
        grep -Eq "kaslr: heap [0-9]+ bit\(s\), heap bookkeeping [0-9]+, stacks [0-9]+, page-table alias [0-9]+, mmio [0-9]+; kernel image slid by the bootloader \(seed [0-9]+ bit\(s\)\)" \
            "$OUT/kaslr-differs-$accel-1.log.clean" || { ok=0; why="$why no entropy line;"; }
        if [[ $ok -eq 1 ]]; then
            echo "  ✓ kaslr-differs [$accel]: $n boots, six regions placed differently ($(tr '\n' '|' <"$OUT/kaslr-differs-$accel-1.vals" | cut -d' ' -f1) ...)"
            PASSED=$((PASSED + 1))
        else
            echo "  ✗ kaslr-differs [$accel]:$why"
            FAILED=$((FAILED + 1))
        fi
    done
}

# H4 (exploit mitigations, ADR-170..175): one suite for both architectures.
# The hooks are dev-image only (`selftest` feature); the scenarios boot the
# raw dev image with a test word and read the serial log.
hardening_suite() {
    kaslr_differs
    # The unprivileged database worker (ADR-210): every way it can misbehave
    # ends in a failed call and a restart, never a kernel fault; the kernel
    # word it tried to overwrite is intact; the CPU's kernel/user separation
    # (PAN, or SMEP and SMAP) is on.
    # The same on the real store path: the worker faults between a commit and
    # the next one; the store comes back from the WAL with the committed rows
    # only, and the broker goes on.
    scenario worker-fault "smoke serve test=worker-fault" on \
        "worker-fault: 100 rows committed, 10 more in an open transaction" \
        "dbworker: call [0-9]+ faulted: " "dbworker: restarted \(restart #1\)" \
        "db: the database worker was restarted \(restart #1\); reopening the store, 11 uncommitted op\(s\) lost|db: the database worker was restarted \(restart #1\); reopening the store, 0 uncommitted op\(s\) lost" \
        "db: store reopened after the worker restart" \
        "worker-fault: 100 rows consistent after the restart, the 10 uncommitted rows are gone" \
        "worker-fault: done, powering off" \
        "NOT:INCONSISTENT|expected 100|setup failed|verify failed" "NOT:!!! EXCEPTION|PANIC" "^URMQTT READY$"
    scenario worker-contain "smoke test=worker-contain" on \
        "worker-contain: hello before: ok" \
        "worker-contain: kernel/user separation: (PAN|SMEP\+SMAP)$" \
        "worker-contain: read-kernel-data: contained \(Fault\), worker restarted" \
        "worker-contain: write-kernel-data: contained \(Fault\), worker restarted" \
        "worker-contain: exec-kernel-text: contained \(Fault\), worker restarted" \
        "worker-contain: privileged-instruction: contained \(Fault\), worker restarted" \
        "worker-contain: write-own-code: contained \(Fault\), worker restarted" \
        "worker-contain: exec-own-data: contained \(Fault\), worker restarted" \
        "worker-contain: null-read: contained \(Fault\), worker restarted" \
        "worker-contain: endless-loop: contained \(Timeout\), worker restarted" \
        "worker-contain: kernel data intact" \
        "worker-contain: 8/8 contained, 8 restart\(s\), kernel still running$" \
        "NOT:NOT contained|FAILED|OVERWRITTEN|WITH FAILURES" "^URMQTT READY$" "$NO_FAULT"
    # Allocator (ADR-170): the allocator stops the VM on each of these.
    scenario double-free "smoke test=double-free" on \
        "test mode: triggering HeapDoubleFree" "PANIC: panicked at" "^heap: double free" \
        "NOT:was NOT detected" "NOT:URMQTT READY"
    scenario heap-uaf "smoke test=heap-uaf" on \
        "PANIC: panicked at" "^heap: write after free" "NOT:was NOT detected" "NOT:URMQTT READY"
    scenario heap-overflow "smoke test=heap-overflow" on \
        "PANIC: panicked at" "^heap: heap overflow" "NOT:was NOT detected" "NOT:URMQTT READY"
    # Stack protector (ADR-171): the canary is renewed twice at boot, and an
    # overrun of a local buffer stops the machine at the function's return.
    scenario stack-guard-boot "smoke" on \
        "hardening: boot seed of [0-9]+ bit\(s\)" "hardening: stack canary renewed from the CSPRNG \(56 bits\)" \
        "^URMQTT READY$" "$NO_FAULT" "NOT:STACK SMASHING"
    scenario stack-smash "smoke test=stack-smash" on \
        "test mode: triggering StackSmash" "test: the stack canary is not the build-time constant: true" \
        "!!! STACK SMASHING DETECTED" "NOT:was NOT detected" "NOT:URMQTT READY"
    # Fault policy (ADR-172): under the production policy a fault report has no
    # register, no stack or heap content and no absolute address; the open
    # twin of each test proves the grep can see the key when it is printed.
    scenario fault-secrets "smoke redact test=fault-secrets" on \
        "test mode: triggering FaultSecrets" "!!! EXCEPTION: " \
        "pc = kernel\+0x[0-9a-f]+; registers, stack and memory withheld \(production policy\)" \
        "NOT:5345435245544b45|595f544553545f31|SECRETKE|Y_TEST_" "NOT:(x[0-9]+|R[A-Z0-9]+)=0x[0-9a-f]{16}" \
        "NOT:FAR=0x|CR2=0x|ESR=0x|RIP=0x|RSP=0x" "NOT:URMQTT READY"
    scenario fault-secrets-open "smoke test=fault-secrets-open" on \
        "test mode: triggering FaultSecretsOpen" "!!! EXCEPTION: " \
        "0x5345435245544b45" "0x595f544553545f31" "0x5345435245544b33" "0x595f544553545f33" "NOT:URMQTT READY"
    scenario panic-secret "smoke redact test=panic-secret" on \
        "!!! PANIC: panicked at " "hardtest.rs" "message withheld: it has formatted arguments" \
        "NOT:5345435245544b45|595f544553545f31|SECRETKE|test panic carrying a key" "NOT:URMQTT READY"
    scenario panic-secret-open "smoke test=panic-secret" on \
        "!!! PANIC: panicked at " "test panic carrying a key: .*5345435245544b45" "NOT:URMQTT READY"
    scenario double-free-prod "smoke redact test=double-free" on \
        "!!! PANIC: panicked at " "^heap: double free" "NOT:message withheld" "NOT:URMQTT READY"
    scenario keyslab-zero "smoke test=keyslab-zero" on \
        "keyslab-zero: 8 key\(s\) stored and read back in place \(true\), freed; 16 free slot\(s\) all zero \(true\); stale handles refused \(true\): ok" \
        "keyslab-zero: a freed 1000-byte heap block reads back as poison 0xdf \(true\), no byte of the old contents left \(true\): ok" \
        "NOT:FAILED" "^URMQTT READY$" "$NO_FAULT"
    # Memory tagging (ADR-174): aarch64 under TCG only (QEMU's virt machine
    # with mte=on; HVF does not implement FEAT_MTE).
    if [[ $ARCH == aarch64 && " $ACCELS " == *" tcg "* ]]; then
        local MTE_ON='mte: synchronous tag checking on; live heap allocations up to [0-9]+ KiB carry a random tag'
        ACCELS=tcg URMQTT_MTE=1 scenario mte-boot "smoke" on \
            "cpu features: .* mte=true" "$MTE_ON" "selftest: frames ok" \
            "^URMQTT READY$" "$NO_FAULT" "NOT:tag check fault"
        ACCELS=tcg URMQTT_MTE=1 scenario mte-uaf "smoke test=mte-uaf" on \
            "$MTE_ON" "test mode: triggering MteUaf" \
            "EC=0x25 data abort \(same EL\), read, synchronous tag check fault" \
            "NOT:was NOT detected" "NOT:URMQTT READY"
        ACCELS=tcg URMQTT_MTE=1 scenario mte-overflow "smoke test=mte-overflow" on \
            "write inside the last granule was accepted" \
            "EC=0x25 data abort \(same EL\), write, synchronous tag check fault" \
            "NOT:was NOT detected" "NOT:URMQTT READY"
        # The whole broker under tag checking: TLS handshakes, MQTT, the
        # database. A false positive anywhere would be a tag check fault.
        ACCELS=tcg URMQTT_MTE=1 SERVICE_PORT=8883 service mte-mqtt-tls "serve" $PORT "TLS 1.3 listener on port 8883" \
            python3 -I "$ROOT/scripts/mqtt-scenarios.py" --tls "$ROOT/deploy/dev" -- \
            "$MTE_ON" "client: pubsub-wildcard ok" "client: retained ok" "client: qos1-after-reconnect ok" \
            "client: tls-wrong-ca-rejected ok" "tls: device-001 authenticated \(TLS13_" \
            "NOT:FAILED" "NOT:tag check fault" "$NO_FAULT"
    else
        echo "  - mte-*: skipped (needs aarch64 under TCG; HVF and x86_64 have no FEAT_MTE)"
    fi
}

# SMOKE_ONLY=hardening: the H4 scenarios of this architecture.
if [[ ${SMOKE_ONLY:-} == hardening && $ARCH != universal ]]; then
    hardening_suite
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=time: just the wall-clock scenarios (H7, T1).
if [[ ${SMOKE_ONLY:-} == time && $ARCH != universal ]]; then
    time_before_build
    time_sntp
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=storage: the disk scenarios of this architecture (SMOKE_SCENARIOS=<regex>
# picks groups by function name; first boot and
# its power cuts, the SCSI boot, the CD, a damaged partition, the host tool,
# the topology, layout v1 refusal, migration and growing); no network service.
if [[ ${SMOKE_ONLY:-} == storage && $ARCH != universal ]]; then
    want first_boot && first_boot
    want first_boot_crash && first_boot_crash
    want scsi_boot && scsi_boot
    want iso_as_cd && iso_as_cd
    want own_damaged && own_damaged
    want storage_topology && storage_topology
    want layout_v1 && layout_v1
    want grow_online && grow_online
    want discard_qcow2 && discard_qcow2
    want db_backup && db_backup
    want storage_encrypted && storage_encrypted
    [[ ${SMOKE_SCENARIOS:-} == *storage_encrypted_bench* ]] && storage_encrypted_bench
    want backup_upgrade && backup_upgrade
    want backup_scheduled && backup_scheduled
    want backup_bench && backup_bench
    want scrub_flip && scrub_flip
    want scrub_load && scrub_load
    if ! want disk_tool; then
        :
    elif command -v mosquitto_pub >/dev/null && command -v sqlite3 >/dev/null; then
        disk_tool
    else
        echo "  ✗ disk-tool needs sqlite3 and the mosquitto clients"
        FAILED=$((FAILED + 1))
    fi
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

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

# SMOKE_ONLY=migrated (universal): a migrated v1 disk, grown by one machine and
# read by the other two (S2, X8).
if [[ ${SMOKE_ONLY:-} == migrated && $ARCH == universal ]]; then
    universal_migrated
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=template (universal): only the released template ISO (SMOKE_TEMPLATE_ISO=<file>).
if [[ ${SMOKE_ONLY:-} == template && $ARCH == universal ]]; then
    universal_template
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=config (universal): the configuration scenarios (C1: the patched template, the installer
# carrying the configuration to the installed disk).
if [[ ${SMOKE_ONLY:-} == config && $ARCH == universal ]]; then
    universal_config
    universal_template
    universal_install
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=integrity (universal): H8, modified kernel / module / limine.conf are refused by the loader
# (SMOKE_INTEGRITY=<aa64|x86-uefi|x86-bios> limits the machine).
if [[ ${SMOKE_ONLY:-} == integrity && $ARCH == universal ]]; then
    universal_integrity
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=install-rules (universal): H8, what may start the installer (SMOKE_INTEGRITY=<machine> limits it).
if [[ ${SMOKE_ONLY:-} == install-rules && $ARCH == universal ]]; then
    universal_install_rules
    echo "smoke: $PASSED passed, $FAILED failed"
    [[ $FAILED -eq 0 ]]
    exit
fi

# SMOKE_ONLY=secureboot (universal): H8, OVMF with Secure Boot enforced (needs the tools universal_secureboot lists).
if [[ ${SMOKE_ONLY:-} == secureboot && $ARCH == universal ]]; then
    universal_secureboot
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
    universal_config
    universal_raw
    universal_migrated
    universal_install
    universal_integrity
    universal_install_rules
    universal_secureboot
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
        "CR2=0x0000000000000008" "RIP=0xffffffff[89a-f]" "RAX=0x[0-9a-f]+ RBX=" "R15=0x" \
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
    "${DISPATCH_OK[@]}" "${CONFIG_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
want config_packed && config_packed
want release_kernel && release_kernel
want plaintext && plaintext
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
    [[ -f $log ]] || continue # SMOKE_SCENARIOS filtered the scenario out
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
    "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${DEV_OK[@]}" "${SMP4_OK[@]}" "${DB_OK[@]}" "${DISPATCH_OK[@]}" "${CONFIG_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario boot-dtb "smoke" off \
    "$BOOT_LINE" "platform: discovered via DeviceTree" "console: pl011 at 0x9000000" "${MEMORY_OK[@]}" \
    "${TIME_OK[@]}" "${DEV_OK[@]}" "${DISPATCH_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
want config_packed && config_packed
want release_kernel && release_kernel
want plaintext && plaintext
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
    "EXCEPTION: synchronous, current EL, SP0" "data abort \(same EL\), (read|write), translation fault" \
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
    SERVICE_PORT=8883 service mqtt-tls "serve" $PORT "TLS 1.3 listener on port 8883" \
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
        start_vm "$log" --disk "$data" --accel "$accel" --fwd $PORT:8883
        if wait_log "$log" "TLS 1.3 listener"; then
            python3 -I "$ROOT/scripts/sys-scenarios.py" reboot "$ROOT/deploy/dev" $PORT >"$log.client" 2>&1 || status=1
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
    SERVICE_PORT=8883 service sys-slow-log "serve test=slow-log:4000" $PORT "TLS 1.3 listener on port 8883" \
        python3 -I "$ROOT/scripts/sys-scenarios.py" watch "$ROOT/deploy/dev" -- \
        "client: sys-watch ok" "NOT:\(step sys\)" "NOT:FAILED" "$NO_FAULT"
fi

# ADR-090: the log never stalls the data path. Every core logs one numbered
# line every 25 ms from inside a watched handler while each line takes 4 ms
# to reach the sinks (a hypervisor's serial port and screen). No handler may
# be reported over budget; no line may be lost or reordered within its core,
# and the timestamps of the merged log are in order.
SERVICE_PORT=8883 service log-slow-flood "serve test=slow-log:4000 test=log-flood:25 ${LOG_FLOOD_EXTRA:-}" 18893 \
    "TLS 1.3 listener on port 8883" python3 -I "$ROOT/scripts/log-flood-check.py" -- \
    "client: log-flood ok" "log: asynchronous: cores queue their lines" "log: cost: [0-9]+ call" \
    "NOT:over budget" "NOT:FAILED" "$NO_FAULT"

# O1, O2: an operator with mutual TLS reads `$SYS/broker/#` (retained, every
# 10 s), asks `$SYS/query/info`, reads the console and runs the fixed command
# set; devices and the backend service cannot reach any of it. Every command
# is audit-logged on the serial console.
if command -v mosquitto_pub >/dev/null && command -v mosquitto_sub >/dev/null; then
    SERVICE_PORT=8883 service sys-operator "serve" $PORT "TLS 1.3 listener on port 8883" \
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
SERVICE_PORT=8883 service ticket-rotation "serve test=ticket-rotate:20" $PORT "TLS 1.3 listener on port 8883" \
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
    SERVICE_PORT=8883 service control "serve" $PORT "TLS 1.3 listener on port 8883" \
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
    SERVICE_PORT=8883 service registry-allowlist "serve registry=allowlist" $PORT "TLS 1.3 listener on port 8883" \
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
if command -v mosquitto_pub >/dev/null; then
    time_sntp
fi

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
# ADR-221: the budget is running time. A handler whose core is stalled for 45 ms
# (interrupts masked: the tick arrives late, as after a descheduled vCPU) is not
# reported; one that really runs for 50 ms is.
scenario watchdog-stall "smoke test=watchdog-stall" on \
    "watchdog: core 0 self-test handler \(step -\) for conn 45 over budget: [0-9]+ ms > 10 ms \(action: Log" \
    "NOT:conn 44 over budget" "^URMQTT READY$" "$NO_FAULT"
# ... and a handler that waits 50 ms for a spin lock is not reported while it waits.
scenario watchdog-lockwait "smoke test=watchdog-lockwait" on \
    "watchdog: core 0 self-test handler \(step -\) for conn 47 over budget: [0-9]+ ms > 10 ms \(action: Log" \
    "NOT:conn 46 over budget" "^URMQTT READY$" "$NO_FAULT"
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
    want mqtt_persist && mqtt_persist
fi
want storm && storm
want attack_raw && attack_raw
want attack_app && attack_app
want observability && observability
want first_boot && first_boot
want first_boot_crash && first_boot_crash
want scsi_boot && scsi_boot
want iso_as_cd && iso_as_cd
if command -v mosquitto_pub >/dev/null; then
    want live_suite && live_suite
else
    echo "  ✗ live-mode scenarios need the mosquitto clients"
    FAILED=$((FAILED + 1))
fi
want own_damaged && own_damaged
want storage_topology && storage_topology
want layout_v1 && layout_v1
want grow_online && grow_online
want db_backup && db_backup
want backup_upgrade && backup_upgrade
want backup_scheduled && backup_scheduled
want backup_bench && backup_bench
want scrub_flip && scrub_flip
want scrub_load && scrub_load
want disk_tool && disk_tool
[[ $ARCH == aarch64 ]] && want install_iso && install_iso
want no_hw_rng && no_hw_rng
[[ $ARCH == aarch64 ]] && want gicv2 && gicv2

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
