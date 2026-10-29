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
        boot "$log" --iso "$iso" --accel "$accel" --acpi "$acpi" --smp "${SMP:-4}" --headless --no-net || status=$?
        check "$name [$accel]" "$log" "$status" "$@"
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
SMP4_OK=("cpu 1 online" "cpu 3 online" "smp: 4/4 cpus online" "ipi: 12/12 ordered pairs ping-pong ok"
    "smp: 4/4 cpus ticking on their own timer")

scenario boot-acpi "smoke" on \
    "$BOOT_LINE" "platform: discovered via Acpi" "console: pl011 at 0x9000000" "psci 1\.[0-9]+ via hvc" \
    "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${SMP4_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
scenario boot-dtb "smoke" off \
    "$BOOT_LINE" "platform: discovered via DeviceTree" "console: pl011 at 0x9000000" "${MEMORY_OK[@]}" \
    "${TIME_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
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
