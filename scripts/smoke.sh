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
SMP4_OK=("cpu 1 online" "cpu 3 online" "smp: 4/4 cpus online" "ipi: 12/12 ordered pairs ping-pong ok"
    "smp: 4/4 cpus ticking on their own timer")

scenario boot-acpi "smoke" on \
    "$BOOT_LINE" "platform: discovered via Acpi" "console: pl011 at 0x9000000" "psci 1\.[0-9]+ via hvc" \
    "${MEMORY_OK[@]}" "${TIME_OK[@]}" "${DEV_OK[@]}" "${SMP4_OK[@]}" "^URMQTT READY$" "$NO_FAULT"
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
else
    echo "  ✗ mosquitto clients not installed (brew install mosquitto / apt install mosquitto-clients)"
    FAILED=$((FAILED + 1))
fi

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
