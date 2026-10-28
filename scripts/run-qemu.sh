#!/usr/bin/env bash
# shellcheck disable=SC2054  # QEMU option syntax uses commas inside one argument
# Boots an urMQTT ISO in QEMU (aarch64 virt, GICv3, UEFI).
#
#   scripts/run-qemu.sh --iso ISO [--accel hvf|tcg|kvm] [--smp N] [--mem 512M]
#                       [--data IMG] [--acpi on|off] [--serial FILE] [--headless]
#                       [--pcap FILE] [--gdb] [--no-net] [-- extra qemu args]
#
# Without --serial the serial console is on stdio. Ctrl-A X quits QEMU.
set -euo pipefail

ISO="" ACCEL="" SMP=4 MEM=512M DATA="" ACPI=on SERIAL="" HEADLESS=0 PCAP="" GDB=0 NET=1
EXTRA=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --iso) ISO=$2; shift 2 ;;
        --accel) ACCEL=$2; shift 2 ;;
        --smp) SMP=$2; shift 2 ;;
        --mem) MEM=$2; shift 2 ;;
        --data) DATA=$2; shift 2 ;;
        --acpi) ACPI=$2; shift 2 ;;
        --serial) SERIAL=$2; shift 2 ;;
        --headless) HEADLESS=1; shift ;;
        --pcap) PCAP=$2; shift 2 ;;
        --gdb) GDB=1; shift ;;
        --no-net) NET=0; shift ;;
        --) shift; EXTRA=("$@"); break ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -f "$ISO" ]] || { echo "error: ISO '$ISO' not found (run make iso)" >&2; exit 1; }

if [[ -z "$ACCEL" ]]; then
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) ACCEL=hvf ;;
        Linux-aarch64) [[ -w /dev/kvm ]] && ACCEL=kvm || ACCEL=tcg ;;
        *) ACCEL=tcg ;;
    esac
fi
case $ACCEL in
    hvf|kvm) CPU=host ;;
    tcg) CPU=max ;;
    *) echo "error: unknown accelerator $ACCEL" >&2; exit 2 ;;
esac

firmware() {
    local c
    for c in \
        "${URMQTT_FIRMWARE:-}" \
        "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-aarch64-code.fd" \
        /usr/share/qemu/edk2-aarch64-code.fd \
        /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
        /usr/share/AAVMF/AAVMF_CODE.fd; do
        [[ -n "$c" && -f "$c" ]] && { echo "$c"; return; }
    done
    echo "error: no aarch64 UEFI firmware found; set URMQTT_FIRMWARE" >&2
    exit 1
}
FW=$(firmware)

ARGS=(
    -machine "virt,gic-version=3,acpi=$ACPI"
    -accel "$ACCEL" -cpu "$CPU" -smp "$SMP" -m "$MEM"
    -bios "$FW"
    -drive "if=none,id=cd0,file=$ISO,format=raw,readonly=on,media=cdrom"
    -device virtio-scsi-pci,id=scsi0 -device scsi-cd,drive=cd0,bus=scsi0.0,bootindex=0
    -device virtio-rng-pci
    -device ramfb
    -display none -no-reboot
)
if [[ -n "$DATA" ]]; then
    ARGS+=(-drive "if=none,id=data0,file=$DATA,format=raw,cache=none" -device virtio-blk-pci,drive=data0)
fi
if [[ $NET -eq 1 ]]; then
    ARGS+=(-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:1883-:1883,hostfwd=tcp:127.0.0.1:8883-:8883"
           -device virtio-net-pci,netdev=n0)
    [[ -n "$PCAP" ]] && ARGS+=(-object "filter-dump,id=dump0,netdev=n0,file=$PCAP")
fi
if [[ -n "$SERIAL" ]]; then
    ARGS+=(-serial "file:$SERIAL" -monitor none)
elif [[ $HEADLESS -eq 1 ]]; then
    ARGS+=(-serial stdio -monitor none)
else
    ARGS+=(-serial mon:stdio)
fi
if [[ $GDB -eq 1 ]]; then
    ARGS+=(-s -S)
    echo "QEMU halted with a gdb stub on localhost:1234. Attach with:" >&2
    echo "  lldb target/aarch64-unknown-none/release/urmqtt -o 'gdb-remote localhost:1234'" >&2
    echo "  aarch64-elf-gdb target/aarch64-unknown-none/release/urmqtt -ex 'target remote :1234'" >&2
fi

exec qemu-system-aarch64 "${ARGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"}
