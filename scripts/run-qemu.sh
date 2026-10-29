#!/usr/bin/env bash
# shellcheck disable=SC2054  # QEMU option syntax uses commas inside one argument
# Boots an urMQTT ISO (or raw disk image) in QEMU (aarch64 virt, UEFI).
#
#   scripts/run-qemu.sh --iso ISO | --disk RAW [--accel hvf|tcg|kvm] [--smp N] [--mem 512M]
#                       [--data IMG] [--bus blk|scsi] [--cpu MODEL] [--gic 3|2] [--no-rng] [--acpi on|off] [--serial FILE] [--headless]
#                       [--pcap FILE] [--gdb] [--no-net] [--fwd HOST:GUEST,...]
#                       [-- extra qemu args]
#
# --disk boots the raw GPT image (mkraw.py) as a virtio-blk disk, like a
# KVM host or a cloud server would; the data disk is a second virtio-blk.
# --bus scsi attaches the boot disk and the data disk as scsi-hd LUNs on a
# virtio-scsi controller instead, as many clouds do.
# --gic 2 gives the guest a GICv2, as KVM does on a GIC-400 host such as
# the Raspberry Pi 4 and 5 (at most 8 CPUs).
# --fwd replaces the default port forwards (1883 and 8883 on 127.0.0.1);
# --fwd none disables them.
#
# Without --serial the serial console is on stdio. Ctrl-A X quits QEMU.
# Option ROMs are disabled (romfile=): no iPXE in the firmware, faster boot.
set -euo pipefail

ISO="" DISK="" BUS=blk CPU_MODEL="" GIC=3 RNG=1 ACCEL="" SMP=4 MEM=512M DATA="" ACPI=on SERIAL="" HEADLESS=0 PCAP="" GDB=0 NET=1
FWD="1883:1883,8883:8883"
EXTRA=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --iso) ISO=$2; shift 2 ;;
        --disk) DISK=$2; shift 2 ;;
        --bus) BUS=$2; shift 2 ;;
        --cpu) CPU_MODEL=$2; shift 2 ;;
        --gic) GIC=$2; shift 2 ;;
        --no-rng) RNG=0; shift ;;
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
        --fwd) FWD=$2; shift 2 ;;
        --) shift; EXTRA=("$@"); break ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -n "$DISK" ]]; then
    [[ -f "$DISK" ]] || { echo "error: disk image '$DISK' not found (run make raw)" >&2; exit 1; }
else
    [[ -f "$ISO" ]] || { echo "error: ISO '$ISO' not found (run make iso)" >&2; exit 1; }
fi

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
# e.g. --cpu neoverse-n1 (TCG): the Ampere Altra core, no RNDR, no PAC/BTI.
[[ -n "$CPU_MODEL" ]] && CPU=$CPU_MODEL

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
[[ $GIC == 2 || $GIC == 3 ]] || { echo "error: --gic 3|2" >&2; exit 2; }

ARGS=(
    -machine "virt,gic-version=$GIC,acpi=$ACPI"
    -accel "$ACCEL" -cpu "$CPU" -smp "$SMP" -m "$MEM"
    -bios "$FW"
    -device ramfb
    -display none -no-reboot
)
if [[ $RNG -eq 1 ]]; then
    ARGS+=(-device virtio-rng-pci,romfile=)
fi
[[ $BUS == blk || $BUS == scsi ]] || { echo "error: --bus blk|scsi" >&2; exit 2; }
if [[ -z "$DISK" || $BUS == scsi ]]; then
    ARGS+=(-device virtio-scsi-pci,id=scsi0,romfile=)
fi
if [[ -n "$DISK" ]]; then
    ARGS+=(-drive "if=none,id=boot0,file=$DISK,format=raw,cache=none")
    if [[ $BUS == scsi ]]; then
        ARGS+=(-device scsi-hd,drive=boot0,bus=scsi0.0,scsi-id=0,lun=0,bootindex=0)
    else
        ARGS+=(-device virtio-blk-pci,drive=boot0,bootindex=0,romfile=)
    fi
else
    ARGS+=(-drive "if=none,id=cd0,file=$ISO,format=raw,readonly=on,media=cdrom"
        -device scsi-cd,drive=cd0,bus=scsi0.0,bootindex=0)
fi
if [[ -n "$DATA" ]]; then
    ARGS+=(-drive "if=none,id=data0,file=$DATA,format=raw,cache=none")
    if [[ $BUS == scsi ]]; then
        ARGS+=(-device scsi-hd,drive=data0,bus=scsi0.0,scsi-id=1,lun=0)
    else
        ARGS+=(-device virtio-blk-pci,drive=data0,romfile=)
    fi
fi
if [[ $NET -eq 1 ]]; then
    NETDEV="user,id=n0"
    if [[ "$FWD" != none ]]; then
        IFS=, read -r -a pairs <<< "$FWD"
        for p in "${pairs[@]}"; do
            NETDEV+=",hostfwd=tcp:127.0.0.1:${p%%:*}-:${p##*:}"
        done
    fi
    ARGS+=(-netdev "$NETDEV" -device virtio-net-pci,netdev=n0,romfile=)
    [[ -n "$PCAP" ]] && ARGS+=(-object "filter-dump,id=dump0,netdev=n0,file=$PCAP")
else
    # Without this QEMU adds a default NIC (with an iPXE option ROM).
    ARGS+=(-nic none)
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
