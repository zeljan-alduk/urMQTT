#!/usr/bin/env bash
# shellcheck disable=SC2054  # QEMU option syntax uses commas inside one argument
# Runs the urMQTT VM on an aarch64 Linux KVM host (Raspberry Pi 4/5 or any
# other board or server). Started by urmqtt.service; reads /etc/urmqtt/vm.conf.
#
#   urmqtt-vm.sh [--dry-run]
#
# The serial console goes to stdout, so `journalctl -u urmqtt` is the log.
# `gic-version=host` gives the guest the host's GIC: a GICv2 on a GIC-400
# board such as the Raspberry Pi, a GICv3 elsewhere; urMQTT drives both.
set -euo pipefail

CONF=${URMQTT_CONF:-/etc/urmqtt/vm.conf}
# Defaults; vm.conf overrides them.
DIR=/var/lib/urmqtt
CPUS=4
MEM=2G
NET=user          # "user" (port forward on the host) or "bridge:<bridge>"
PORT=8883         # host port forwarded to the broker (NET=user)
# shellcheck source=/dev/null
[[ -f "$CONF" ]] && . "$CONF"

firmware() {
    local c
    for c in "${FIRMWARE:-}" /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd \
        /usr/share/edk2/aarch64/QEMU_EFI.fd /usr/share/qemu/edk2-aarch64-code.fd; do
        [[ -n "$c" && -f "$c" ]] && { echo "$c"; return; }
    done
    echo "error: no aarch64 UEFI firmware (apt install qemu-efi-aarch64)" >&2
    exit 1
}

# One disk: the boot image with its data partition (single-disk model).
[[ -f "$DIR/disk.img" ]] || { echo "error: $DIR/disk.img missing (run install.sh)" >&2; exit 1; }

case $NET in
    user) NETDEV="user,id=n0,hostfwd=tcp::$PORT-:8883" ;;
    bridge:?*) NETDEV="bridge,id=n0,br=${NET#bridge:}" ;;
    *) echo "error: NET must be user or bridge:<name>, not '$NET'" >&2; exit 1 ;;
esac

ARGS=(
    -machine virt,gic-version=host -accel kvm -cpu host -smp "$CPUS" -m "$MEM"
    -bios "$(firmware)"
    -nodefaults -display none -monitor none -serial stdio
    -device virtio-rng-pci,romfile=
    -drive "if=none,id=disk0,file=$DIR/disk.img,format=raw,cache=none,aio=threads"
    -device virtio-blk-pci,drive=disk0,bootindex=0,romfile=
    -netdev "$NETDEV" -device virtio-net-pci,netdev=n0,romfile=
)

if [[ ${1:-} == --dry-run ]]; then
    printf '%q ' qemu-system-aarch64 "${ARGS[@]}"
    echo
    exit 0
fi
[[ -w /dev/kvm ]] || { echo "error: /dev/kvm is not available (a 64-bit kernel with KVM is needed)" >&2; exit 1; }
exec qemu-system-aarch64 "${ARGS[@]}"
