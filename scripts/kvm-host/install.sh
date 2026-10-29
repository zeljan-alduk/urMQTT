#!/usr/bin/env bash
# Installs urMQTT as a KVM guest on an aarch64 Debian-family host such as a
# Raspberry Pi 4/5 with 64-bit Raspberry Pi OS or Ubuntu (docs/DEPLOY.md).
#
#   sudo scripts/kvm-host/install.sh IMAGE.img [--data-size 8G] [--cpus 4] [--mem 2G]
#                                    [--net user|bridge:<bridge>] [--port 8883]
#
# IMAGE.img is the raw boot image (make raw / the release's .img). It becomes
# /var/lib/urmqtt/boot.img; re-running with a new image updates it. The data
# disk /var/lib/urmqtt/data.img is created blank once and never overwritten.
set -euo pipefail

IMG="" DATA_SIZE=8G CPUS=4 MEM=2G NET=user PORT=8883
while [[ $# -gt 0 ]]; do
    case $1 in
        --data-size) DATA_SIZE=$2; shift 2 ;;
        --cpus) CPUS=$2; shift 2 ;;
        --mem) MEM=$2; shift 2 ;;
        --net) NET=$2; shift 2 ;;
        --port) PORT=$2; shift 2 ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *) IMG=$1; shift ;;
    esac
done
[[ -f "$IMG" ]] || { echo "usage: sudo $0 IMAGE.img [options]" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }
[[ $(uname -m) == aarch64 ]] || { echo "error: needs an aarch64 (64-bit ARM) Linux host" >&2; exit 1; }
if [[ ! -e /dev/kvm ]]; then
    echo "error: /dev/kvm missing. On a Raspberry Pi use the 64-bit OS (its kernel has KVM)." >&2
    exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=/var/lib/urmqtt

if ! command -v qemu-system-aarch64 >/dev/null || [[ ! -f /usr/share/qemu-efi-aarch64/QEMU_EFI.fd ]]; then
    apt-get update
    apt-get install -y --no-install-recommends qemu-system-arm qemu-efi-aarch64
fi

# Host checks: report, do not guess.
if grep -q GICv2 /proc/interrupts; then
    echo "host: GICv2 interrupt controller (the guest gets a GICv2, at most 8 vCPUs)"
    (( CPUS <= 8 )) || { echo "error: --cpus $CPUS > 8 on a GICv2 host" >&2; exit 1; }
fi
host_mib=$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo)
case $MEM in
    *G) vm_mib=$(( ${MEM%G} * 1024 )) ;;
    *M) vm_mib=${MEM%M} ;;
    *) echo "error: --mem like 2G or 1536M" >&2; exit 2 ;;
esac
# The prod image reserves a 1 GiB kernel heap (memory.kernel_heap_mb).
(( vm_mib >= 1536 )) || echo "warning: --mem $MEM is below 1536M; the prod heap (1 GiB) needs more"
(( vm_mib + 512 <= host_mib )) || echo "warning: --mem $MEM leaves less than 512 MiB of the host's $host_mib MiB"

install -d -m 0750 "$DIR" /etc/urmqtt /usr/local/lib/urmqtt
install -m 0640 "$IMG" "$DIR/boot.img"
if [[ ! -e "$DIR/data.img" ]]; then
    truncate -s "$DATA_SIZE" "$DIR/data.img"
    chmod 0640 "$DIR/data.img"
    echo "data disk: $DIR/data.img ($DATA_SIZE, blank: urMQTT formats it on first boot)"
else
    echo "data disk: keeping $DIR/data.img"
fi
install -m 0755 "$HERE/urmqtt-vm.sh" /usr/local/lib/urmqtt/urmqtt-vm.sh
install -m 0644 "$HERE/urmqtt.service" /etc/systemd/system/urmqtt.service
cat >/etc/urmqtt/vm.conf <<EOF
# Read by /usr/local/lib/urmqtt/urmqtt-vm.sh; restart urmqtt after changes.
DIR=$DIR
CPUS=$CPUS
MEM=$MEM
NET=$NET
PORT=$PORT
EOF
if [[ $NET == bridge:* ]]; then
    br=${NET#bridge:}
    install -d /etc/qemu
    grep -qx "allow $br" /etc/qemu/bridge.conf 2>/dev/null || echo "allow $br" >>/etc/qemu/bridge.conf
fi

systemctl daemon-reload
systemctl enable urmqtt.service
systemctl restart urmqtt.service
echo "urmqtt: started. Log: journalctl -u urmqtt -f"
case $NET in
    user) echo "MQTT/TLS: port $PORT on this host's addresses (forward it on your router for access from outside)" ;;
    *) echo "MQTT/TLS: port 8883 on the VM's own DHCP address (see 'net: dhcp lease' in the log)" ;;
esac
