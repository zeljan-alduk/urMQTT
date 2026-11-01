#!/usr/bin/env bash
# X11: install and start Mosquitto on a fresh Debian 13 VPS with the same TLS
# material as the urMQTT production image. Run as root ON the VPS, after
# copying this directory's files to /root/x11/:
#
#   /root/x11/ca.pem server.pem server.key     (deploy/prod)
#   /root/x11/urmqtt-x11.conf urmqtt-x11.acl   (scripts/mosquitto)
#
# It replaces /etc/mosquitto/mosquitto.conf (the Debian default keeps
# persistence on and logs to a file), raises the descriptor limit (the
# systemd default of 1024 would make Mosquitto the limit of the idle-capacity
# test, not the design) and prints the exact versions for docs/PERFORMANCE.md.
set -euo pipefail
X=/root/x11
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq mosquitto mosquitto-clients >/dev/null
systemctl stop mosquitto
install -d -o mosquitto -g mosquitto -m 750 /etc/mosquitto/certs
install -o mosquitto -g mosquitto -m 640 "$X/ca.pem" "$X/server.pem" "$X/server.key" /etc/mosquitto/certs/
install -o mosquitto -g mosquitto -m 640 "$X/urmqtt-x11.acl" /etc/mosquitto/urmqtt-x11.acl
{
    cat "$X/urmqtt-x11.conf"
    echo "# Debian service: pid file and the operator's \$SYS refresh"
    echo "pid_file /run/mosquitto/mosquitto.pid"
    echo "sys_interval 2"
} >/etc/mosquitto/mosquitto.conf
rm -f /etc/mosquitto/conf.d/*.conf
install -d /etc/systemd/system/mosquitto.service.d
printf '[Service]\nLimitNOFILE=1048576\n' >/etc/systemd/system/mosquitto.service.d/nofile.conf
systemctl daemon-reload
systemctl enable --now mosquitto
sleep 2
systemctl --no-pager --lines=5 status mosquitto || true
echo "--- versions"
(mosquitto -h 2>&1 || true) | head -1
dpkg -l mosquitto libssl3t64 openssl 2>/dev/null | awk '/^ii/{print $2, $3}'
uname -r
grep -m1 'model name' /proc/cpuinfo
echo "--- limits"
cat "/proc/$(pidof mosquitto | cut -d' ' -f1)/limits" | grep -i 'open files'
ss -ltn | grep 8883
