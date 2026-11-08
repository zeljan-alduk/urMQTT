#!/usr/bin/env bash
# rtt.sh LABEL MODE: echo RTT under QEMU 8.2.2 TCG (idle gaps 50 ms, then back-to-back)
ROOT=/Users/aldo/dev/urMQTT-rxfix; cd $ROOT; D=build/rx; label=$1 mode=$2
img=$D/aa-${KTAG:-}$mode.raw; log=$D/$label.log
cp $img $D/$label.img; truncate -s 64m $D/$label.img
docker run --rm --name now13b-c-q82 -v $ROOT:$ROOT -w $ROOT now13b-c-qemu82 bash -c "
URMQTT_FIRMWARE=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd scripts/run-qemu.sh --serial $log --disk $D/$label.img --accel tcg --headless --fwd 28907:7,28900:8883 >/dev/null 2>&1 &
for i in \$(seq 300); do grep -aq 'net: dhcp lease 10.0.2.15' $log 2>/dev/null && break; sleep 0.5; done; sleep 3
python3 $D/echo-rtt.py 28907 100 0.05; python3 $D/echo-rtt.py 28907 300 0; python3 $D/conn-rate.py 28900 deploy/dev
pkill qemu-system; sleep 1"
