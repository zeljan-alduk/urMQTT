#!/usr/bin/env bash
# pcap.sh LABEL MODE: 40 sequential stalled TCP connects, with a pcap
ROOT=/Users/aldo/dev/urMQTT-rxfix; cd $ROOT; D=build/rx; label=$1 mode=$2
img=$D/aa-${KTAG:-}$mode.raw; log=$D/$label.log
cp $img $D/$label.img; truncate -s 64m $D/$label.img; rm -f $log $log.pcap
docker run --rm --name now13b-c-q82 -v $ROOT:$ROOT -w $ROOT now13b-c-qemu82 bash -c "
URMQTT_FIRMWARE=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd scripts/run-qemu.sh --serial $log --disk $D/$label.img --accel tcg --headless --fwd 28900:8883 --pcap $log.pcap >/dev/null 2>&1 &
for i in \$(seq 300); do grep -aq 'net: dhcp lease 10.0.2.15' $log 2>/dev/null && break; sleep 0.5; done; sleep 2
t0=\$(date +%s.%N); $D/linux-target/release/urmqtt-attack slowloris --stage tcp --port 28900 --certs deploy/dev --clients 40 --duration 1; echo \"time \$(echo \"\$(date +%s.%N) - \$t0\" | bc)\"
pkill qemu-system; sleep 1"
