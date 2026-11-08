#!/usr/bin/env bash
# repro.sh LABEL CONFIG(auto|off) : attack-app scenario against QEMU 8.2.2 TCG in Docker
set -u
ROOT=/Users/aldo/dev/urMQTT-rxfix; cd $ROOT
label=$1 mode=$2 P=28901 D=build/rx
img=$D/aa-${KTAG:-}$mode.raw
if [[ ! -f $img ]]; then
  extra=()
  if [[ $mode == off ]]; then
    awk '{ print } /^\[devices\]/ { print "virtio_net_interrupt = \"off\"" }' deploy/dev/config.toml > $D/off.toml
    extra=(--config $D/off.toml --config-root deploy/dev)
  fi
  scripts/mkiso.sh --kernel ${KERNEL:-target/aarch64-unknown-none/release/urmqtt} --out $img.iso --cmdline "serve log=info" --esp-out $img.esp ${extra[@]+"${extra[@]}"} >/dev/null
  python3 -I scripts/mkraw.py $img.esp $img >/dev/null; rm -f $img.iso
fi
log=$D/$label.log; rm -f $log
cp $img $D/$label.img; truncate -s 64m $D/$label.img
docker rm -f now13b-c-q82 >/dev/null 2>&1
docker run --rm --name now13b-c-q82 -v $ROOT:$ROOT -w $ROOT now13b-c-qemu82 bash -c "
URMQTT_FIRMWARE=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd scripts/run-qemu.sh --serial $log --disk $D/$label.img --accel tcg --headless --fwd 28900:8883 &
for i in \$(seq 300); do grep -aq 'net: dhcp lease 10.0.2.15' $log 2>/dev/null && break; sleep 0.5; done
A=$D/linux-target/release/urmqtt-attack; c='--port 28900 --certs deploy/dev'
{ for st in 'slowloris --stage tcp --clients 200 --duration 1' 'slowloris --stage tls --clients 200 --duration 1' 'slowloris --stage mqtt --clients 60 --duration 1' 'half-records'; do
  t0=\$(date +%s.%N); \$A \$st \$c; echo \"time: \$st \$(echo \"\$(date +%s.%N) - \$t0\" | bc) s\"; done; } > $log.client 2>&1
sleep 2; pkill qemu-system; sleep 1" >/dev/null 2>&1
echo "== $label"; grep -aE "receive wake-up|admission:|attack: slowloris|half-records|^time:" $log $log.client | sed 's/^[^:]*://' | cut -c1-160
grep -a "dataplane: core 0" $log | grep -oE "[0-9]+ frame\(s\) dispatched, [0-9]+ receive interrupt\(s\), [0-9]+ loop passes" | head -6
