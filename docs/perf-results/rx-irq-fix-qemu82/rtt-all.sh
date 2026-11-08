#!/usr/bin/env bash
cd /Users/aldo/dev/urMQTT-rxfix
for r in 1 2; do
  echo "== base #$r"; KTAG=base- build/rx/rtt.sh rtt2-base-$r auto 2>&1 | grep -E "^echo|^tls"
  echo "== auto #$r"; KTAG= build/rx/rtt.sh rtt2-auto-$r auto 2>&1 | grep -E "^echo|^tls"
  echo "== off #$r"; KTAG= build/rx/rtt.sh rtt2-off-$r off 2>&1 | grep -E "^echo|^tls"
done
echo DONE
