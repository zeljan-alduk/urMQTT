#!/usr/bin/env bash
# The multiqueue A/B on the local rig (ADR-314, PERFORMANCE.md section 14), run
# inside the urmqtt-mq-rig container from the repository root:
#
#   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD:$PWD" -w "$PWD" \
#       urmqtt-mq-rig docs/perf-results/next6-mq/bench.sh ROUNDS SECONDS
#
# Images (built on the host, see section 14): build/mqbench/a-auto.raw and
# a-single.raw, the same aarch64 kernel and static configuration, the second
# with devices.virtio_net_queues = "single", both booted with
# "serve log=info limits=bench" on the same 4-queue tap with 4 vCPUs. Each
# round runs both, alternating, and keeps the serial logs.
set -u
ROUNDS=${1:-2} SECS=${2:-15}
LG=build/linux-target/release/urmqtt-loadgen
for r in $(seq 1 "$ROUNDS"); do
    for v in auto single; do
        log=build/mqbench/a-$v-$r.log
        echo "== $v round $r (load $(cut -d' ' -f1-3 /proc/loadavg))"
        scripts/mq-rig.sh --arch aarch64 --disk "build/mqbench/a-$v.raw" --smp 4 --queues 4 --rounds 1 \
            --bench "$SECS" --loadgen "$LG" --log "$log" >/dev/null 2>&1
        grep -a "^client: RESULT" "$log" | cut -c1-400
        grep -aE "net: (multiqueue|one queue pair)" "$log" | cut -c17-120
        grep -aE "dataplane: core [0-9]: busy" "$log" | sed -E 's/^\[ *([0-9.]+)\] INFO  /\1 /' | cut -c1-140
    done
done
