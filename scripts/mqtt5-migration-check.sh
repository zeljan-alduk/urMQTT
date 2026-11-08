#!/usr/bin/env bash
# shellcheck disable=SC2015 # `cond && say ok || say FAILED` is intended: say only prints, never fails
# Store schema N -> N+1 on a real disk (ADR-274: 3 -> 4; ADR-275: 4 -> 5): a
# data disk written by an older kernel (e.g. main before the change) is booted
# by this one.
#
#   scripts/mqtt5-migration-check.sh OLD_KERNEL [--from N] [--port PORT] [--accel hvf|tcg] [--work DIR]
#
# --from: the schema the old kernel writes (default 4, the schema before
# MQTT 5.0 part 3; 3 for a kernel from before part 2).
#
# 1. The old kernel serves a fresh disk (one per client script); its own era's clients leave state:
#    qos2-scenarios.py phase 1 (QoS 2 flows in the middle of every step, a
#    queue) and mqtt-persist.py phase 1 (a retained message, a persistent
#    session with a queued QoS 1 command); QEMU is killed (SIGKILL).
# 2. The disk's boot partition gets this tree's kernel (the data partition
#    kept, as an offline kernel update does); it boots, migrates the database
#    (`schema vN+1 (from vN)`), restores the sessions, and the phase 2 clients
#    find every flow, the queue and the retained message.
# 3. urmqtt-disk verify and export-db read the migrated disk; the exported
#    database has the new schema's columns (4: expiry and options; 5: the
#    Subscription Identifier) and the old sessions.
# Prints "check: <name> ok|FAILED" lines; exits non-zero on a failure.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OLD=$1
shift
PORT=48883
ACCEL=hvf
WORK=${TMPDIR:-/tmp}/urmqtt-mqtt5-migration
FROM=4
while [[ $# -gt 0 ]]; do
    case $1 in
        --from) FROM=$2; shift 2 ;;
        --port) PORT=$2; shift 2 ;;
        --accel) ACCEL=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        *) echo "unknown argument $1" >&2; exit 2 ;;
    esac
done
TO=$((FROM + 1))
NEW="$ROOT/target/aarch64-unknown-none/release/urmqtt"
D="$ROOT/deploy/dev"
mkdir -p "$WORK"
rm -f "$WORK"/*.log
fails=0
say() { echo "check: $1 $2"; [[ $2 == ok ]] || fails=$((fails + 1)); }

img() { # img <kernel> <name>
    "$ROOT/scripts/mkiso.sh" --kernel "$1" --out "$WORK/$2.iso" --cmdline "serve" --esp-out "$WORK/$2.esp" >/dev/null
    python3 -I "$ROOT/scripts/mkraw.py" "$WORK/$2.esp" "$WORK/$2.raw" >/dev/null
}
img "$OLD" old
img "$NEW" new

boot() { # boot <disk> <log>
    "$ROOT/scripts/run-qemu.sh" --serial "$2" --headless --disk "$1" --accel "$ACCEL" \
        --fwd "$PORT:8883" >"$2.qemu" 2>&1 &
    VM=$!
    local i
    for ((i = 0; i < 1500; i++)); do
        grep -aq "net: dhcp lease 10.0.2.15" "$2" 2>/dev/null && return 0
        kill -0 "$VM" 2>/dev/null || return 1
        sleep 0.2
    done
    return 1
}
stop() { kill -9 "$VM" 2>/dev/null || true; wait "$VM" 2>/dev/null || true; }
trap stop EXIT

(cd "$ROOT" && cargo build -q --locked -p urmqtt-disk-tool)
ud="$ROOT/target/debug/urmqtt-disk"

# One old disk per client script (both use device-002).
for case in qos2 persist; do
    disk="$WORK/$case.img"
    cp "$WORK/old.raw" "$disk"
    truncate -s 64m "$disk"
    case $case in
        qos2) cmd=(python3 -I "$ROOT/scripts/qos2-scenarios.py" "$PORT" --tls "$D" --phase) ;;
        persist) cmd=(python3 -I "$ROOT/scripts/mqtt-persist.py" "$PORT" --tls "$D" --phase) ;;
    esac
    # 1. The old kernel leaves its state.
    boot "$disk" "$WORK/$case-old.log"
    "${cmd[@]}" 1 >"$WORK/$case-old.client" 2>&1 || true
    sleep 1
    stop
    grep -aq "schema v$FROM (from v0)" "$WORK/$case-old.log" && say "$case: old-kernel-wrote-schema-$FROM" ok || say "$case: old-kernel-wrote-schema-$FROM" FAILED
    grep -q "FAILED" "$WORK/$case-old.client" && say "$case: old-kernel-phase-1" FAILED || say "$case: old-kernel-phase-1" ok
    # 2. This kernel on the same disk (the ESP starts at 1 MiB in every image).
    dd if="$WORK/new.esp" of="$disk" bs=1048576 seek=1 conv=notrunc status=none
    boot "$disk" "$WORK/$case-new.log"
    "${cmd[@]}" 2 >"$WORK/$case-new.client" 2>&1 || true
    stop
    grep -a "db: sqlite\|db: restored" "$WORK/$case-new.log" | sed 's/^/  /'
    sed 's/^/  /' "$WORK/$case-new.client"
    grep -aq "schema v$TO (from v$FROM)" "$WORK/$case-new.log" && say "$case: migrated-at-boot" ok || say "$case: migrated-at-boot" FAILED
    grep -aqE "db: restored [0-9]+ retained message\(s\), [1-9][0-9]* persistent session\(s\)" "$WORK/$case-new.log" \
        && say "$case: sessions-restored" ok || say "$case: sessions-restored" FAILED
    if grep -q "ok" "$WORK/$case-new.client" && ! grep -q "FAILED" "$WORK/$case-new.client"; then
        say "$case: phase-2-on-the-new-kernel" ok
    else
        say "$case: phase-2-on-the-new-kernel" FAILED
    fi
    grep -aqE "EXCEPTION|PANIC" "$WORK/$case-new.log" && say "$case: no-fault" FAILED || say "$case: no-fault" ok
    # 3. The host tool on the migrated disk.
    "$ud" verify "$disk" >"$WORK/$case-verify.out" 2>&1 && say "$case: disk-verify" ok || say "$case: disk-verify" FAILED
    grep -E "sqlite|verify:" "$WORK/$case-verify.out" | sed 's/^/  /'
    rm -f "$WORK/$case.db"
    "$ud" export-db "$disk" "$WORK/$case.db" >/dev/null 2>&1 && say "$case: disk-export-db" ok || say "$case: disk-export-db" FAILED
    if command -v sqlite3 >/dev/null; then
        v=$(sqlite3 "$WORK/$case.db" "PRAGMA user_version")
        cols=$(sqlite3 "$WORK/$case.db" "SELECT group_concat(name) FROM pragma_table_info('sessions')")
        subcols=$(sqlite3 "$WORK/$case.db" "SELECT group_concat(name) FROM pragma_table_info('subscriptions')")
        echo "  export: user_version $v, sessions columns $cols, subscriptions columns $subcols"
        ok=1
        [[ $v == "$TO" && $cols == *expiry_s* && $cols == *offline_since* && $subcols == *options* ]] || ok=0
        if (( TO >= 5 )); then
            [[ $subcols == *sub_id* && $(sqlite3 "$WORK/$case.db" "SELECT count(*) FROM subscriptions WHERE sub_id != 0") == 0 ]] || ok=0
        fi
        ((ok)) && say "$case: export-has-schema-$TO" ok || say "$case: export-has-schema-$TO" FAILED
    fi
done
echo "migration-check: $fails failure(s); logs in $WORK"
exit $((fails > 0))
