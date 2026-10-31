#!/usr/bin/env bash
# The host fault runner (STORAGE-PLAN section 4): for a procedure of the disk
# tool it loops N over every write, cuts the power after the N-th write (and,
# separately, tears the N-th), and checks after each case that the disk is
# valid, that finishing the procedure works and that no data was lost.
#
#   scripts/fault-loop.sh migrate [--tool PATH] [--keep]
#   scripts/fault-loop.sh grow    [--tool PATH] [--keep]
#
# migrate: a layout-v1 image with real broker state (devices, retained
#          messages, a session, 600 telemetry records) is migrated with the
#          device stopping after write N. Then the disk must be a valid v1 or
#          v2 disk (info), `migrate --resume` must finish it (verify, the
#          telemetry count), and `migrate --rollback --force` must return it
#          to layout v1 (and a new dry run must succeed).
# grow:    a migrated layout-v2 image on a larger disk is grown with the
#          device stopping after write N. Then at least one partition table
#          copy must be valid and the layout v1/v2 readable, and growing again
#          must finish, verify clean, with all 600 telemetry records.
#
# The cut is clean (the file has no volatile cache): the same as dropping
# the unflushed writes. The tests in tools/disk/tests/migrate.rs and
# crates/store/tests/grow.rs cover the torn and cache-applied variants; the
# tear variant here tears the N-th write after its first sector.
#
# Every case works on a copy; nothing outside $WORK is touched. Cap: the
# loop ends when the procedure completes without the fault firing, or after
# MAX cases (default 200).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROC=${1:-}
shift || true
TOOL="$ROOT/target/release/urmqtt-disk"
KEEP=0
MAX=${FAULT_LOOP_MAX:-200}
while [[ $# -gt 0 ]]; do
    case $1 in
        --tool) TOOL=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ $PROC == migrate || $PROC == grow ]] || { echo "usage: $0 migrate|grow [--tool PATH] [--keep]" >&2; exit 2; }
if [[ ! -x $TOOL ]]; then
    (cd "$ROOT" && cargo build --release --locked -q -p urmqtt-disk-tool)
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/urmqtt-fault-loop.XXXXXX")
[[ $KEEP == 1 ]] || trap 'rm -rf "$WORK"' EXIT
echo "fault-loop: $PROC, work dir $WORK"

# A dummy 1 MiB ESP is enough: the loop never boots the image.
head -c 1048576 /dev/zero >"$WORK/esp.img"
"$TOOL" create "$WORK/base.img" --esp "$WORK/esp.img" --size 64M 2>/dev/null
"$TOOL" fixture-v1 "$WORK/base.img" --populate --write 2>/dev/null
if [[ $PROC == grow ]]; then
    "$TOOL" migrate "$WORK/base.img" --write --rollback-file "$WORK/base.rb" >/dev/null
    truncate -s 192m "$WORK/base.img"
fi

fail() { echo "fault-loop: FAIL: $*" >&2; exit 1; }
count_records() { "$TOOL" export-telemetry "$1" --format jsonl 2>&1 >/dev/null | sed -n 's/.*export-telemetry: \([0-9]*\) record.*/\1/p'; }
want_records=600 # what `fixture-v1 --populate` writes

cases=0
completed=0
for variant in stop tear; do
    for ((n = 1; n <= MAX; n++)); do
        case $variant in
            stop) spec="stop-after-write=$n" ;;
            tear) spec="tear-write=$n:1" ;;
        esac
        img="$WORK/case.img"
        cp "$WORK/base.img" "$img"
        rm -f "$WORK/case.rb"
        if [[ $PROC == migrate ]]; then
            if "$TOOL" migrate "$img" --write --rollback-file "$WORK/case.rb" --fault "$spec" >/dev/null 2>&1; then
                completed=1
                echo "fault-loop: migrate completes with $((n - 1)) write(s) before the fault ($variant)"
                break
            fi
        else
            if "$TOOL" grow "$img" --write --fault "$spec" >/dev/null 2>&1; then
                completed=1
                echo "fault-loop: grow completes with $((n - 1)) write(s) before the fault ($variant)"
                break
            fi
        fi
        cases=$((cases + 1))
        info=$("$TOOL" info "$img" 2>&1) || fail "$spec: info failed: $info"
        # 1. A valid disk: one GPT copy valid, layout v1 or v2.
        grep -Eq 'primary valid|backup valid' <<<"$info" || fail "$spec: no valid partition table copy"
        grep -Eq 'data: layout v[12]' <<<"$info" || fail "$spec: neither a v1 nor a v2 layout: $(grep 'data:' <<<"$info")"
        if [[ $PROC == migrate ]]; then
            # 2. Finish.
            cp "$img" "$WORK/resume.img"
            if grep -q 'migration record' <<<"$info"; then
                "$TOOL" migrate "$WORK/resume.img" --resume --write >/dev/null 2>"$WORK/err" || fail "$spec: resume: $(cat "$WORK/err")"
            else
                "$TOOL" migrate "$WORK/resume.img" --write --rollback-file "$WORK/resume.rb" >/dev/null 2>"$WORK/err" || fail "$spec: migrate again: $(cat "$WORK/err")"
            fi
            "$TOOL" verify "$WORK/resume.img" >/dev/null 2>"$WORK/err" || fail "$spec: verify after resume: $(cat "$WORK/err")"
            [[ $(count_records "$WORK/resume.img") == "$want_records" ]] || fail "$spec: telemetry records after resume"
            rm -f "$WORK/resume.rb"
            # 3. Roll back.
            cp "$img" "$WORK/back.img"
            if grep -q 'migration record' <<<"$info"; then
                "$TOOL" migrate "$WORK/back.img" --rollback --force --write --rollback-file "$WORK/case.rb" >/dev/null 2>"$WORK/err" || fail "$spec: rollback: $(cat "$WORK/err")"
            fi
            after=$("$TOOL" info "$WORK/back.img" 2>&1) || fail "$spec: info after rollback"
            grep -q 'data: layout v1' <<<"$after" || fail "$spec: not v1 after rollback"
            "$TOOL" migrate "$WORK/back.img" >/dev/null 2>"$WORK/err" || fail "$spec: dry run after rollback: $(cat "$WORK/err")"
        else
            # 2. Grow again, without the fault.
            "$TOOL" grow "$img" --write >/dev/null 2>"$WORK/err" || fail "$spec: grow again: $(cat "$WORK/err")"
            "$TOOL" verify "$img" >/dev/null 2>"$WORK/err" || fail "$spec: verify after grow: $(cat "$WORK/err")"
            after=$("$TOOL" info "$img" 2>&1) || fail "$spec: info after grow"
            grep -q 'layout v2 generation 3' <<<"$after" || fail "$spec: not generation 3 after growing"
            [[ $(count_records "$img") == 600 ]] || fail "$spec: telemetry records after grow"
        fi
    done
    [[ $completed == 1 ]] || fail "the procedure never completed within $MAX writes"
    completed=0
done
echo "fault-loop: $PROC: $cases cases, every one a valid disk that finishes (and rolls back, for migrate): ok"
