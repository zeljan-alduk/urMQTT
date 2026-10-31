#!/usr/bin/env bash
# Line coverage of fuzz targets (H5): grow a corpus for FUZZ_SECS seconds per
# target from fuzz/seeds, then replay it with `cargo fuzz coverage` and report
# the lines of the crate sources the target is about.
#
#   scripts/fuzz-coverage.sh [target...]       FUZZ_SECS=20 (default)
#   SEEDS_ONLY=1 scripts/fuzz-coverage.sh      only the committed seeds
#
# Needs cargo-fuzz and the llvm-tools component (rust-toolchain.toml). The
# corpus lives in $COV_DIR (default: a temp directory), never in the repo.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-fuzz >/dev/null || { echo "install cargo-fuzz: cargo install cargo-fuzz --locked" >&2; exit 1; }
FUZZ_SECS="${FUZZ_SECS:-20}"
COV_DIR="${COV_DIR:-$(mktemp -d)}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
LLVM_BIN="$(rustc --print sysroot)/lib/rustlib/$HOST/bin"
# source files the coverage of a target is reported for (bash 3.2: no maps)
src_of() {
    case "$1" in
        mqtt_decode) echo "crates/mqtt/src/decode.rs" ;;
        tcp_segment) echo "crates/tcp/src/wire.rs" ;;
        net_frame) echo "crates/net/src" ;;
        tls_record) echo "crates/tls/src/record.rs" ;;
        broker_input) echo "crates/broker/src/lib.rs crates/broker/src/acl.rs crates/broker/src/topics.rs" ;;
        config_parse) echo "crates/config-schema/src/lib.rs" ;;
    esac
}
TARGETS=("$@")
[[ ${#TARGETS[@]} -gt 0 ]] || TARGETS=(mqtt_decode tcp_segment net_frame tls_record broker_input config_parse)
printf '%-14s %10s %10s %8s\n' target lines covered percent
for t in "${TARGETS[@]}"; do
    corpus="$COV_DIR/$t"
    mkdir -p "$corpus"
    seeds=()
    [[ -d fuzz/seeds/$t ]] && seeds=("fuzz/seeds/$t")
    if [[ -z "${SEEDS_ONLY:-}" ]]; then
        cargo fuzz run "$t" "$corpus" ${seeds[@]+"${seeds[@]}"} -- -max_total_time="$FUZZ_SECS" >"$COV_DIR/$t.run.log" 2>&1 || {
            echo "$t: fuzz run failed, see $COV_DIR/$t.run.log" >&2
            continue
        }
    else
        [[ ${#seeds[@]} -eq 0 ]] || cp "${seeds[0]}"/* "$corpus"/
    fi
    cargo fuzz coverage "$t" "$corpus" >"$COV_DIR/$t.cov.log" 2>&1 || {
        echo "$t: coverage build failed, see $COV_DIR/$t.cov.log" >&2
        continue
    }
    # cargo-fuzz builds the instrumented binary under <target dir>/<host>/coverage/.
    bin="$(find target fuzz/target -type f -path "*/coverage/*/release/$t" 2>/dev/null | head -n1)"
    [[ -n "$bin" ]] || { echo "$t: instrumented binary not found" >&2; continue; }
    prof="fuzz/coverage/$t/coverage.profdata"
    # shellcheck disable=SC2086
    "$LLVM_BIN/llvm-cov" export -summary-only -instr-profile="$prof" "$bin" $(src_of "$t") >"$COV_DIR/$t.json"
    python3 - "$t" "$COV_DIR/$t.json" <<'PY'
import json, sys
t, path = sys.argv[1:3]
d = json.load(open(path))["data"][0]["files"]
lines = sum(f["summary"]["lines"]["count"] for f in d)
cov = sum(f["summary"]["lines"]["covered"] for f in d)
print(f"{t:<14} {lines:>10} {cov:>10} {100*cov/max(lines,1):>7.1f}%")
PY
done
echo "corpus and logs: $COV_DIR"
