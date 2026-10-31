#!/usr/bin/env bash
# Miri on the host crates (H5): undefined behaviour, out-of-bounds access and
# aliasing violations in the sans-IO code. proptest and the model tests read
# the working directory and run many cases, so isolation is off and the case
# count is small: Miri is for the memory model, the fuzzers cover volume.
# Excluded (see docs/VERIFICATION.md): tcp model::tcp_against_the_model (too
# slow), net rss spread test (too slow), integration tests under tests/ (they
# need files, subprocesses or minutes of CPU), store (FFI to C SQLite: Miri
# cannot run C; `make sanitize` covers it), the kernel and arch crates.
#
#   scripts/miri.sh [crate...]     (default: the crates below)
set -euo pipefail
cd "$(dirname "$0")/.."
CRATES=("$@")
[[ ${#CRATES[@]} -gt 0 ]] || CRATES=(urmqtt-mqtt urmqtt-timer-wheel urmqtt-net urmqtt-tcp urmqtt-broker urmqtt-tls)
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-disable-isolation}"
export PROPTEST_CASES="${PROPTEST_CASES:-6}" PROPTEST_DISABLE_FAILURE_PERSISTENCE=true
for c in "${CRATES[@]}"; do
    echo "== miri: $c"
    only=()
    case "$c" in
        # The scripted segment tests, cookies only (table::behaves_like_a_map_under_churn is too slow too). model:: (the
        # stateful proptest) and tests:: (loss, flood and retransmission
        # simulations) run for more than 25 minutes each under Miri; they run
        # natively in `cargo test`.
        # Skipped: compact:: (60 000-step loop), and the tests that insert
        # hundreds of retained messages or run 10 000 iterations.
        urmqtt-broker) only=(--skip compact:: --skip console_lines_are_replayed --skip clearing_retained_messages --skip unsubscribed_filters_leave --skip many_sessions_route --skip retained_per_device_limit --skip retained_byte_budget --skip hot_state_stays_small) ;;
        urmqtt-tcp) only=(cookie:: refused:: scripts:: seq:: siphash::) ;;
    esac
    cargo miri test -q -p "$c" --lib -- ${only[@]+"${only[@]}"}
done
