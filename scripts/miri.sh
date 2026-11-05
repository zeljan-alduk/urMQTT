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
#   scripts/miri.sh [crate...]           (default: the crates below)
#   scripts/miri.sh --negative-control   Miri must REPORT the deliberate UB in
#                                        urmqtt-config (miri_negative_control);
#                                        this fails if it does not (ADR-262)
#
# The runner (ADR-262):
#   MIRI_RUNNER=nextest   one Miri process per test, MIRI_JOBS in parallel
#                         (`cargo miri nextest run`); the default when
#                         cargo-nextest is installed
#   MIRI_RUNNER=libtest   the old runner: one `cargo miri test` process per
#                         crate, the tests one after another on one core
#   MIRI_JOBS=N           nextest only: parallel tests (default 2; CI sets 4)
#   MIRI_PARTITION=count:K/N  nextest only: run this share of each crate's tests
# Both runners take the same skip lists below and run the same tests.
set -euo pipefail
cd "$(dirname "$0")/.."

NEG=0
if [[ ${1:-} == --negative-control ]]; then
    NEG=1
    shift
fi
CRATES=("$@")
[[ ${#CRATES[@]} -gt 0 ]] || CRATES=(urmqtt-mqtt urmqtt-timer-wheel urmqtt-net urmqtt-tcp urmqtt-broker urmqtt-tls urmqtt-cfg urmqtt-config)
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-disable-isolation}"
export PROPTEST_CASES="${PROPTEST_CASES:-6}" PROPTEST_DISABLE_FAILURE_PERSISTENCE=true
# cargo-miri's runner compiles the test crate again in every test process; with
# incremental compilation, parallel test processes race on the same session
# directory ("failed to move dependency graph"). CI sets 0 for every job anyway.
export CARGO_INCREMENTAL=0

RUNNER=${MIRI_RUNNER:-}
if [[ -z $RUNNER ]]; then
    if cargo nextest --version > /dev/null 2>&1; then RUNNER=nextest; else RUNNER=libtest; fi
fi
case "$RUNNER" in
    nextest | libtest) ;;
    *) echo "MIRI_RUNNER must be nextest or libtest, not '$RUNNER'" >&2; exit 2 ;;
esac
JOBS=${MIRI_JOBS:-2}
if [[ -n ${MIRI_PARTITION:-} && $RUNNER != nextest ]]; then
    echo "MIRI_PARTITION needs MIRI_RUNNER=nextest" >&2
    exit 2
fi
echo "== miri runner: $RUNNER$([[ $RUNNER == nextest ]] && echo " (-j $JOBS${MIRI_PARTITION:+, partition $MIRI_PARTITION})")"

# The skip list and the flags of one crate: sets `only` and `flags`.
selection() {
    only=()
    flags=$MIRIFLAGS
    case "$1" in
        # The configuration blob (C1): the decoder and the field table. The 20 000-case
        # garbage loop is the fuzz target's job.
        # PBKDF2 (passwd, ADR-229): every account hash runs at least 1000 iterations, and
        # Miri needs minutes per hash. The RFC vectors and the stored-form rules run
        # natively in `cargo test`; Miri keeps the cheap ones (long_keys, hmac). The tests
        # live in passwd::tests: until ADR-262 seven of these skips read `passwd::<name>`,
        # matched nothing, and those seven tests ran under Miri (most of the cfg job).
        urmqtt-cfg) only=(--skip tests::garbage_never_panics --skip passwd::tests::published_vectors --skip passwd::tests::encode_parse_verify_round_trip --skip passwd::tests::binary_and_long_passwords --skip passwd::tests::every_salt_and_iteration_changes_the_hash --skip passwd::tests::the_stored_form_is_strict --skip passwd::tests::the_decoy_costs --skip passwd::tests::debug_never_shows_the_key --skip plain::tests::user_entries --skip tests::plaintext_rules --skip tests::the_anonymous_identity --skip passwd::tests::rfc_7914_vectors --skip passwd::tests::encode_refuses_out_of_range_parameters) ;;
        # The loaded configuration lives in a write-once `.bss` arena (the one unsafe
        # module, ADR-216); its tests leak a few boxes on purpose.
        urmqtt-config) flags="$MIRIFLAGS -Zmiri-ignore-leaks" ;;
        # The scripted segment tests, cookies only (table::behaves_like_a_map_under_churn is too slow too). model:: (the
        # stateful proptest) and tests:: (loss, flood and retransmission
        # simulations) run for more than 25 minutes each under Miri; they run
        # natively in `cargo test`.
        # Skipped: compact:: (60 000-step loop), and the tests that insert
        # hundreds of retained messages or run 10 000 iterations.
        urmqtt-broker) only=(--skip compact:: --skip console_lines_are_replayed --skip clearing_retained_messages --skip unsubscribed_filters_leave --skip many_sessions_route --skip retained_per_device_limit --skip retained_byte_budget --skip hot_state_stays_small) ;;
        urmqtt-tcp) only=(cookie:: refused:: scripts:: seq:: siphash::) ;;
        # The TLS record layer, tickets, rng and the secret-capture table keep their Miri run.
        # provider:: (the P-256 and X25519 table arithmetic, X9/PERF work after H5), kat::, bench:: and
        # probe:: are heavy pure-arithmetic tests (the first one alone ran for 55 minutes under
        # Miri and took the job past its timeout); the crate is forbid(unsafe_code), the unsafe
        # assembly lives in urmqtt-nistz256/x25519, and all of these run natively in `cargo test`.
        urmqtt-tls) only=(--skip provider:: --skip kat:: --skip bench:: --skip probe::) ;;
    esac
}

# One crate's lib tests under Miri, with the chosen runner. Extra arguments go
# to the runner before the test filters.
run() {
    local c=$1
    shift
    selection "$c"
    if [[ $RUNNER == nextest ]]; then
        # --no-fail-fast: one report with every failing test; the exit status is still
        # non-zero on any failure. Every test is printed with its time (the profile).
        MIRIFLAGS=$flags cargo miri nextest run -p "$c" --lib -j "$JOBS" --no-fail-fast \
            --status-level pass --final-status-level slow \
            ${MIRI_PARTITION:+--partition "$MIRI_PARTITION"} "$@" -- ${only[@]+"${only[@]}"}
    else
        MIRIFLAGS=$flags cargo miri test -q -p "$c" --lib "$@" -- ${only[@]+"${only[@]}"}
    fi
}

if [[ $NEG == 1 ]]; then
    # The negative control: a use-after-free compiled only under Miri and #[ignore]d.
    # It must fail, and fail with Miri's own report; a pass, or a failure for any other
    # reason (no such test, a build error), fails this step.
    test=miri_negative_control::deliberate_use_after_free_must_be_reported
    echo "== miri negative control: $test (must be reported as UB)"
    selection urmqtt-config
    if [[ $RUNNER == nextest ]]; then
        cmd=(cargo miri nextest run -p urmqtt-config --lib -j 1 --run-ignored only --no-fail-fast -- --exact "$test")
    else
        cmd=(cargo miri test -p urmqtt-config --lib -- --ignored --exact "$test")
    fi
    if out=$(MIRIFLAGS=$flags "${cmd[@]}" 2>&1); then
        printf '%s\n' "$out"
        echo "FAIL: Miri did not report the deliberate use-after-free" >&2
        exit 1
    fi
    printf '%s\n' "$out" | grep -E 'Undefined Behavior|error:' | head -n 5 || true
    if ! grep -q 'Undefined Behavior' <<< "$out"; then
        printf '%s\n' "$out"
        echo "FAIL: the negative control failed, but not with Miri's undefined-behaviour report" >&2
        exit 1
    fi
    echo "ok: Miri reported the deliberate undefined behaviour"
    exit 0
fi

for c in "${CRATES[@]}"; do
    echo "== miri: $c"
    run "$c"
done
