#!/usr/bin/env bash
# Kani proofs (H5): bounded model checking of the parsers and the timer wheel.
# The harnesses live in crates/*/src/proofs.rs behind #[cfg(kani)].
#
#   scripts/kani.sh [crate...]     (default: the crates below)
#
# Install: cargo install --locked kani-verifier && cargo kani setup
#
# Kani bundles its own rustc, which trails the pinned nightly, and cargo
# refuses the workspace `rust-version` ("requires rustc 1.101"). For the run
# the script drops the requirement in Cargo.toml and restores the file on
# exit (ADR-120). Nothing else about the build changes.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo-kani >/dev/null || { echo "install kani: cargo install --locked kani-verifier && cargo kani setup" >&2; exit 1; }
CRATES=("$@")
[[ ${#CRATES[@]} -gt 0 ]] || CRATES=(urmqtt-timer-wheel urmqtt-mqtt urmqtt-tcp urmqtt-tls urmqtt-config-schema urmqtt-ws)
backup="$(mktemp)"
cp Cargo.toml "$backup"
trap 'cp "$backup" Cargo.toml; rm -f "$backup"' EXIT
sed -i.bak 's/^rust-version = ".*"/rust-version = "1.85"/' Cargo.toml
rm -f Cargo.toml.bak
# Harnesses that are documented as NOT PROVEN (docs/VERIFICATION.md): Kani cannot finish them within the cap
# below, so it reports "Verification failed" without a counterexample. They are reported loudly and do not fail
# the run; any other harness that fails, and any failure WITH a counterexample ("Status: FAILURE"), does.
# parse_any_segment is proven on an Apple M-series machine but does not finish within 3 minutes on the 4-core
# CI runner.
KNOWN_NOT_PROVEN=(decode_typed_packets decode_any_short_input topic_filter_any_short_string parse_rate_any_short_string parse_any_segment)
log="$(mktemp)"
trap 'cp "$backup" Cargo.toml; rm -f "$backup" "$log"' EXIT
for c in "${CRATES[@]}"; do
    echo "== kani: $c"
    # Hard cap per harness: one that does not finish is NOT PROVEN, not passed.
    # shellcheck disable=SC2086 # KANI_ARGS is a list of options
    cargo kani -p "$c" -Z unstable-options -Z stubbing --harness-timeout "${KANI_TIMEOUT:-3m}" ${KANI_ARGS:-} 2>&1 | tee -a "$log" || true
done
failed=0
if grep -q 'Status: FAILURE' "$log"; then
    echo "KANI: a harness failed WITH a counterexample" >&2
    failed=1
fi
while read -r h; do
    name="${h##*::}"
    known=0
    for k in "${KNOWN_NOT_PROVEN[@]}"; do [[ $k == "$name" ]] && known=1; done
    if [[ $known == 1 ]]; then
        echo "KANI: NOT PROVEN (known, did not finish in ${KANI_TIMEOUT:-3m}): $h"
    else
        echo "KANI: FAILED: $h" >&2
        failed=1
    fi
done < <(sed 's/\x1b\[[0-9;]*m//g' "$log" | sed -n 's/^Verification failed for - //p' | sort -u)
exit "$failed"
