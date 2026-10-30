#!/usr/bin/env bash
# Miri on the host crates (H5): undefined behaviour, out-of-bounds access and
# aliasing violations in the sans-IO code. proptest and the model tests read
# the working directory and run many cases, so isolation is off and the case
# count is small: Miri is for the memory model, the fuzzers cover volume.
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
    cargo miri test -q -p "$c" --lib
done
