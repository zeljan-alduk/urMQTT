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
[[ ${#CRATES[@]} -gt 0 ]] || CRATES=(urmqtt-timer-wheel urmqtt-mqtt urmqtt-tcp urmqtt-tls urmqtt-config-schema)
backup="$(mktemp)"
cp Cargo.toml "$backup"
trap 'cp "$backup" Cargo.toml; rm -f "$backup"' EXIT
sed -i.bak 's/^rust-version = ".*"/rust-version = "1.85"/' Cargo.toml
rm -f Cargo.toml.bak
for c in "${CRATES[@]}"; do
    echo "== kani: $c"
    # Hard cap per harness: one that does not finish is NOT PROVEN, not passed.
    cargo kani -p "$c" -Z unstable-options --harness-timeout "${KANI_TIMEOUT:-3m}" ${KANI_ARGS:-} || failed=1
done
exit "${failed:-0}"
