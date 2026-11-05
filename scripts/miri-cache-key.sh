#!/usr/bin/env bash
# The key of the Miri result cache (ADR-262): a SHA-256 over everything a
# green Miri run of these crates depends on. CI skips the run when a run with
# the same key already succeeded; any change to an input below changes the key.
#
#   scripts/miri-cache-key.sh crate...
#
# Inputs: the tracked files (contents and paths) of each crate and of every
# path dependency it builds with (normal, build and dev edges, transitively);
# the workspace manifest, Cargo.lock, .cargo/config.toml, rust-toolchain.toml;
# this script, scripts/miri.sh and scripts/gen-dev-certs.sh (the tests read the
# development certificates it generates); `rustc -vV`, `cargo miri --version`,
# the nextest version; MIRIFLAGS, PROPTEST_CASES, MIRI_RUNNER, MIRI_PARTITION;
# the machine architecture and OS.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -gt 0 ]] || { echo "usage: $0 crate..." >&2; exit 2; }

if command -v sha256sum > /dev/null 2>&1; then SHA=(sha256sum); else SHA=(shasum -a 256); fi

root=$(pwd -P)
# Every path package in the build graph prints as "name vX (/abs/path)".
dirs=()
while IFS= read -r d; do
    dirs+=("${d#"$root"/}")
done < <(for c in "$@"; do
    cargo tree -q --locked -p "$c" -e normal,build,dev --prefix none --format '{p}'
done | sed -n 's/.*(\(\/[^)]*\)).*/\1/p' | sort -u)
[[ ${#dirs[@]} -gt 0 ]] || { echo "no path packages found for: $*" >&2; exit 1; }

{
    echo "crates: $*"
    echo "dirs: ${dirs[*]}"
    # Tracked files only: build output and the generated certificates are not inputs.
    git ls-files -z -- "${dirs[@]}" Cargo.toml Cargo.lock .cargo/config.toml rust-toolchain.toml \
        scripts/miri.sh scripts/miri-cache-key.sh scripts/gen-dev-certs.sh .config/nextest.toml \
        | sort -z | xargs -0 "${SHA[@]}"
    rustc -vV
    cargo miri --version
    cargo nextest --version 2> /dev/null | head -n 1 || echo "no nextest"
    echo "MIRIFLAGS=${MIRIFLAGS:-}"
    echo "PROPTEST_CASES=${PROPTEST_CASES:-}"
    echo "MIRI_RUNNER=${MIRI_RUNNER:-}"
    echo "MIRI_PARTITION=${MIRI_PARTITION:-}"
    uname -sm
} | "${SHA[@]}" | cut -c1-64
