#!/usr/bin/env bash
# Builds the web builder (C1e, ADR-220..222) into build/builder/:
#
#   urmqtt-cfg<N>.wasm   the WebAssembly module for configuration format N
#   app.js, app.css      the page's script and style (sources in tools/builder/web/src)
#   index.html           a standalone page (for local use and the browser tests);
#                        the aldo.tech site wraps the same app in its own template
#   i18n/<lang>.json     the page's texts, one file per site language
#
#   tools/builder/build.sh [--wasm-only]
#
# Needs the wasm32 target (`rustup target add wasm32-unknown-unknown`); there is
# no npm and no bundler: the script concatenates the ES modules of
# tools/builder/web/src in dependency order and strips their import/export
# keywords (tools/builder/web/bundle.mjs).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$ROOT/build/builder
CARGO=${CARGO:-cargo}
FORMAT=$(sed -n 's/^pub const FORMAT_VERSION: u16 = \([0-9]*\);.*/\1/p' "$ROOT/crates/cfg/src/blob.rs")
[[ -n "$FORMAT" ]] || { echo "build.sh: cannot read FORMAT_VERSION" >&2; exit 1; }

command -v rustup >/dev/null && ! rustup target list --installed | grep -q '^wasm32-unknown-unknown$' && {
    echo "build.sh: install the target first: rustup target add wasm32-unknown-unknown" >&2
    exit 1
}

mkdir -p "$OUT"
(cd "$ROOT" && "$CARGO" build --locked --profile wasm --target wasm32-unknown-unknown -p urmqtt-builder-wasm)
cp "$ROOT/target/wasm32-unknown-unknown/wasm/urmqtt_builder_wasm.wasm" "$OUT/urmqtt-cfg$FORMAT.wasm"
printf 'builder: %s (%s bytes)\n' "$OUT/urmqtt-cfg$FORMAT.wasm" "$(wc -c < "$OUT/urmqtt-cfg$FORMAT.wasm" | tr -d ' ')"

[[ ${1:-} == --wasm-only ]] && exit 0
command -v node >/dev/null || { echo "build.sh: node is needed to assemble the page" >&2; exit 1; }
node "$ROOT/tools/builder/web/bundle.mjs" "$OUT"
