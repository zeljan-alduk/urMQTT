#!/usr/bin/env bash
# Makes the emulator's runtime files for the builder page's "Try in the emulator" (C1g, ADR-228):
# QEMU 8.2.0 with a TCG backend that emits WebAssembly (https://github.com/ktock/qemu-wasm, GPL-2.0),
# from the prebuilt files of the project's demo, checked against pinned SHA-256 sums, with one fix.
#
#   tools/builder/emulator/make-runtime.sh [OUT_DIR]        (default: build/emulator-runtime)
#
# 1. downloads the 5 upstream files from a pinned commit of ktock/qemu-wasm-demo-images and checks sha256
# 2. patches the wasm (4 bytes: x86 POPCNT is miscompiled by the upstream wasm TCG backend; the source-level
#    fix is qemu-wasm-ctpop-fix.patch, see SOURCE.txt) and the site must serve exactly this file
# 3. strips the 28 MB of DWARF/name sections (40.8 MB -> 12.4 MB)
# 4. splits the file_packager ROM bundle into plain files (SeaBIOS, VGA BIOS, ...)
# 5. writes .br/.gz siblings, which the web server sends with the matching Content-Encoding
# The result is OUT_DIR/qemu/ (not committed: it is a build output of someone else's source). bundle.mjs puts
# it into build/builder/emulator/<version>/ together with the page's loader. Needs: curl, python3, shasum,
# gzip, brotli (optional).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=${1:-$ROOT/build/emulator-runtime}
COMMIT=b7c549b5e6f4c376f76483a03e983214421434ad          # ktock/qemu-wasm-demo-images, 2025-08-28 "update images"
BASE=https://raw.githubusercontent.com/ktock/qemu-wasm-demo-images/$COMMIT/alpine-x86_64
DL=${URMQTT_EMU_DOWNLOADS:-$ROOT/build/emulator-download}   # upstream files are cached here
mkdir -p "$DL" "$OUT/qemu/roms"

fetch() { # name expected-sha256
    [ -f "$DL/$1" ] || curl -fsSL --retry 3 -o "$DL/$1" "$BASE/$1"
    echo "$2  $DL/$1" | shasum -a 256 -c - >/dev/null || { echo "sha256 mismatch for $1 (not the pinned upstream file)" >&2; rm -f "$DL/$1"; exit 1; }
}
fetch out.js                       dab94140dc2ea847181ba47ae4cbd759728e551d8fd9ba9de409711ed25eddcc
fetch qemu-system-x86_64.wasm      f53107a35029d676aa551cd00d042f4f65af39a89bf72464494321fafdf54191
fetch qemu-system-x86_64.worker.js 8efab02a9cb5ee63ced22e9853bce74cbb895d15a5fb3d5139fef855c50f62ea
fetch load-rom.js                  617e4dc685cb2cedada4844f097eb18a56cf0f8bbd4c4e2e9231b4f07d0d8a88
fetch load-rom.data                15de099e1363ceb13a31b9d11836337bab974f9460836449330b20c0534d06c9

cp "$DL/out.js" "$OUT/qemu/qemu-system-x86_64.js"
cp "$DL/qemu-system-x86_64.worker.js" "$OUT/qemu/qemu-system-x86_64.worker.js"
python3 -I "$HERE/patch_ctpop.py" "$DL/qemu-system-x86_64.wasm" "$DL/patched-full.wasm"
python3 -I "$HERE/strip_wasm.py" "$DL/patched-full.wasm" "$OUT/qemu/qemu-system-x86_64.wasm"
python3 -I "$HERE/extract_roms.py" "$DL/load-rom.js" "$DL/load-rom.data" "$OUT/qemu/roms" \
    bios-256k.bin vgabios-stdvga.bin kvmvapic.bin linuxboot_dma.bin

for f in qemu-system-x86_64.wasm qemu-system-x86_64.js qemu-system-x86_64.worker.js roms/bios-256k.bin; do
    gzip -9 -k -f "$OUT/qemu/$f"
    if command -v brotli >/dev/null; then brotli -q 11 -k -f "$OUT/qemu/$f"; fi
done
ls -l "$OUT/qemu" "$OUT/qemu/roms"
shasum -a 256 "$OUT/qemu/qemu-system-x86_64.wasm"
