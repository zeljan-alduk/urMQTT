#!/usr/bin/env bash
# AddressSanitizer on the host test suites (H5), including the vendored SQLite
# amalgamation, the raw-disk VFS and the libc shims of the store crate, which
# the host build compiles with the host C compiler.
#
#   scripts/sanitize.sh [crate...]     (default: the crates below)
#
# - Rust code: -Zsanitizer=address (nightly). It needs an explicit --target so
#   build scripts and proc macros stay uninstrumented.
# - C code (SQLite): CFLAGS add ASan and UBSan (trapping: no UBSan runtime to link); the `cc` crate passes them on.
#   rustc has no UBSan for Rust code (Miri covers that, scripts/miri.sh), so
#   UBSan here means the C side.
# - detect_leaks is off on macOS (LeakSanitizer is not supported on arm64
#   Darwin); on Linux leak detection stays on.
set -euo pipefail
cd "$(dirname "$0")/.."
CRATES=("$@")
[[ ${#CRATES[@]} -gt 0 ]] || CRATES=(urmqtt-mqtt urmqtt-timer-wheel urmqtt-net urmqtt-tcp urmqtt-broker urmqtt-store urmqtt-config-schema)
HOST="$(rustc -vV | sed -n 's/^host: //p')"
export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address"
export CFLAGS="${CFLAGS:-} -fsanitize=address,undefined -fsanitize-trap=undefined -fno-omit-frame-pointer -g"
# A separate target directory: sanitised and plain objects must not mix.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/sanitize}"
case "$HOST" in
    *apple-darwin)
        export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}"
        # Apple clang instruments C with a call to a version-check symbol
        # that only Apple's own runtime defines; rustc links the LLVM
        # runtime (same ABI), which has no such symbol. Define it as a no-op.
        mkdir -p "$CARGO_TARGET_DIR"
        probe="$CARGO_TARGET_DIR/asan-probe"
        printf 'int f(int *p) { return *p; }\n' > "$probe.c"
        clang -c -fsanitize=address "$probe.c" -o "$probe.o"
        sym="$(nm -u "$probe.o" | sed -n 's/^_*\(__asan_version_mismatch_check_[A-Za-z0-9_]*\)$/\1/p' | head -n1)"
        if [[ -n "$sym" ]]; then
            printf 'void %s(void) {}\n' "$sym" > "$probe-stub.c"
            clang -c "$probe-stub.c" -o "$probe-stub.o"
            export RUSTFLAGS="$RUSTFLAGS -Clink-arg=$PWD/$probe-stub.o"
        fi
        ;;
    *) export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}" ;;
esac
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"
# The model tests run many cases; the sanitiser slows each by 2-3x.
export PROPTEST_CASES="${PROPTEST_CASES:-32}" PROPTEST_DISABLE_FAILURE_PERSISTENCE=true
for c in "${CRATES[@]}"; do
    echo "== asan+ubsan(C): $c"
    cargo test -q --target "$HOST" -p "$c"
done
