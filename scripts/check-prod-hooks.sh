#!/usr/bin/env bash
# Verifies that the dev-only test hooks of the H4 mitigations (hardtest.rs and
# the test words that start them) are not in a kernel built without the
# `selftest` feature, i.e. a production or bench image (ADR-172).
#
#   scripts/check-prod-hooks.sh KERNEL_ELF [DEV_KERNEL_ELF]
#
# With a dev kernel it also checks that the same strings ARE found there, so a
# renamed string cannot make the check pass for the wrong reason.
set -euo pipefail
prod=${1:?usage: $0 KERNEL_ELF [DEV_KERNEL_ELF]}
dev=${2:-}

# Text only the hooks print or parse, and the test key's bytes (little-endian
# "SECRETKE" and "Y_TEST_1", the first two words of hardtest::TEST_KEY).
strings_wanted=(
    "the second free was NOT detected"
    "the write after free was NOT detected"
    "the overflow was NOT detected"
    "the stack smash was NOT detected"
    "keyslab-zero:"
    "the fault with secrets did not happen"
    "test panic carrying a key"
    "worker-contain: "
    "worker-fault: "
)
count() { LC_ALL=C grep -c -a -F -- "$2" "$1" || true; }
fail=0
for s in "${strings_wanted[@]}"; do
    n=$(count "$prod" "$s")
    if [[ $n -ne 0 ]]; then
        echo "  ✗ found in the production kernel: $s"
        fail=1
    fi
    if [[ -n $dev ]]; then
        m=$(count "$dev" "$s")
        if [[ $m -eq 0 ]]; then
            echo "  ✗ not found in the dev kernel either (stale check?): $s"
            fail=1
        fi
    fi
done
# The test key as bytes.
key=$(printf 'EKTERCES')
if [[ $(count "$prod" "$key") -ne 0 ]]; then
    echo "  ✗ the test key is in the production kernel"
    fail=1
fi
if [[ -n $dev && $(count "$dev" "$key") -eq 0 ]]; then
    echo "  ✗ the test key is not in the dev kernel (stale check?)"
    fail=1
fi
if [[ $fail -eq 0 ]]; then
    echo "  ✓ prod-hooks-absent: ${#strings_wanted[@]} hook strings and the test key are not in $(basename "$prod")${dev:+ (all present in the dev kernel)}"
fi
exit $fail
