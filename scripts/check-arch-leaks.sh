#!/usr/bin/env bash
# Fails if architecture-specific code appears outside its arch crate
# (ADR-040): inline or global assembly, AArch64 system-register names and
# accessors anywhere but crates/arch-aarch64, and x86 privileged
# instructions anywhere but crates/arch-x86_64.
#
# Comments are skipped (documentation may name registers); code, strings
# and attributes are not.
#
#   scripts/check-arch-leaks.sh            check the tree, exit 1 on a leak
#   scripts/check-arch-leaks.sh --self-test   prove every pattern fires
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Rule i: code matching PATTERNS[i] may only appear under ALLOWED[i].
AARCH64='^crates/arch-aarch64/'
X86='^crates/arch-x86_64/'
ANY_ARCH='^crates/arch-(aarch64|x86_64)/'
# Pure-computation assembly (no privileged or system instruction) may also
# live in its own leaf crates, cfg-gated by target_arch (ADR-130, ADR-131).
ASM_OK='^crates/(arch-(aarch64|x86_64)|nistz256|x25519)/'
PATTERNS=(
    '\basm!'
    '\bglobal_asm!'
    '\b(mrs|msr)\b'
    '_[Ee][Ll][0-3]\b'
    '\bdaif(set|clr)?\b'
    '(?i)tpidr'
    '\b(rdmsr|wrmsr)\b'
    '\bcr[0-4]\b'
    '\b(in|out)[bwl]?\s+(%?[ad]x|%al|\$?0x)'
    '\bcpuid\b'
)
# `msr` is also a plain identifier in x86 code (an MSR number), so the
# AArch64 system-register rule only polices code outside both arch crates.
ALLOWED=("$ASM_OK" "$ASM_OK" "$ANY_ARCH" "$AARCH64" "$AARCH64" "$AARCH64" "$X86" "$X86" "$X86" "$X86")
WHAT=(
    'inline assembly'
    'global assembly'
    'AArch64 system-register access'
    'AArch64 exception-level register name'
    'AArch64 interrupt mask (DAIF)'
    'AArch64 thread-pointer register'
    'x86 model-specific register access'
    'x86 control register'
    'x86 port I/O'
    'x86 CPUID'
)
SAMPLES=(
    'unsafe { core::arch::asm!("nop") };'
    'core::arch::global_asm!(".text");'
    'let v = read("mrs {}, cntvct_el0");'
    'let v = regs::ttbr1_el1();'
    'emit("msr daifset, #2");'
    'regs::set_tpidr_el1(0);'
    'emit("rdmsr");'
    'emit("mov {}, cr3");'
    'emit("outb %al, 0x80");'
    'emit("cpuid");'
)

# Prints `file:line: text` for code lines (not comments) matching $1 in the
# .rs files given on stdin, outside paths matching $2.
scan() {
    local re=$1 allowed=$2
    while IFS= read -r f; do
        [[ $f =~ $allowed ]] && continue
        perl -ne '
            BEGIN { $re = shift @ARGV; $f = shift @ARGV }
            next if m{^\s*//};
            s{//.*$}{};
            print "$f:$.: $_" if /$re/;
        ' "$re" "$f" "$f"
    done
}

files() {
    (cd "$ROOT" && git ls-files -- 'crates/*.rs' 'tools/*.rs' 'fuzz/*.rs')
}

check() {
    local leaks=0 i out
    for i in "${!PATTERNS[@]}"; do
        out=$(cd "$ROOT" && files | scan "${PATTERNS[$i]}" "${ALLOWED[$i]}")
        if [[ -n $out ]]; then
            echo "arch leak: ${WHAT[$i]} outside the arch crate (${ALLOWED[$i]}):" >&2
            echo "$out" >&2
            leaks=1
        fi
    done
    return $leaks
}

# One leaking line per rule must be found, the same line as a comment must
# not, and the same line inside the arch crate must not.
self_test() {
    local tmp i fails=0
    tmp=$(mktemp -d)
    mkdir -p "$tmp/crates/kernel/src" "$tmp/crates/arch-aarch64/src" "$tmp/crates/arch-x86_64/src"
    for i in "${!PATTERNS[@]}"; do
        printf '%s\n' "${SAMPLES[$i]}" >"$tmp/crates/kernel/src/leak.rs"
        printf '    // %s\n' "${SAMPLES[$i]}" >"$tmp/crates/kernel/src/comment.rs"
        printf 'x(); // %s\n' "${SAMPLES[$i]}" >>"$tmp/crates/kernel/src/comment.rs"
        printf '%s\n' "${SAMPLES[$i]}" >"$tmp/crates/arch-aarch64/src/ok.rs"
        printf '%s\n' "${SAMPLES[$i]}" >"$tmp/crates/arch-x86_64/src/ok.rs"
        if [[ -z $(echo crates/kernel/src/leak.rs | (cd "$tmp" && scan "${PATTERNS[$i]}" "${ALLOWED[$i]}")) ]]; then
            echo "self-test: '${WHAT[$i]}' missed: ${SAMPLES[$i]}" >&2
            fails=1
        fi
        if [[ -n $(echo crates/kernel/src/comment.rs | (cd "$tmp" && scan "${PATTERNS[$i]}" "${ALLOWED[$i]}")) ]]; then
            echo "self-test: '${WHAT[$i]}' fired on a comment" >&2
            fails=1
        fi
        local own=crates/arch-aarch64/src/ok.rs
        [[ ${ALLOWED[$i]} == "$X86" ]] && own=crates/arch-x86_64/src/ok.rs
        if [[ -n $(echo "$own" | (cd "$tmp" && scan "${PATTERNS[$i]}" "${ALLOWED[$i]}")) ]]; then
            echo "self-test: '${WHAT[$i]}' fired inside its own arch crate" >&2
            fails=1
        fi
    done
    rm -r "${tmp:?}"
    if [[ $fails == 0 ]]; then
        echo "check-arch-leaks self-test: ${#PATTERNS[@]} rules ok"
    fi
    return $fails
}

case "${1:-}" in
    --self-test) self_test ;;
    "") check && echo "check-arch-leaks: no architecture-specific code outside crates/arch-*" ;;
    *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
