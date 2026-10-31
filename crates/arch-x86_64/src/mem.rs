//! `memcpy`, `memmove` and `memset` for the x86_64 kernel (PERF, ADR-200).
//!
//! compiler_builtins' x86_64 versions run three `rep` instructions for every
//! call, whatever the size. A `rep movs` costs 20 to 30 cycles before it
//! moves a byte, so a 1-byte copy took about 60 cycles and the broker and
//! the TLS layer, which make dozens of small copies per record, spent 10 to
//! 45 % of their time in them (docs/DECISIONS.md, ADR-200).
//!
//! These versions are assembly with a path per size:
//!
//! | size            | how                                                          |
//! |-----------------|--------------------------------------------------------------|
//! | 0 to 3          | three byte moves (first, middle, last)                       |
//! | 4 to 7, 8 to 16 | two overlapping 4- or 8-byte moves (head and tail)           |
//! | 17 to 128       | 2, 4 or 8 overlapping 16-byte SSE2 moves (head and tail)     |
//! | above 128       | 64 bytes per iteration, destination 16-byte aligned          |
//! | 2 KiB and more  | `rep movsb`/`rep stosb` when the CPU has ERMS ([`set_fast_rep`]) |
//!
//! Every path up to 128 bytes loads everything before it stores anything, so
//! it is correct for overlapping `memmove` in both directions. Above that,
//! `copy` goes forward unless the destination starts inside the source (then
//! backward, from the end), and both loops keep the first and last 64 bytes
//! in registers and store them last.
//!
//! Only SSE2 registers (`xmm0` to `xmm8`) are used. The kernel is built
//! hard-float with SSE (ADR-042), its exception entry saves that state, and
//! it keeps no AVX state: AVX would be wrong here (ADR-042). Non-temporal
//! stores are not used (see ADR-200). The direction flag is clear on entry
//! (System V), and no instruction here sets it.
//!
//! The functions are `extern "C"` System V (rdi, rsi, rdx) and touch only
//! caller-saved registers.

#![allow(unsafe_code)]

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU8, Ordering};

/// Non-zero: `rep movsb` and `rep stosb` are fast for large blocks (CPUID
/// leaf 7 EBX bit 9, ERMS). Read by the assembly; the default is the SSE loop,
/// which is also what runs before CPUID is read.
static FAST_REP: AtomicU8 = AtomicU8::new(0);

/// Tells the large-block paths to use `rep movsb`/`rep stosb` (or not).
pub fn set_fast_rep(on: bool) {
    // Relaxed: a hint; either path is correct.
    FAST_REP.store(u8::from(on), Ordering::Relaxed);
}

/// Whether the large-block paths use `rep movsb`/`rep stosb`.
pub fn fast_rep() -> bool {
    FAST_REP.load(Ordering::Relaxed) != 0
}

/// Copies `n` bytes; the ranges may overlap (`memmove`; also `memcpy`).
///
/// # Safety
/// `src..src+n` readable, `dest..dest+n` writable.
#[unsafe(naked)]
pub unsafe extern "C" fn copy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    naked_asm!(
        "mov rax, rdi",
        "cmp rdx, 16",
        "ja 20f",
        "cmp rdx, 8",
        "jae 18f",
        "cmp rdx, 4",
        "jae 17f",
        "test rdx, rdx",
        "jz 19f",
        // 1 to 3 bytes: first, middle, last.
        "movzx ecx, byte ptr [rsi]",
        "mov r8, rdx",
        "shr r8, 1",
        "movzx r9d, byte ptr [rsi + r8]",
        "movzx r10d, byte ptr [rsi + rdx - 1]",
        "mov byte ptr [rdi], cl",
        "mov byte ptr [rdi + r8], r9b",
        "mov byte ptr [rdi + rdx - 1], r10b",
        "ret",
        // 4 to 7.
        "17:",
        "mov ecx, dword ptr [rsi]",
        "mov r8d, dword ptr [rsi + rdx - 4]",
        "mov dword ptr [rdi], ecx",
        "mov dword ptr [rdi + rdx - 4], r8d",
        "ret",
        // 8 to 16.
        "18:",
        "mov rcx, qword ptr [rsi]",
        "mov r8, qword ptr [rsi + rdx - 8]",
        "mov qword ptr [rdi], rcx",
        "mov qword ptr [rdi + rdx - 8], r8",
        "19:",
        "ret",
        // 17 to 32.
        "20:",
        "cmp rdx, 32",
        "ja 21f",
        "movups xmm0, xmmword ptr [rsi]",
        "movups xmm1, xmmword ptr [rsi + rdx - 16]",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + rdx - 16], xmm1",
        "ret",
        // 33 to 64.
        "21:",
        "cmp rdx, 64",
        "ja 22f",
        "movups xmm0, xmmword ptr [rsi]",
        "movups xmm1, xmmword ptr [rsi + 16]",
        "movups xmm2, xmmword ptr [rsi + rdx - 32]",
        "movups xmm3, xmmword ptr [rsi + rdx - 16]",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + 16], xmm1",
        "movups xmmword ptr [rdi + rdx - 32], xmm2",
        "movups xmmword ptr [rdi + rdx - 16], xmm3",
        "ret",
        // 65 to 128.
        "22:",
        "cmp rdx, 128",
        "ja 23f",
        "movups xmm0, xmmword ptr [rsi]",
        "movups xmm1, xmmword ptr [rsi + 16]",
        "movups xmm2, xmmword ptr [rsi + 32]",
        "movups xmm3, xmmword ptr [rsi + 48]",
        "movups xmm4, xmmword ptr [rsi + rdx - 64]",
        "movups xmm5, xmmword ptr [rsi + rdx - 48]",
        "movups xmm6, xmmword ptr [rsi + rdx - 32]",
        "movups xmm7, xmmword ptr [rsi + rdx - 16]",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + 16], xmm1",
        "movups xmmword ptr [rdi + 32], xmm2",
        "movups xmmword ptr [rdi + 48], xmm3",
        "movups xmmword ptr [rdi + rdx - 64], xmm4",
        "movups xmmword ptr [rdi + rdx - 48], xmm5",
        "movups xmmword ptr [rdi + rdx - 32], xmm6",
        "movups xmmword ptr [rdi + rdx - 16], xmm7",
        "ret",
        // Above 128: the destination starts inside the source (dest - src
        // below n, unsigned): copy backward.
        "23:",
        "mov rcx, rdi",
        "sub rcx, rsi",
        "cmp rcx, rdx",
        "jb 40f",
        "cmp rdx, 2048",
        "jb 24f",
        "cmp byte ptr [rip + {fast}], 0",
        "je 24f",
        "mov rcx, rdx",
        "rep movsb",
        "ret",
        // Forward, 64 bytes per iteration, destination aligned. The last and
        // first bytes are loaded first and stored last (memmove with the
        // destination below the source).
        "24:",
        "movups xmm4, xmmword ptr [rsi + rdx - 64]",
        "movups xmm5, xmmword ptr [rsi + rdx - 48]",
        "movups xmm6, xmmword ptr [rsi + rdx - 32]",
        "movups xmm7, xmmword ptr [rsi + rdx - 16]",
        "movups xmm0, xmmword ptr [rsi]",
        "lea r8, [rdi + rdx - 64]",
        "mov r10, rdi",
        "lea r9, [rdi + 16]",
        "and r9, -16",
        "mov rcx, r9",
        "sub rcx, rdi",
        "add rsi, rcx",
        "mov rdi, r9",
        ".p2align 4",
        "25:",
        "movups xmm1, xmmword ptr [rsi]",
        "movups xmm2, xmmword ptr [rsi + 16]",
        "movups xmm3, xmmword ptr [rsi + 32]",
        "movups xmm8, xmmword ptr [rsi + 48]",
        "movaps xmmword ptr [rdi], xmm1",
        "movaps xmmword ptr [rdi + 16], xmm2",
        "movaps xmmword ptr [rdi + 32], xmm3",
        "movaps xmmword ptr [rdi + 48], xmm8",
        "add rsi, 64",
        "add rdi, 64",
        "cmp rdi, r8",
        "jb 25b",
        "movups xmmword ptr [r8], xmm4",
        "movups xmmword ptr [r8 + 16], xmm5",
        "movups xmmword ptr [r8 + 32], xmm6",
        "movups xmmword ptr [r8 + 48], xmm7",
        "movups xmmword ptr [r10], xmm0",
        "ret",
        // Backward: the first 64 and the last 16 bytes are loaded first and
        // stored last; the end is aligned down to 16.
        "40:",
        "movups xmm4, xmmword ptr [rsi]",
        "movups xmm5, xmmword ptr [rsi + 16]",
        "movups xmm6, xmmword ptr [rsi + 32]",
        "movups xmm7, xmmword ptr [rsi + 48]",
        "movups xmm0, xmmword ptr [rsi + rdx - 16]",
        "lea r8, [rdi + rdx]",
        "lea r9, [rsi + rdx]",
        "mov r10, r8",
        "mov rcx, r8",
        "and rcx, 15",
        "sub r8, rcx",
        "sub r9, rcx",
        "lea r11, [rdi + 64]",
        ".p2align 4",
        "41:",
        "movups xmm1, xmmword ptr [r9 - 64]",
        "movups xmm2, xmmword ptr [r9 - 48]",
        "movups xmm3, xmmword ptr [r9 - 32]",
        "movups xmm8, xmmword ptr [r9 - 16]",
        "movaps xmmword ptr [r8 - 64], xmm1",
        "movaps xmmword ptr [r8 - 48], xmm2",
        "movaps xmmword ptr [r8 - 32], xmm3",
        "movaps xmmword ptr [r8 - 16], xmm8",
        "sub r9, 64",
        "sub r8, 64",
        "cmp r8, r11",
        "ja 41b",
        "movups xmmword ptr [rdi], xmm4",
        "movups xmmword ptr [rdi + 16], xmm5",
        "movups xmmword ptr [rdi + 32], xmm6",
        "movups xmmword ptr [rdi + 48], xmm7",
        "movups xmmword ptr [r10 - 16], xmm0",
        "ret",
        fast = sym FAST_REP,
    )
}

/// Fills `n` bytes at `dest` with the byte `c` (low 8 bits of `c`).
///
/// # Safety
/// `dest..dest+n` writable.
#[unsafe(naked)]
pub unsafe extern "C" fn set(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    naked_asm!(
        "mov rax, rdi",
        "movzx esi, sil",
        "mov r9, 0x0101010101010101",
        "imul rsi, r9",
        "cmp rdx, 16",
        "ja 20f",
        "cmp rdx, 8",
        "jae 18f",
        "cmp rdx, 4",
        "jae 17f",
        "test rdx, rdx",
        "jz 19f",
        "mov r8, rdx",
        "shr r8, 1",
        "mov byte ptr [rdi], sil",
        "mov byte ptr [rdi + r8], sil",
        "mov byte ptr [rdi + rdx - 1], sil",
        "ret",
        "17:",
        "mov dword ptr [rdi], esi",
        "mov dword ptr [rdi + rdx - 4], esi",
        "ret",
        "18:",
        "mov qword ptr [rdi], rsi",
        "mov qword ptr [rdi + rdx - 8], rsi",
        "19:",
        "ret",
        "20:",
        "movq xmm0, rsi",
        "punpcklqdq xmm0, xmm0",
        "cmp rdx, 32",
        "ja 21f",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + rdx - 16], xmm0",
        "ret",
        "21:",
        "cmp rdx, 64",
        "ja 22f",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + 16], xmm0",
        "movups xmmword ptr [rdi + rdx - 32], xmm0",
        "movups xmmword ptr [rdi + rdx - 16], xmm0",
        "ret",
        "22:",
        "cmp rdx, 128",
        "ja 23f",
        "movups xmmword ptr [rdi], xmm0",
        "movups xmmword ptr [rdi + 16], xmm0",
        "movups xmmword ptr [rdi + 32], xmm0",
        "movups xmmword ptr [rdi + 48], xmm0",
        "movups xmmword ptr [rdi + rdx - 64], xmm0",
        "movups xmmword ptr [rdi + rdx - 48], xmm0",
        "movups xmmword ptr [rdi + rdx - 32], xmm0",
        "movups xmmword ptr [rdi + rdx - 16], xmm0",
        "ret",
        "23:",
        "cmp rdx, 2048",
        "jb 24f",
        "cmp byte ptr [rip + {fast}], 0",
        "je 24f",
        "mov r8, rax",
        "mov eax, esi",
        "mov rcx, rdx",
        "rep stosb",
        "mov rax, r8",
        "ret",
        "24:",
        "lea r8, [rdi + rdx - 64]",
        "movups xmmword ptr [rdi], xmm0",
        "lea r9, [rdi + 16]",
        "and r9, -16",
        ".p2align 4",
        "25:",
        "movaps xmmword ptr [r9], xmm0",
        "movaps xmmword ptr [r9 + 16], xmm0",
        "movaps xmmword ptr [r9 + 32], xmm0",
        "movaps xmmword ptr [r9 + 48], xmm0",
        "add r9, 64",
        "cmp r9, r8",
        "jb 25b",
        "movups xmmword ptr [r8], xmm0",
        "movups xmmword ptr [r8 + 16], xmm0",
        "movups xmmword ptr [r8 + 32], xmm0",
        "movups xmmword ptr [r8 + 48], xmm0",
        "ret",
        fast = sym FAST_REP,
    )
}

/// The code compiler_builtins ran before ADR-200 (three `rep` instructions per
/// call), kept for the `memprof` build, which times both in one boot.
#[cfg(feature = "mem-baseline")]
pub mod baseline {
    use core::arch::asm;

    fn rep_param(dest: *mut u8, mut count: usize) -> (usize, usize, usize) {
        let pre = ((8 - (dest as usize & 7)) & 7).min(count);
        count -= pre;
        (pre, count >> 3, count & 7)
    }

    /// # Safety
    /// `src..src+n` readable, `dest..dest+n` writable; may overlap.
    pub unsafe fn copy(dest: *mut u8, src: *const u8, n: usize) {
        let delta = (dest as usize).wrapping_sub(src as usize);
        let (pre, q, tail) = rep_param(dest, n);
        if delta >= n {
            let (mut d, mut s) = (dest, src);
            // SAFETY: the caller's contract; forward `rep movs`.
            unsafe {
                asm!("rep movsb", inout("ecx") pre => _, inout("rdi") d => d,
                     inout("rsi") s => s, options(nostack, preserves_flags));
                asm!("rep movsq", inout("rcx") q => _, inout("rdi") d => d,
                     inout("rsi") s => s, options(nostack, preserves_flags));
                asm!("rep movsb", inout("ecx") tail => _, inout("rdi") d => _,
                     inout("rsi") s => _, options(nostack, preserves_flags));
            }
        } else {
            // SAFETY: the caller's contract; backward `rep movs` (std/cld).
            unsafe {
                asm!(
                    "std", "rep movsb", "sub rsi, 7", "sub rdi, 7", "mov rcx, {q:r}",
                    "rep movsq", "add rsi, 7", "add rdi, 7", "mov ecx, {pre:e}",
                    "rep movsb", "cld",
                    pre = in(reg) pre, q = in(reg) q,
                    inout("ecx") tail => _,
                    inout("rdi") dest.add(n - 1) => _,
                    inout("rsi") src.add(n - 1) => _,
                    options(nostack)
                );
            }
        }
    }

    /// # Safety
    /// `dest..dest+n` writable.
    pub unsafe fn set(dest: *mut u8, c: i32, n: usize) {
        let c = (c as u8) as u64 * 0x0101_0101_0101_0101;
        let (pre, q, tail) = rep_param(dest, n);
        let mut d = dest;
        // SAFETY: the caller's contract.
        unsafe {
            asm!("rep stosb", inout("ecx") pre => _, inout("rdi") d => d,
                 in("rax") c, options(nostack, preserves_flags));
            asm!("rep stosq", inout("rcx") q => _, inout("rdi") d => d,
                 in("rax") c, options(nostack, preserves_flags));
            asm!("rep stosb", inout("ecx") tail => _, inout("rdi") d => _,
                 in("rax") c, options(nostack, preserves_flags));
        }
    }
}

// The C symbols the compiler and `core` call. compiler_builtins' versions are
// weak, so these replace them. A `memprof` build defines its own (counting)
// ones that call `copy` and `set`.
#[cfg(all(target_os = "none", not(feature = "no-mem-symbols")))]
#[allow(suspicious_runtime_symbol_definitions)]
mod symbols {
    use core::arch::naked_asm;

    /// # Safety
    /// The C contract of `memcpy`.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub unsafe extern "C" fn memcpy(_dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8 {
        naked_asm!("jmp {copy}", copy = sym super::copy)
    }

    /// # Safety
    /// The C contract of `memmove`.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub unsafe extern "C" fn memmove(_dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8 {
        naked_asm!("jmp {copy}", copy = sym super::copy)
    }

    /// # Safety
    /// The C contract of `memset`.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub unsafe extern "C" fn memset(_dest: *mut u8, _c: i32, _n: usize) -> *mut u8 {
        naked_asm!("jmp {set}", set = sym super::set)
    }
}

#[cfg(test)]
mod tests;
