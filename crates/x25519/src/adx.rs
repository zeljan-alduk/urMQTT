//! Multiplication and squaring in GF(2^255 - 19) with MULX and ADCX/ADOX.
//!
//! Written for this crate. Operands are any four-limb values below 2^256;
//! the result is below 2^256 and congruent to the product (2^256 = 38).
//! Callers must have checked `bmi2` and `adx` (the `Backend::Adx` token).
//!
//! The product is formed row by row (`b[i] * a[0..4]` with two carry chains,
//! CF through ADCX and OF through ADOX), the 512-bit result is folded
//! `lo + 38 * hi` with the same two chains, and the last carry limb is
//! folded once more. No branches, no memory writes.

use core::arch::asm;

use crate::Fe;

/// `a * b`.
pub(crate) fn mul(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: `Backend::Adx` is only constructed when the CPU has BMI2 and
    // ADX. The block reads 32 bytes at each of `a` and `b` (valid `&Fe`) and
    // writes only registers, declared as outputs or clobbers; no stack use.
    unsafe {
        asm!(
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            // row 0
            "mov rdx, [rdi]",
            "mulx r9, r8, [rsi]",
            "mulx r10, rax, [rsi + 8]",
            "add r9, rax",
            "mulx r11, rax, [rsi + 16]",
            "adc r10, rax",
            "mulx r12, rax, [rsi + 24]",
            "adc r11, rax",
            "adc r12, 0",
            // row 1 (t1..t5)
            "mov rdx, [rdi + 8]",
            "xor eax, eax",
            "mulx rcx, rax, [rsi]",
            "adcx r9, rax",
            "adox r10, rcx",
            "mulx rcx, rax, [rsi + 8]",
            "adcx r10, rax",
            "adox r11, rcx",
            "mulx rcx, rax, [rsi + 16]",
            "adcx r11, rax",
            "adox r12, rcx",
            "mulx rcx, rax, [rsi + 24]",
            "adcx r12, rax",
            "adox r13, rcx",
            "adc r13, 0",
            // row 2 (t2..t6)
            "mov rdx, [rdi + 16]",
            "xor eax, eax",
            "mulx rcx, rax, [rsi]",
            "adcx r10, rax",
            "adox r11, rcx",
            "mulx rcx, rax, [rsi + 8]",
            "adcx r11, rax",
            "adox r12, rcx",
            "mulx rcx, rax, [rsi + 16]",
            "adcx r12, rax",
            "adox r13, rcx",
            "mulx rcx, rax, [rsi + 24]",
            "adcx r13, rax",
            "adox r14, rcx",
            "adc r14, 0",
            // row 3 (t3..t7)
            "mov rdx, [rdi + 24]",
            "xor eax, eax",
            "mulx rcx, rax, [rsi]",
            "adcx r11, rax",
            "adox r12, rcx",
            "mulx rcx, rax, [rsi + 8]",
            "adcx r12, rax",
            "adox r13, rcx",
            "mulx rcx, rax, [rsi + 16]",
            "adcx r13, rax",
            "adox r14, rcx",
            "mulx rcx, rax, [rsi + 24]",
            "adcx r14, rax",
            "adox r15, rcx",
            "adc r15, 0",
            // fold: t[0..4] += 38 * t[4..8]
            "mov edx, 38",
            "xor eax, eax",
            "mulx rcx, rax, r12",
            "adcx r8, rax",
            "adox r9, rcx",
            "mulx rcx, rax, r13",
            "adcx r9, rax",
            "adox r10, rcx",
            "mulx rcx, rax, r14",
            "adcx r10, rax",
            "adox r11, rcx",
            "mulx rcx, rax, r15",
            "adcx r11, rax",
            "mov eax, 0",
            "adcx rcx, rax",
            "adox rcx, rax",
            // top limb (<= 38) * 38 back into the low limbs
            "imul rcx, rcx, 38",
            "add r8, rcx",
            "adc r9, 0",
            "adc r10, 0",
            "adc r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            out("r8") r0,
            out("r9") r1,
            out("r10") r2,
            out("r11") r3,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(nostack, readonly, pure),
        );
    }
    [r0, r1, r2, r3]
}

/// `a * a`: the six cross products once, doubled, plus the four squares.
pub(crate) fn sqr(a: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as in `mul`; only `a` is read (32 bytes).
    unsafe {
        asm!(
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            // a0 * (a1, a2, a3) at positions 1.. (t1 = r9 .. t4 = r12)
            "mov rdx, [rsi]",
            "mulx r10, r9, [rsi + 8]",
            "mulx r11, rax, [rsi + 16]",
            "add r10, rax",
            "mulx r12, rax, [rsi + 24]",
            "adc r11, rax",
            "adc r12, 0",
            // a1 * (a2, a3)
            "mov rdx, [rsi + 8]",
            "mulx rcx, rax, [rsi + 16]",
            "add r11, rax",
            "adc r12, rcx",
            "adc r13, 0",
            "mulx rcx, rax, [rsi + 24]",
            "add r12, rax",
            "adc r13, rcx",
            "adc r14, 0",
            // a2 * a3
            "mov rdx, [rsi + 16]",
            "mulx rcx, rax, [rsi + 24]",
            "add r13, rax",
            "adc r14, rcx",
            // double t1..t6 into t7
            "add r9, r9",
            "adc r10, r10",
            "adc r11, r11",
            "adc r12, r12",
            "adc r13, r13",
            "adc r14, r14",
            "adc r15, r15",
            // add the squares
            "mov rdx, [rsi]",
            "mulx rcx, r8, rdx",
            "add r9, rcx",
            "mov rdx, [rsi + 8]",
            "mulx rcx, rax, rdx",
            "adc r10, rax",
            "adc r11, rcx",
            "mov rdx, [rsi + 16]",
            "mulx rcx, rax, rdx",
            "adc r12, rax",
            "adc r13, rcx",
            "mov rdx, [rsi + 24]",
            "mulx rcx, rax, rdx",
            "adc r14, rax",
            "adc r15, rcx",
            // fold: t[0..4] += 38 * t[4..8]
            "mov edx, 38",
            "xor eax, eax",
            "mulx rcx, rax, r12",
            "adcx r8, rax",
            "adox r9, rcx",
            "mulx rcx, rax, r13",
            "adcx r9, rax",
            "adox r10, rcx",
            "mulx rcx, rax, r14",
            "adcx r10, rax",
            "adox r11, rcx",
            "mulx rcx, rax, r15",
            "adcx r11, rax",
            "mov eax, 0",
            "adcx rcx, rax",
            "adox rcx, rax",
            "imul rcx, rcx, 38",
            "add r8, rcx",
            "adc r9, 0",
            "adc r10, 0",
            "adc r11, 0",
            "sbb rax, rax",
            "and eax, 38",
            "add r8, rax",
            in("rsi") a.as_ptr(),
            out("r8") r0,
            out("r9") r1,
            out("r10") r2,
            out("r11") r3,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(nostack, readonly, pure),
        );
    }
    [r0, r1, r2, r3]
}
