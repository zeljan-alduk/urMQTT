//! Deliberate faults for the `test=` boot scenarios: each executes an
//! instruction the hardware must trap.

#![allow(unsafe_code)]

/// `brk` immediate the kernel's handler treats as "report and resume".
pub const BRK_RESUME: u16 = 0x5155;

/// Encoding of `ret`, the code `test=exec-heap` places in a heap buffer.
pub const RET_INSN: u32 = 0xd65f_03c0;

/// Size of the instruction the resumable breakpoint skips.
pub const BRK_LEN: u64 = 4;

/// Executes the resumable `brk`.
pub fn breakpoint() {
    // SAFETY: the handler recognises this immediate and skips it.
    unsafe { core::arch::asm!("brk #0x5155", options(nomem, nostack)) };
}

/// Executes a permanently undefined instruction.
pub fn undefined_instruction() {
    // SAFETY: deliberately faulting instruction in test mode.
    unsafe { core::arch::asm!("udf #0", options(nomem, nostack)) };
}

// SAFETY: both symbols are defined by the assembly below with these C
// signatures (no arguments, result in x0).
unsafe extern "C" {
    fn urmqtt_pac_violation() -> u64;
    fn urmqtt_bti_violation() -> u64;
}

core::arch::global_asm!(
    ".text",
    // Authenticates an unsigned return address: FEAT_FPAC traps on
    // `autiasp`, otherwise the poisoned address faults on `ret`.
    ".global urmqtt_pac_violation",
    "urmqtt_pac_violation:",
    "mov x9, x30",
    "adr x30, 1f",
    "hint #29", // autiasp
    "ret",
    "1: mov x30, x9",
    "mov x0, #1",
    "ret",
    // Indirect branch to an instruction that is not a BTI landing pad.
    ".global urmqtt_bti_violation",
    "urmqtt_bti_violation:",
    "adr x16, 2f",
    "br x16",
    "2: mov x0, #1",
    "ret",
);

/// Returns through a forged (unsigned) return address. Returns true only
/// if pointer authentication failed to detect it.
pub fn forged_return() -> bool {
    // SAFETY: test mode; returns only if PAC failed to detect the forgery.
    unsafe { urmqtt_pac_violation() == 1 }
}

/// Branches indirectly to an instruction that is not a landing pad.
/// Returns true only if BTI did not fire.
pub fn branch_to_non_landing_pad() -> bool {
    // SAFETY: test mode; returns only if BTI did not fire.
    unsafe { urmqtt_bti_violation() == 1 }
}
