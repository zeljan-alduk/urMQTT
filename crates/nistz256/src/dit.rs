//! PSTATE.DIT (Data Independent Timing, FEAT_DIT, Armv8.4) around secret
//! arithmetic.
//!
//! Arm guarantees that the timing of the data-processing instructions it
//! lists (among them `mul`, `umulh`, `madd`, `adds`/`adcs` and the
//! cryptographic extensions) does not depend on their operands **only while
//! PSTATE.DIT is 1**; with DIT clear, an implementation may, for example,
//! finish a multiplication early for small or zero operands. The nistz256
//! assembly is built from exactly these instructions, so the secret-scalar
//! entry points of this crate run with DIT set ([`dit_guard`]).
//!
//! DIT is part of PSTATE: it is per thread, survives context switches on
//! Linux (saved in SPSR on exception entry, restored on `eret`), and is
//! writable at EL0 and EL1 without a trap. On a core without FEAT_DIT the
//! register does not exist and the guard does nothing. In the bare-metal
//! kernel the boot code sets DIT on every CPU and keeps it set in every
//! saved context (`crates/arch-aarch64`), so there the guard finds it set
//! and changes nothing.
//!
//! On x86_64 the guard is a no-op: Intel's equivalent (DOITM) is a
//! model-specific register the kernel would have to own; not done.

/// While alive, PSTATE.DIT is 1 on a core that implements FEAT_DIT; on drop
/// it is put back as it was. A no-op on cores without FEAT_DIT and on
/// x86_64.
#[must_use = "DIT is only set while the guard is alive"]
pub struct DitGuard {
    #[cfg(target_arch = "aarch64")]
    restore: bool,
    /// Not `Send`: PSTATE belongs to the thread that set it.
    _not_send: core::marker::PhantomData<*const ()>,
}

/// Sets PSTATE.DIT for the lifetime of the returned guard (see the module
/// documentation).
pub fn dit_guard() -> DitGuard {
    #[cfg(target_arch = "aarch64")]
    {
        let restore = available() && !imp::get();
        if restore {
            imp::set(true);
        }
        DitGuard {
            restore,
            _not_send: core::marker::PhantomData,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        DitGuard {
            _not_send: core::marker::PhantomData,
        }
    }
}

impl Drop for DitGuard {
    fn drop(&mut self) {
        #[cfg(target_arch = "aarch64")]
        if self.restore {
            imp::set(false);
        }
    }
}

/// Whether this core implements FEAT_DIT (ID_AA64PFR0_EL1.DIT >= 1). Always
/// `false` on x86_64.
pub fn available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        imp::available()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// The current PSTATE.DIT (`false` where FEAT_DIT is absent, and on x86_64).
pub fn enabled() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        available() && imp::get()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use core::arch::asm;
    use core::sync::atomic::{AtomicU8, Ordering};

    /// PSTATE.DIT as the `DIT` special register shows it.
    const DIT_BIT: u64 = 1 << 24;

    /// 0: not read yet, 1: absent, 2: present.
    static HAVE: AtomicU8 = AtomicU8::new(0);

    pub(super) fn available() -> bool {
        match HAVE.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let pfr0: u64;
                // SAFETY: reading ID_AA64PFR0_EL1 has no side effect; at EL1
                // it is a plain register read (or a hypervisor-emulated one),
                // at EL0 on Linux the kernel emulates it (HWCAP_CPUID, Linux
                // 4.11+) and exposes the DIT field.
                unsafe {
                    asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nomem, nostack, preserves_flags));
                }
                let have = (pfr0 >> 48) & 0xf >= 1;
                HAVE.store(if have { 2 } else { 1 }, Ordering::Relaxed);
                have
            }
        }
    }

    /// Reads PSTATE.DIT; only call when [`available`].
    pub(super) fn get() -> bool {
        let v: u64;
        // SAFETY: the DIT special register (op0=3, op1=3, CRn=4, CRm=2,
        // op2=5) exists with FEAT_DIT, which the caller checked; reading it
        // has no side effect. Written by encoding so no `+dit` target
        // feature is needed.
        unsafe {
            asm!("mrs {}, s3_3_c4_c2_5", out(reg) v, options(nomem, nostack, preserves_flags));
        }
        v & DIT_BIT != 0
    }

    /// Writes PSTATE.DIT; only call when [`available`]. Not `nomem`: the
    /// write must stay ordered with the arithmetic it protects.
    pub(super) fn set(on: bool) {
        let v = if on { DIT_BIT } else { 0 };
        // SAFETY: as in `get`; DIT is writable at EL0 and EL1, changes only
        // instruction timing guarantees, and touches no memory or flags.
        unsafe {
            asm!("msr s3_3_c4_c2_5, {}", in(reg) v, options(nostack, preserves_flags));
        }
    }
}
