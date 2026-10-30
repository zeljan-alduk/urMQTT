//! The IDT (X2): gate encoding is pure and tested on the host; building
//! and loading the table is bare metal only.

/// One 16-byte interrupt-gate descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Gate {
    offset_lo: u16,
    selector: u16,
    ist: u8,
    attr: u8,
    offset_mid: u16,
    offset_hi: u32,
    zero: u32,
}

const ATTR_INTERRUPT_GATE: u8 = 0x8e; // present, DPL 0, 64-bit interrupt gate

impl Gate {
    /// A gate that is not present: using it raises #NP.
    pub const MISSING: Self = Self {
        offset_lo: 0,
        selector: 0,
        ist: 0,
        attr: 0,
        offset_mid: 0,
        offset_hi: 0,
        zero: 0,
    };

    /// An interrupt gate (IF cleared on entry) into `handler`, running on
    /// IST stack `ist` (1..=7, 0 = the current stack).
    pub const fn interrupt(handler: u64, selector: u16, ist: u8) -> Self {
        Self {
            offset_lo: handler as u16,
            selector,
            ist: ist & 7,
            attr: ATTR_INTERRUPT_GATE,
            offset_mid: (handler >> 16) as u16,
            offset_hi: (handler >> 32) as u32,
            zero: 0,
        }
    }

    pub const fn is_present(&self) -> bool {
        self.attr & 0x80 != 0
    }

    pub const fn handler(&self) -> u64 {
        (self.offset_lo as u64) | ((self.offset_mid as u64) << 16) | ((self.offset_hi as u64) << 32)
    }

    pub const fn ist(&self) -> u8 {
        self.ist
    }

    /// The same gate marked not present (self-tests of #DF use this).
    pub const fn not_present(mut self) -> Self {
        self.attr &= 0x7f;
        self
    }
}

/// Which exceptions push an error code (the others get a zero from the
/// entry stub): #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP, and the AMD-only
/// #VC and #SX.
pub const fn has_error_code(vector: u64) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

/// The IST slot a vector's gate uses (0: the interrupted stack).
pub const fn ist_for(vector: u64) -> u8 {
    use crate::gdt::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, IST_PAGE_FAULT};
    match vector {
        2 => IST_NMI,
        8 => IST_DOUBLE_FAULT,
        14 => IST_PAGE_FAULT,
        18 => IST_MACHINE_CHECK,
        _ => 0,
    }
}

#[cfg(target_os = "none")]
pub use boot::{init, set_present};

#[cfg(target_os = "none")]
#[allow(unsafe_code)]
mod boot {
    use core::cell::UnsafeCell;

    use super::*;
    use crate::gdt::KERNEL_CS;

    #[repr(C, align(16))]
    struct Table([Gate; 256]);

    /// Written by [`init`] and the self-test hook [`set_present`] on the
    /// boot CPU; the CPU reads it through IDTR.
    struct Boot(UnsafeCell<Table>);
    // SAFETY: mutated only on the boot CPU with interrupts disabled (see
    // `init` and `set_present`).
    unsafe impl Sync for Boot {}

    static IDT: Boot = Boot(UnsafeCell::new(Table([Gate::MISSING; 256])));

    unsafe extern "C" {
        /// The first of 256 entry stubs, 16 bytes apart (`isr.rs`).
        static urmqtt_isr_stubs: [u8; 0];
    }

    /// Fills all 256 gates with the entry stubs and loads the table.
    ///
    /// # Safety
    /// Call once on the boot CPU after the GDT is loaded, interrupts off.
    pub unsafe fn init() {
        let base = core::ptr::addr_of!(urmqtt_isr_stubs) as u64;
        // SAFETY: exclusive access per the contract.
        let table = unsafe { &mut *IDT.0.get() };
        for (v, gate) in table.0.iter_mut().enumerate() {
            *gate = Gate::interrupt(base + 16 * v as u64, KERNEL_CS, ist_for(v as u64));
        }
        let idtr = [
            (core::mem::size_of::<Table>() as u64 - 1) | (table.0.as_ptr() as u64) << 16,
            (table.0.as_ptr() as u64) >> 48,
        ];
        // SAFETY: `idtr` describes the static table, whose gates point at
        // the stubs; the code segment they name is loaded.
        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) idtr.as_ptr(), options(readonly, nostack, preserves_flags));
        }
    }

    /// Marks `vector`'s gate present or not (a not-present gate turns the
    /// exception into #NP, and a fault while delivering one into #DF: the
    /// `test=df` self-test).
    ///
    /// # Safety
    /// Boot CPU only, interrupts off, after [`init`].
    pub unsafe fn set_present(vector: u8, present: bool) {
        // SAFETY: exclusive access per the contract.
        let table = unsafe { &mut *IDT.0.get() };
        if let Some(g) = table.0.get_mut(usize::from(vector)) {
            *g = if present {
                Gate::interrupt(g.handler(), KERNEL_CS, g.ist())
            } else {
                g.not_present()
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_splits_the_handler_address() {
        let g = Gate::interrupt(0xffff_ffff_8012_3456, 0x08, 4);
        assert_eq!(g.handler(), 0xffff_ffff_8012_3456);
        assert_eq!(g.ist(), 4);
        assert!(g.is_present());
        assert_eq!(core::mem::size_of::<Gate>(), 16);
    }

    #[test]
    fn missing_and_not_present_gates_are_not_present() {
        assert!(!Gate::MISSING.is_present());
        let g = Gate::interrupt(0x1000, 0x08, 0).not_present();
        assert!(!g.is_present());
        assert_eq!(g.handler(), 0x1000, "the address survives for set_present");
    }

    #[test]
    fn error_code_vectors_are_the_architectural_ones() {
        let with: std::vec::Vec<u64> = (0..32).filter(|&v| has_error_code(v)).collect();
        assert_eq!(with, [8, 10, 11, 12, 13, 14, 17, 21, 29, 30]);
        assert!(!has_error_code(32) && !has_error_code(0xff));
    }

    #[test]
    fn critical_exceptions_get_their_own_stacks() {
        assert_eq!(ist_for(8), 1);
        assert_eq!(ist_for(2), 2);
        assert_eq!(ist_for(18), 3);
        assert_eq!(ist_for(14), 4);
        assert_eq!(ist_for(6), 0);
        assert_eq!(ist_for(13), 0);
    }
}
