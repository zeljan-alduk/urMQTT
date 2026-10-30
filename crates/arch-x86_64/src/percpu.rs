//! Per-CPU identity and secondary-CPU start (X5).

#![allow(unsafe_code)]

pub fn current() -> usize {
    unimplemented_until!("X5 (SMP)")
}

/// # Safety
/// `id` must be this CPU's logical index.
pub unsafe fn set_current(_id: usize) {
    unimplemented_until!("X5 (SMP)")
}

/// The APIC ID of the executing CPU.
pub fn hw_id() -> u64 {
    unimplemented_until!("X5 (SMP)")
}

/// The block an application processor reads when it starts.
#[repr(C)]
pub struct ApBoot {
    cr3: u64,
    stack: u64,
    cpu: u64,
    entry: u64,
}

pub type ApEntry = extern "C" fn(u64) -> !;

impl ApBoot {
    pub const fn empty() -> Self {
        Self {
            cr3: 0,
            stack: 0,
            cpu: 0,
            entry: 0,
        }
    }

    pub fn capture(
        &mut self,
        _cpu: usize,
        _exc_top: u64,
        _main_top: u64,
        _entry: ApEntry,
        _pac_key: Option<(u64, u64)>,
    ) {
        let _ = (self.cr3, self.stack, self.cpu, self.entry);
        unimplemented_until!("X5 (SMP)")
    }
}
