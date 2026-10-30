//! Per-CPU identity (X4) and secondary-CPU start (X5).

#![allow(unsafe_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{apic, prim};

const MSR_GS_BASE: u32 = 0xc000_0101;

/// Most CPUs the per-CPU blocks cover.
pub const MAX_CPUS: usize = 64;

/// What `gs:[0]` points at on each CPU. `id` must stay the first field.
#[repr(C, align(64))]
struct Block {
    id: u64,
}

const fn blocks() -> [Block; MAX_CPUS] {
    let mut b = [const { Block { id: 0 } }; MAX_CPUS];
    let mut i = 0;
    while i < MAX_CPUS {
        b[i].id = i as u64;
        i += 1;
    }
    b
}

static BLOCKS: [Block; MAX_CPUS] = blocks();

/// Set by the first `set_current`; until then `current()` is the boot CPU.
static READY: AtomicBool = AtomicBool::new(false);

/// The executing CPU's logical index (0 before the first `set_current`).
/// Every CPU must call `set_current` before anything calls this on it.
#[inline]
pub fn current() -> usize {
    if !READY.load(Ordering::Relaxed) {
        return 0;
    }
    let id: u64;
    // SAFETY: after `set_current` GS base points at this CPU's `Block`,
    // whose first word is the index.
    unsafe { asm!("mov {}, gs:[0]", out(reg) id, options(nostack, preserves_flags)) };
    id as usize
}

/// Points this CPU's GS base at its block.
///
/// # Safety
/// `id` must be this CPU's logical index (below [`MAX_CPUS`]) and unique.
pub unsafe fn set_current(id: usize) {
    let block = &BLOCKS[id.min(MAX_CPUS - 1)];
    prim::wrmsr(MSR_GS_BASE, core::ptr::from_ref(block) as u64);
    READY.store(true, Ordering::Release);
}

/// The APIC ID of the executing CPU.
pub fn hw_id() -> u64 {
    if apic::mode() != apic::Mode::Off {
        return u64::from(apic::id());
    }
    // The APIC is not up yet: ask CPUID (x2APIC ID from leaf 0xB, else the
    // 8-bit initial APIC ID from leaf 1).
    if prim::max_leaf() >= 0xb {
        u64::from(prim::cpuid(0xb, 0).3)
    } else {
        u64::from(prim::cpuid(1, 0).1 >> 24)
    }
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
