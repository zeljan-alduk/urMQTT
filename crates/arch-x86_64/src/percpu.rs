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

/// The block an application processor reads when it starts: the boot
/// CPU's control state, which the entry stub mirrors before any compiled
/// code runs. Field offsets are used by the assembly below.
#[repr(C)]
pub struct ApBoot {
    cr0: u64,
    cr3: u64,
    cr4: u64,
    /// The boot CPU's EFER: only NXE is copied.
    efer: u64,
    pat: u64,
    /// Top of the AP's main stack.
    stack: u64,
    cpu: u64,
    entry: u64,
    /// Top of the AP's exception stack, which holds its IST stacks.
    exc_top: u64,
}

/// First compiled code an AP runs, on its main stack. Receives the logical
/// CPU index.
pub type ApEntry = extern "C" fn(u64) -> !;

const MSR_EFER: u32 = 0xc000_0080;
const MSR_PAT: u32 = 0x277;
const EFER_NXE: u64 = 1 << 11;

fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading a control register has no side effect.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: as for `read_cr0`.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: as for `read_cr0`.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

impl ApBoot {
    pub const fn empty() -> Self {
        Self {
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            pat: 0,
            stack: 0,
            cpu: 0,
            entry: 0,
            exc_top: 0,
        }
    }

    /// Fills the block from the executing (boot) CPU's configuration. The
    /// `pac_key` of the AArch64 signature does not exist here.
    pub fn capture(
        &mut self,
        cpu: usize,
        exc_top: u64,
        main_top: u64,
        entry: ApEntry,
        _pac_key: Option<(u64, u64)>,
    ) {
        *self = Self {
            cr0: read_cr0(),
            cr3: read_cr3(),
            cr4: read_cr4(),
            efer: prim::rdmsr(MSR_EFER),
            pat: prim::rdmsr(MSR_PAT),
            stack: main_top,
            cpu: cpu as u64,
            entry: entry as *const () as u64,
            exc_top,
        };
    }
}

// Limine enters an AP at `urmqtt_ap_entry` in 64-bit mode with its own
// tables and a small stack of its own, `rdi` pointing at its MP info whose
// `extra_argument` (offset 24) is an `ApBoot`. The stub gives the AP the
// boot CPU's EFER.NXE, PAT, CR4, page tables and CR0 (in that order: the
// kernel's tables use NX, and WP comes last), puts the FPU in the state the
// hard-float kernel needs, switches to the AP's stack and continues in
// `urmqtt_ap_prepare`.
core::arch::global_asm!(
    r#"
    .text
    .global urmqtt_ap_entry
urmqtt_ap_entry:
    cli
    cld
    mov rbx, [rdi + 24]
    mov ecx, {efer}
    rdmsr
    mov rsi, [rbx + {o_efer}]
    and esi, {nxe}
    or eax, esi
    wrmsr
    mov ecx, {pat}
    mov eax, [rbx + {o_pat}]
    mov edx, [rbx + {o_pat} + 4]
    wrmsr
    mov rax, [rbx + {o_cr4}]
    mov cr4, rax
    mov rax, [rbx + {o_cr3}]
    mov cr3, rax
    mov rax, [rbx + {o_cr0}]
    mov cr0, rax
    fninit
    mov rsp, [rbx + {o_stack}]
    xor ebp, ebp
    push 0x1f80
    ldmxcsr [rsp]
    add rsp, 8
    mov rdi, rbx
    call urmqtt_ap_prepare
    ud2
    "#,
    efer = const MSR_EFER,
    pat = const MSR_PAT,
    nxe = const EFER_NXE,
    o_efer = const core::mem::offset_of!(ApBoot, efer),
    o_pat = const core::mem::offset_of!(ApBoot, pat),
    o_cr0 = const core::mem::offset_of!(ApBoot, cr0),
    o_cr3 = const core::mem::offset_of!(ApBoot, cr3),
    o_cr4 = const core::mem::offset_of!(ApBoot, cr4),
    o_stack = const core::mem::offset_of!(ApBoot, stack),
);

/// Gives the AP its own GDT/TSS, the shared IDT and its per-CPU pointer,
/// then enters the kernel on its main stack.
#[unsafe(no_mangle)]
extern "C" fn urmqtt_ap_prepare(boot: &ApBoot) -> ! {
    let cpu = boot.cpu as usize;
    // SAFETY: this CPU's own entry; its IST region is the top of its
    // mapped exception stack, used by nothing else; interrupts are off.
    unsafe { crate::gdt::init_ap(cpu, boot.exc_top) };
    // SAFETY: the GDT above is loaded and the table is the boot CPU's.
    unsafe { crate::idt::load() };
    // SAFETY: `cpu` is this CPU's unique logical index; the GDT reload
    // above cleared GS, which is why this comes after it.
    unsafe { set_current(cpu) };
    crate::cpu::enable_extended_state();
    // SAFETY: `entry` was captured from a valid `ApEntry`.
    let entry: ApEntry = unsafe { core::mem::transmute::<u64, ApEntry>(boot.entry) };
    entry(boot.cpu)
}
