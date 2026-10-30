//! The GDT and the TSS (X2): descriptor encoding is pure and tested on the
//! host; loading them is bare metal only.
//!
//! Long mode ignores base and limit of code and data segments, so the GDT
//! is five slots: null, kernel code, kernel data, and the 16-byte TSS
//! descriptor. The TSS carries the interrupt stack table (IST): the
//! exceptions that must be reportable even when the current stack is gone
//! (double fault, NMI, machine check, page fault) run on stacks of their
//! own. There is no user mode.

/// Selector of the kernel code segment.
pub const KERNEL_CS: u16 = 0x08;
/// Selector of the kernel data segment.
pub const KERNEL_DS: u16 = 0x10;
/// Selector of the TSS.
pub const TSS_SEL: u16 = 0x18;

/// IST slots (1-based, as in the IDT gate): which exception uses which.
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
pub const IST_PAGE_FAULT: u8 = 4;

/// A 64-bit code segment: present, DPL 0, execute/read, L=1.
pub const fn code64() -> u64 {
    // Access 0x9a (P, S, type 0xa), flags L (bit 53) in the upper dword.
    (0x9a << 40) | (0xa << 52) | 0xffff | (0xf << 48)
}

/// A flat data segment: present, DPL 0, read/write.
pub const fn data() -> u64 {
    // Access 0x92 (P, S, type 2), flags G|DB.
    (0x92 << 40) | (0xc << 52) | 0xffff | (0xf << 48)
}

/// The two-slot descriptor of an available 64-bit TSS at `base`.
pub const fn tss(base: u64, limit: u32) -> [u64; 2] {
    let low = (limit as u64 & 0xffff)
        | ((base & 0xff_ffff) << 16)
        | (0x89 << 40)
        | (((limit as u64 >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    [low, base >> 32]
}

/// The 64-bit task state segment.
#[derive(Clone, Copy)]
#[repr(C, packed(4))]
pub struct Tss {
    reserved0: u32,
    /// Stack pointers for privilege changes (unused: no user mode).
    pub rsp: [u64; 3],
    reserved1: u64,
    /// The interrupt stack table; `ist[0]` is IST1.
    pub ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// I/O permission bitmap offset; past the limit means "no bitmap".
    pub iopb: u16,
}

impl Tss {
    pub const SIZE: usize = 104;

    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iopb: Self::SIZE as u16,
        }
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "none")]
pub use boot::{IST_REGION_SIZE, init, init_ap, which_ist};

#[cfg(target_os = "none")]
#[allow(unsafe_code)]
mod boot {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::percpu::MAX_CPUS;

    /// Bytes of each IST stack. The report formatting is the deepest user.
    const IST_STACK_SIZE: usize = 16 * 1024;
    const IST_COUNT: usize = 4;
    /// Bytes of the four IST stacks together: the boot CPU's static
    /// region, and the part of an application processor's exception stack
    /// (`kernel::layout`) that holds its own.
    pub const IST_REGION_SIZE: usize = IST_STACK_SIZE * IST_COUNT;

    #[repr(C, align(16))]
    struct IstStacks([[u8; IST_STACK_SIZE]; IST_COUNT]);

    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    struct Tables {
        gdt: [u64; 5],
        tss: Tss,
    }

    /// Per-CPU state, written once by [`init`] / [`init_ap`] on the CPU it
    /// belongs to before that CPU takes an interrupt.
    struct Boot<T>(UnsafeCell<T>);
    // SAFETY: each element is written only by its own CPU before it loads
    // the tables; afterwards only that CPU (through GDTR/TR) reads them.
    unsafe impl<T> Sync for Boot<T> {}

    static STACKS: Boot<IstStacks> =
        Boot(UnsafeCell::new(IstStacks([[0; IST_STACK_SIZE]; IST_COUNT])));
    static TABLES: Boot<[Tables; MAX_CPUS]> = Boot(UnsafeCell::new(
        [Tables {
            gdt: [0; 5],
            tss: Tss::new(),
        }; MAX_CPUS],
    ));
    /// Lowest address of each CPU's IST region (0: not set up).
    static IST_BASES: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

    /// The top of IST stack `slot` (1-based) of the region at `base`,
    /// 16-byte aligned.
    const fn slot_top(base: u64, slot: u8) -> u64 {
        base + slot as u64 * IST_STACK_SIZE as u64
    }

    /// Which IST stack (1-based) `addr` lies in, on any CPU.
    pub fn which_ist(addr: u64) -> Option<u8> {
        IST_BASES.iter().find_map(|b| {
            // Relaxed: set before the CPU can fault; read while reporting.
            let base = b.load(Ordering::Relaxed);
            if base == 0 {
                return None;
            }
            (1..=IST_COUNT as u8).find(|&slot| {
                let top = slot_top(base, slot);
                (top - IST_STACK_SIZE as u64..top).contains(&addr)
            })
        })
    }

    /// Builds the GDT and TSS for the boot CPU, loads them, and reloads
    /// the segment registers with the kernel's own selectors.
    ///
    /// # Safety
    /// Call once, on the boot CPU, before interrupts are enabled.
    pub unsafe fn init() {
        // SAFETY: forwarded; the region is a static of this module.
        unsafe { load(0, STACKS.0.get() as u64) }
    }

    /// The same for application processor `cpu`, with its IST stacks in
    /// the `IST_REGION_SIZE` bytes ending at `ist_top`.
    ///
    /// # Safety
    /// Call once per CPU, on that CPU, before it enables interrupts. The
    /// region must be mapped, writable, and used by nothing else. Reloading
    /// GS clears its base: set the per-CPU pointer afterwards.
    pub unsafe fn init_ap(cpu: usize, ist_top: u64) {
        // SAFETY: forwarded.
        unsafe { load(cpu, ist_top - IST_REGION_SIZE as u64) }
    }

    /// # Safety
    /// See [`init`] and [`init_ap`].
    unsafe fn load(cpu: usize, ist_base: u64) {
        let cpu = cpu.min(MAX_CPUS - 1);
        // SAFETY: the caller guarantees exclusive access (this CPU's own
        // entry, before it can take an interrupt).
        let tables = unsafe { &mut (*TABLES.0.get())[cpu] };
        // Whole-array store: the field is unaligned inside the packed TSS.
        let mut ist = [0u64; 7];
        for (i, slot) in ist.iter_mut().take(IST_COUNT).enumerate() {
            *slot = slot_top(ist_base, i as u8 + 1);
        }
        tables.tss.ist = ist;
        // Relaxed: see `which_ist`.
        IST_BASES[cpu].store(ist_base, Ordering::Relaxed);
        let desc = tss(
            core::ptr::addr_of!(tables.tss) as u64,
            (Tss::SIZE - 1) as u32,
        );
        tables.gdt = [0, code64(), data(), desc[0], desc[1]];
        let gdtr = [
            // Limit (16 bits) and base (64 bits), packed into 10 bytes.
            ((core::mem::size_of_val(&tables.gdt) - 1) as u64) | (tables.gdt.as_ptr() as u64) << 16,
            (tables.gdt.as_ptr() as u64) >> 48,
        ];
        // SAFETY: `gdtr` is a valid pseudo-descriptor of the table above,
        // which stays alive and unchanged; the far return reloads CS with
        // the code descriptor just installed; the data selectors and the
        // TSS selector index descriptors of that table.
        unsafe {
            core::arch::asm!(
                "lgdt [{gdtr}]",
                "push {cs}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "mov ds, {ds:x}",
                "mov es, {ds:x}",
                "mov ss, {ds:x}",
                "xor {tmp:e}, {tmp:e}",
                "mov fs, {tmp:x}",
                "mov gs, {tmp:x}",
                "ltr {tss:x}",
                gdtr = in(reg) gdtr.as_ptr(),
                cs = in(reg) u64::from(KERNEL_CS),
                ds = in(reg) u32::from(KERNEL_DS),
                tss = in(reg) u32::from(TSS_SEL),
                tmp = out(reg) _,
                options(preserves_flags),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_and_data_descriptors_match_the_manual() {
        // The values every 64-bit kernel uses for flat code/data.
        assert_eq!(code64(), 0x00af_9a00_0000_ffff);
        assert_eq!(data(), 0x00cf_9200_0000_ffff);
    }

    #[test]
    fn tss_descriptor_splits_the_base() {
        let d = tss(0xffff_ffff_8123_4567, 103);
        assert_eq!(d[0] & 0xffff, 103);
        assert_eq!((d[0] >> 16) & 0xff_ffff, 0x23_4567);
        assert_eq!((d[0] >> 40) & 0xff, 0x89, "present, available 64-bit TSS");
        assert_eq!(d[0] >> 56, 0x81);
        assert_eq!(d[1], 0xffff_ffff);
    }

    #[test]
    fn tss_is_104_bytes() {
        assert_eq!(core::mem::size_of::<Tss>(), Tss::SIZE);
    }
}
