//! The interrupt controller: the local APIC and the I/O APIC (X4).
//!
//! The facade's `Controller` maps onto vectors (see `vectors.rs` for the
//! map). An "INTID" on x86 is the IDT vector: IPIs are 0xf1-0xf3, the
//! timer is 0x20, I/O APIC lines are `0x21 + GSI`, and MSIs use the vector
//! `msi::Frame` handed out.
//!
//! The kernel's trap path calls `ack` once per interrupt entry (it reports
//! the vector in service from the local APIC's ISR), runs the handler, and
//! calls `eoi`. There is no acknowledge register on a local APIC, so a
//! spurious interrupt (vector 0xff, never in service) is reported by the
//! trap glue with [`Ack::SPURIOUS`] and gets no EOI.

#![allow(unsafe_code)]

use crate::apic::{self, Delivery, Mode, Target, TimerMode};
use crate::ioapic::{self, IoApic, Redirection};
use crate::{pic, prim, vectors};
use urmqtt_sync::sync::OnceCell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// GICs do not exist here.
    NoController,
    /// xAPIC mode needs the register window's mapped address.
    NoLocalApic,
}

/// Where the platform tables (X6) say the controllers are.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    /// Mapped (uncached) xAPIC register window; needed unless x2APIC is used.
    pub lapic_mmio: Option<usize>,
    /// Mapped I/O APIC windows and the first GSI each serves.
    pub ioapics: &'a [(usize, u32)],
    /// Use x2APIC when the CPU has it (it is also kept if firmware enabled it).
    pub prefer_x2apic: bool,
}

const MAX_IOAPICS: usize = 8;

struct IoApics {
    chips: [Option<IoApic>; MAX_IOAPICS],
}

static IOAPICS: OnceCell<IoApics> = OnceCell::new();

/// The platform's interrupt controller.
#[derive(Clone, Copy)]
pub struct Controller(());

/// A CPU's handle on its local APIC.
#[derive(Debug, Clone, Copy)]
pub struct Local {
    pub apic_id: u32,
}

/// Unused on x86; kept for the facade contract.
pub const GICV2_MAX_CPUS: usize = 8;

/// An acknowledged interrupt.
#[derive(Debug, Clone, Copy)]
pub struct Ack {
    pub intid: u32,
}

impl Ack {
    /// No vector is in service.
    pub const NONE: Self = Self { intid: 256 };
    /// The local APIC's spurious vector fired.
    pub const SPURIOUS: Self = Self {
        intid: vectors::SPURIOUS,
    };

    /// True when there is nothing to handle (also for a spurious vector).
    pub fn is_none(&self) -> bool {
        self.intid >= 256 || self.intid == vectors::SPURIOUS
    }

    pub fn is_spurious(&self) -> bool {
        self.intid == vectors::SPURIOUS
    }
}

impl Controller {
    /// Brings the interrupt hardware up on the boot CPU: masks the 8259s,
    /// selects x2APIC or xAPIC, masks every I/O APIC pin, and enables the
    /// local APIC (via [`Controller::init_local`], which the caller still
    /// runs for the boot CPU's [`Local`]).
    pub fn apic(cfg: &Config<'_>) -> Result<Self, Error> {
        pic::disable();
        let (_, _, ecx, _) = prim::cpuid(1, 0);
        let has_x2 = ecx & (1 << 21) != 0;
        let firmware_x2 = prim::rdmsr(apic::MSR_APIC_BASE) & apic::APIC_BASE_EXTD != 0;
        let x2 = firmware_x2 || (has_x2 && cfg.prefer_x2apic);
        let mmio = match (x2, cfg.lapic_mmio) {
            (true, m) => m.unwrap_or(0),
            (false, Some(m)) => m,
            (false, None) => return Err(Error::NoLocalApic),
        };
        apic::select(x2, mmio);

        let mut chips = [None; MAX_IOAPICS];
        for (slot, &(va, base)) in chips.iter_mut().zip(cfg.ioapics) {
            let io = IoApic::probe(va, base);
            io.mask_all();
            *slot = Some(io);
        }
        // A second call keeps the first table; the hardware setup above is
        // idempotent.
        let _ = IOAPICS.set(IoApics { chips });
        Ok(Self(()))
    }

    /// GICv3 and GICv2 do not exist on x86; kept so the kernel's interrupt
    /// setup compiles until the platform glue gives it an APIC path.
    ///
    /// # Safety
    /// Never called on x86.
    pub unsafe fn v3(_gicd: usize, _gicr: usize, _len: usize) -> Result<Self, Error> {
        Err(Error::NoController)
    }

    /// # Safety
    /// Never called on x86.
    pub unsafe fn v2(_gicd: usize, _gicc: usize) -> Self {
        unimplemented_until!("X6 (platform glue: use Controller::apic)")
    }

    pub fn is_v2(&self) -> bool {
        false
    }

    /// Interrupt numbers (vectors) the controller can deliver.
    pub fn lines(&self) -> u32 {
        256
    }

    /// CPUs the controller can address: 8-bit IDs in xAPIC mode.
    pub fn max_cpus(&self) -> usize {
        match apic::mode() {
            Mode::X2Apic => 4096,
            _ => 254,
        }
    }

    /// Per-CPU part: enables this CPU's local APIC, sets the spurious
    /// vector, priority 0, the LVT entries, and returns its handle.
    pub fn init_local(&self) -> Result<Local, Error> {
        if apic::mode() == Mode::Off {
            return Err(Error::NoLocalApic);
        }
        apic::enable_this_cpu();
        apic::write(apic::REG_SVR, apic::svr(vectors::SPURIOUS, true));
        apic::write(apic::REG_TPR, 0);
        apic::write(
            apic::REG_LVT_TIMER,
            apic::lvt_timer(vectors::TIMER, TimerMode::OneShot, true),
        );
        // LINT0 carries ExtINT from the (masked) PIC; LINT1 carries NMI.
        apic::write(apic::REG_LVT_LINT0, apic::lvt_fixed(0, true));
        apic::write(apic::REG_LVT_LINT1, apic::lvt_nmi(false));
        apic::write(apic::REG_LVT_ERROR, apic::lvt_fixed(vectors::ERROR, false));
        // The ESR needs a write before each read to latch; clear it.
        apic::write(apic::REG_ESR, 0);
        Ok(Local {
            apic_id: apic::id(),
        })
    }

    /// Enables a private interrupt on the executing CPU. The IPI vectors
    /// are always deliverable; the timer vector needs its LVT entry
    /// programmed and unmasked.
    pub fn enable_private(&self, _local: Option<&Local>, intid: u32) {
        if intid == vectors::TIMER {
            crate::time::unmask_timer_lvt();
        }
    }

    /// Routes a shared interrupt. An I/O APIC vector (`0x21 + GSI`) gets its
    /// redirection entry (ISA defaults for polarity and trigger; use
    /// [`route_gsi`] when the firmware overrides them). An MSI vector needs
    /// nothing: the device's write reaches the local APIC directly.
    pub fn enable_spi(&self, intid: u32, hw_id: u64, _local: Option<&Local>) {
        if let Some(gsi) = vectors::vector_gsi(intid) {
            let (trigger, polarity) = ioapic::default_flags(gsi);
            route_gsi(gsi, hw_id as u32, trigger, polarity);
        }
    }

    /// Sends the IPI `intid` (a vector) to the CPU with APIC ID `hw_id`.
    pub fn send_ipi(&self, intid: u32, hw_id: u64, _local: Option<&Local>) {
        apic::send(Target::Cpu(hw_id as u32), intid, Delivery::Fixed);
    }

    /// The vector in service on this CPU, or [`Ack::NONE`].
    pub fn ack(&self) -> Ack {
        apic::in_service().map_or(Ack::NONE, |intid| Ack { intid })
    }

    /// Signals end-of-interrupt (not for a spurious vector).
    pub fn eoi(&self, ack: Ack) {
        if !ack.is_none() {
            apic::eoi();
        }
    }
}

/// The local APIC's register interface in use, for the boot log.
pub fn mode_name() -> &'static str {
    match apic::mode() {
        Mode::X2Apic => "x2APIC",
        Mode::XApic => "xAPIC",
        Mode::Off => "off",
    }
}

/// Programs the I/O APIC pin for `gsi` to deliver `0x21 + gsi` to the CPU
/// with APIC ID `dest`, unmasked. Returns the vector, or `None` if no I/O
/// APIC serves the GSI, the vector range is exhausted, or the destination
/// is not addressable (I/O APIC destinations are 8 bits wide).
pub fn route_gsi(
    gsi: u32,
    dest: u32,
    trigger: ioapic::Trigger,
    polarity: ioapic::Polarity,
) -> Option<u32> {
    let vector = vectors::gsi_vector(gsi)?;
    if !apic::xapic_reachable(dest) {
        return None;
    }
    let chip = IOAPICS
        .get()?
        .chips
        .iter()
        .flatten()
        .find(|c| c.serves(gsi))?;
    chip.set(
        gsi,
        Redirection {
            vector,
            dest,
            polarity,
            trigger,
            masked: false,
        },
    );
    Some(vector)
}

/// Masks the I/O APIC pin for `gsi`.
pub fn mask_gsi(gsi: u32) {
    let Some(vector) = vectors::gsi_vector(gsi) else {
        return;
    };
    if let Some(chip) = IOAPICS
        .get()
        .and_then(|t| t.chips.iter().flatten().find(|c| c.serves(gsi)))
    {
        chip.set(
            gsi,
            Redirection {
                vector,
                dest: 0,
                polarity: ioapic::Polarity::ActiveHigh,
                trigger: ioapic::Trigger::Edge,
                masked: true,
            },
        );
    }
}
