//! x86 platform description from ACPI: MADT (local APICs, I/O APICs,
//! interrupt overrides, NMIs), FADT (power management and reset), HPET, MCFG,
//! SPCR and the `_S5_` sleep type from the DSDT.
//!
//! Everything is plain data produced by pure, bounds-checked parsers over
//! [`Sdt`] bytes, so host tests can feed them hand-built and captured tables.

use crate::acpi::{Acpi, AcpiError, McfgEntry, PhysMemory, Sdt, u8_at, u16_at, u32_at, u64_at};
use crate::aml::{self, SleepType};
use crate::{MAX_CPUS, acpi};

/// Upper bounds for the fixed-capacity lists (the kernel has no allocator
/// this early). Entries beyond them are counted in `dropped`.
pub const MAX_IOAPICS: usize = 8;
pub const MAX_OVERRIDES: usize = 32;
pub const MAX_NMIS: usize = 16;
pub const MAX_ECAMS: usize = 8;
/// Most SSDTs searched for `_S5_` when the DSDT has none.
const MAX_SSDTS: usize = 32;

/// A list with inline storage and a counter for what did not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedVec<T: Copy, const N: usize> {
    items: [T; N],
    len: usize,
    /// Pushes refused because the list was full.
    pub dropped: usize,
}

impl<T: Copy + Default, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self {
            items: [T::default(); N],
            len: 0,
            dropped: 0,
        }
    }
}

impl<T: Copy, const N: usize> FixedVec<T, N> {
    pub fn push(&mut self, v: T) {
        match self.items.get_mut(self.len) {
            Some(slot) => {
                *slot = v;
                self.len += 1;
            }
            None => self.dropped += 1,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self.items.get(..self.len).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A processor's local APIC, from a MADT type 0 or type 9 entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalApic {
    /// APIC ID (the x2APIC ID when `x2apic`).
    pub apic_id: u32,
    /// ACPI processor UID, which NMI entries refer to.
    pub acpi_uid: u32,
    /// Usable now.
    pub enabled: bool,
    /// Can be brought online later (hot-plug); only meaningful if not enabled.
    pub online_capable: bool,
    /// The entry was the x2APIC form (IDs of 255 and above need it).
    pub x2apic: bool,
}

/// An I/O APIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoApic {
    pub id: u8,
    /// Physical MMIO base.
    pub address: u32,
    /// First global system interrupt this I/O APIC serves.
    pub gsi_base: u32,
}

/// Interrupt polarity from MPS INTI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    /// "Conforms to the bus specification" (ISA: active high).
    #[default]
    BusDefault,
    ActiveHigh,
    ActiveLow,
}

/// Interrupt trigger mode from MPS INTI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Trigger {
    /// "Conforms to the bus specification" (ISA: edge).
    #[default]
    BusDefault,
    Edge,
    Level,
}

impl Polarity {
    fn from_inti(flags: u16) -> Self {
        match flags & 0b11 {
            0b01 => Self::ActiveHigh,
            0b11 => Self::ActiveLow,
            _ => Self::BusDefault,
        }
    }
}

impl Trigger {
    fn from_inti(flags: u16) -> Self {
        match (flags >> 2) & 0b11 {
            0b01 => Self::Edge,
            0b11 => Self::Level,
            _ => Self::BusDefault,
        }
    }
}

/// An interrupt source override (MADT type 2), e.g. ISA IRQ 0 -> GSI 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IntOverride {
    /// Always 0 (ISA) in practice.
    pub bus: u8,
    pub source_irq: u8,
    pub gsi: u32,
    pub polarity: Polarity,
    pub trigger: Trigger,
}

/// Local APIC NMI wiring (MADT type 4 and type 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalNmi {
    /// ACPI processor UID, or [`ALL_PROCESSORS`].
    pub acpi_uid: u32,
    /// LINT0 or LINT1.
    pub lint: u8,
    pub polarity: Polarity,
    pub trigger: Trigger,
}

/// `LocalNmi::acpi_uid` meaning "every processor".
pub const ALL_PROCESSORS: u32 = 0xffff_ffff;

/// An ACPI Generic Address Structure address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrSpace {
    #[default]
    Memory,
    Io,
    PciConfig,
    Other(u8),
}

impl AddrSpace {
    fn from_id(id: u8) -> Self {
        match id {
            0 => Self::Memory,
            1 => Self::Io,
            2 => Self::PciConfig,
            n => Self::Other(n),
        }
    }
}

/// The FADT reset register: write `value` to `address` to reset the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetReg {
    pub space: AddrSpace,
    pub address: u64,
    pub value: u8,
}

/// Power-management description from the FADT. I/O ports are `None` when the
/// block is absent (hardware-reduced ACPI) or not in I/O space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fadt {
    pub revision: u8,
    /// System control interrupt, a GSI (after overrides). 0 if hardware-reduced.
    pub sci_int: u16,
    /// Port to write `acpi_enable` to when SCI_EN is clear. `None` if ACPI
    /// mode is already on (or there is no SMM handler).
    pub smi_cmd: Option<u16>,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub pm1a_evt: Option<u16>,
    pub pm1a_cnt: Option<u16>,
    /// Second PM1 control block, written with SLP_TYPb.
    pub pm1b_cnt: Option<u16>,
    /// ACPI PM timer, a 3.579545 MHz counter.
    pub pm_tmr: Option<u16>,
    /// The PM timer counts 32 bits (otherwise 24).
    pub pm_tmr_32bit: bool,
    /// Raw FADT flags.
    pub flags: u32,
    /// Raw IA-PC boot architecture flags (legacy devices, 8042, no VGA, ...).
    pub iapc_boot_arch: u16,
    /// `None` unless the table has one and says it is supported.
    pub reset: Option<ResetReg>,
    /// Physical address of the DSDT (X_DSDT if present, else DSDT).
    pub dsdt: u64,
}

impl Fadt {
    /// Hardware-reduced ACPI: no legacy PM blocks, no SCI.
    pub fn hw_reduced(&self) -> bool {
        self.flags & FADT_HW_REDUCED != 0
    }

    /// The machine has an 8042 keyboard controller (ACPI 2.0+ only; for an
    /// older table the flag is absent, which is why this is advisory).
    pub fn has_8042(&self) -> bool {
        self.iapc_boot_arch & (1 << 1) != 0
    }
}

const FADT_TMR_VAL_EXT: u32 = 1 << 8;
const FADT_RESET_REG_SUP: u32 = 1 << 10;
const FADT_HW_REDUCED: u32 = 1 << 20;

/// The HPET description table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hpet {
    /// MMIO base of the register block.
    pub address: u64,
    /// Sequence number of this HPET.
    pub number: u8,
    pub min_tick: u16,
    /// Counter is 64 bits wide (bit 13 of the capability word).
    pub counter_64bit: bool,
    /// Number of comparators.
    pub comparators: u8,
}

/// Where the SPCR console lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAddr {
    Io(u16),
    Mmio(u64),
}

/// The SPCR console on x86.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialConsole {
    pub interface_type: u8,
    pub addr: SerialAddr,
    /// 16550-compatible register layout (the only kind the kernel drives).
    pub ns16550: bool,
    /// Configured baud rate, if the firmware states one.
    pub baud: Option<u32>,
}

/// Everything the kernel learns about an x86 machine from ACPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct X86Info {
    /// Local APIC MMIO base (the 64-bit override applied).
    pub lapic_addr: u64,
    /// Dual-8259 PICs are installed and must be masked before use of APICs.
    pub pcat_compat: bool,
    /// Processors, firmware order, boot processor included. Disabled entries
    /// that cannot come online are left out.
    pub lapics: FixedVec<LocalApic, MAX_CPUS>,
    pub ioapics: FixedVec<IoApic, MAX_IOAPICS>,
    pub overrides: FixedVec<IntOverride, MAX_OVERRIDES>,
    pub nmis: FixedVec<LocalNmi, MAX_NMIS>,
    /// PCIe ECAM regions from the MCFG.
    pub ecams: FixedVec<EcamRegion, MAX_ECAMS>,
    pub fadt: Option<Fadt>,
    pub hpet: Option<Hpet>,
    /// `\_S5` sleep type, if found in the DSDT or an SSDT.
    pub s5: Option<SleepType>,
    pub console: Option<SerialConsole>,
}

/// One ECAM region (same data as an MCFG entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EcamRegion {
    pub base: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

impl From<McfgEntry> for EcamRegion {
    fn from(e: McfgEntry) -> Self {
        Self {
            base: e.base,
            segment: e.segment,
            bus_start: e.bus_start,
            bus_end: e.bus_end,
        }
    }
}

/// How an ISA IRQ reaches the I/O APIC: (GSI, polarity, trigger) after
/// applying an interrupt source override, with ISA defaults (edge, active
/// high) filled in where the firmware says "conforms to bus".
pub fn resolve_isa_irq(info: &X86Info, irq: u8) -> (u32, Polarity, Trigger) {
    for o in info.overrides.as_slice() {
        if o.bus == 0 && o.source_irq == irq {
            let pol = match o.polarity {
                Polarity::BusDefault => Polarity::ActiveHigh,
                p => p,
            };
            let trig = match o.trigger {
                Trigger::BusDefault => Trigger::Edge,
                t => t,
            };
            return (o.gsi, pol, trig);
        }
    }
    (u32::from(irq), Polarity::ActiveHigh, Trigger::Edge)
}

impl X86Info {
    /// The I/O APIC serving `gsi`: the one with the greatest base not above
    /// it. Pin counts are in the I/O APIC's own registers, so the caller
    /// must still check the pin against the hardware's maximum redirection
    /// entry.
    pub fn ioapic_for_gsi(&self, gsi: u32) -> Option<&IoApic> {
        self.ioapics
            .as_slice()
            .iter()
            .filter(|a| a.gsi_base <= gsi)
            .max_by_key(|a| a.gsi_base)
    }
}

// ---------------------------------------------------------------- MADT

const MADT_LAPIC: u8 = 0;
const MADT_IOAPIC: u8 = 1;
const MADT_OVERRIDE: u8 = 2;
const MADT_LAPIC_NMI: u8 = 4;
const MADT_LAPIC_ADDR: u8 = 5;
const MADT_X2APIC: u8 = 9;
const MADT_X2APIC_NMI: u8 = 10;
const LAPIC_ENABLED: u32 = 1;
const LAPIC_ONLINE_CAPABLE: u32 = 1 << 1;
const MADT_PCAT_COMPAT: u32 = 1;

fn push_cpu(info: &mut X86Info, cpu: LocalApic) {
    if !cpu.enabled && !cpu.online_capable {
        return;
    }
    // A repeated APIC ID would make SMP bring-up start one core twice.
    if info
        .lapics
        .as_slice()
        .iter()
        .any(|c| c.apic_id == cpu.apic_id)
    {
        return;
    }
    info.lapics.push(cpu);
}

/// Fills the MADT-derived fields of `info`.
pub fn parse_madt(t: &Sdt<'_>, info: &mut X86Info) {
    info.lapic_addr = u64::from(u32_at(t.data, 36).unwrap_or(0));
    info.pcat_compat = u32_at(t.data, 40).unwrap_or(0) & MADT_PCAT_COMPAT != 0;
    for (ty, e) in acpi::madt_entries(t) {
        match ty {
            MADT_LAPIC => {
                let flags = u32_at(e, 4).unwrap_or(0);
                if let (Some(uid), Some(id)) = (u8_at(e, 2), u8_at(e, 3)) {
                    push_cpu(
                        info,
                        LocalApic {
                            apic_id: u32::from(id),
                            acpi_uid: u32::from(uid),
                            enabled: flags & LAPIC_ENABLED != 0,
                            online_capable: flags & LAPIC_ONLINE_CAPABLE != 0,
                            x2apic: false,
                        },
                    );
                }
            }
            MADT_X2APIC => {
                let flags = u32_at(e, 8).unwrap_or(0);
                if let (Some(id), Some(uid)) = (u32_at(e, 4), u32_at(e, 12)) {
                    push_cpu(
                        info,
                        LocalApic {
                            apic_id: id,
                            acpi_uid: uid,
                            enabled: flags & LAPIC_ENABLED != 0,
                            online_capable: flags & LAPIC_ONLINE_CAPABLE != 0,
                            x2apic: true,
                        },
                    );
                }
            }
            MADT_IOAPIC => {
                if let (Some(id), Some(address), Some(gsi_base)) =
                    (u8_at(e, 2), u32_at(e, 4), u32_at(e, 8))
                {
                    info.ioapics.push(IoApic {
                        id,
                        address,
                        gsi_base,
                    });
                }
            }
            MADT_OVERRIDE => {
                if let (Some(bus), Some(source_irq), Some(gsi), Some(flags)) =
                    (u8_at(e, 2), u8_at(e, 3), u32_at(e, 4), u16_at(e, 8))
                {
                    info.overrides.push(IntOverride {
                        bus,
                        source_irq,
                        gsi,
                        polarity: Polarity::from_inti(flags),
                        trigger: Trigger::from_inti(flags),
                    });
                }
            }
            MADT_LAPIC_NMI => {
                if let (Some(uid), Some(flags), Some(lint)) =
                    (u8_at(e, 2), u16_at(e, 3), u8_at(e, 5))
                {
                    info.nmis.push(LocalNmi {
                        // 0xff means every processor.
                        acpi_uid: if uid == 0xff {
                            ALL_PROCESSORS
                        } else {
                            u32::from(uid)
                        },
                        lint,
                        polarity: Polarity::from_inti(flags),
                        trigger: Trigger::from_inti(flags),
                    });
                }
            }
            MADT_X2APIC_NMI => {
                if let (Some(flags), Some(uid), Some(lint)) =
                    (u16_at(e, 2), u32_at(e, 4), u8_at(e, 8))
                {
                    info.nmis.push(LocalNmi {
                        acpi_uid: uid,
                        lint,
                        polarity: Polarity::from_inti(flags),
                        trigger: Trigger::from_inti(flags),
                    });
                }
            }
            MADT_LAPIC_ADDR => {
                if let Some(a) = u64_at(e, 4).filter(|&a| a != 0) {
                    info.lapic_addr = a;
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- FADT

/// An ACPI Generic Address Structure.
struct Gas {
    space: AddrSpace,
    address: u64,
}

fn gas_at(b: &[u8], off: usize) -> Option<Gas> {
    Some(Gas {
        space: AddrSpace::from_id(u8_at(b, off)?),
        address: u64_at(b, off.checked_add(4)?)?,
    })
}

/// An I/O port from the extended GAS field if it is a non-zero I/O address,
/// else from the legacy 32-bit field.
fn pm_port(d: &[u8], legacy: usize, extended: usize) -> Option<u16> {
    if let Some(g) = gas_at(d, extended)
        && g.address != 0
        && g.space == AddrSpace::Io
    {
        return u16::try_from(g.address).ok();
    }
    u16::try_from(u32_at(d, legacy)?).ok().filter(|&p| p != 0)
}

pub fn parse_fadt(t: &Sdt<'_>) -> Option<Fadt> {
    let d = t.data;
    let flags = u32_at(d, 112)?;
    let reset = if flags & FADT_RESET_REG_SUP != 0 {
        gas_at(d, 116)
            .zip(u8_at(d, 128))
            .filter(|(g, _)| g.address != 0)
            .map(|(g, value)| ResetReg {
                space: g.space,
                address: g.address,
                value,
            })
    } else {
        None
    };
    let dsdt = u64_at(d, 140)
        .filter(|&a| a != 0)
        .or_else(|| u32_at(d, 40).map(u64::from))
        .unwrap_or(0);
    Some(Fadt {
        revision: t.revision,
        sci_int: u16_at(d, 46)?,
        smi_cmd: u32_at(d, 48)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|&p| p != 0),
        acpi_enable: u8_at(d, 52).unwrap_or(0),
        acpi_disable: u8_at(d, 53).unwrap_or(0),
        pm1a_evt: pm_port(d, 56, 148),
        pm1a_cnt: pm_port(d, 64, 172),
        pm1b_cnt: pm_port(d, 68, 184),
        pm_tmr: pm_port(d, 76, 208),
        pm_tmr_32bit: flags & FADT_TMR_VAL_EXT != 0,
        flags,
        iapc_boot_arch: u16_at(d, 109).unwrap_or(0),
        reset,
        dsdt,
    })
}

// ---------------------------------------------------------------- HPET

pub fn parse_hpet(t: &Sdt<'_>) -> Option<Hpet> {
    let d = t.data;
    let block = u32_at(d, 36)?;
    let g = gas_at(d, 40)?;
    // Only a memory-mapped block with a plausible base is usable.
    if g.space != AddrSpace::Memory || g.address == 0 {
        return None;
    }
    Some(Hpet {
        address: g.address,
        number: u8_at(d, 52)?,
        min_tick: u16_at(d, 53)?,
        counter_64bit: block & (1 << 13) != 0,
        comparators: (((block >> 8) & 0x1f) as u8).saturating_add(1),
    })
}

// ---------------------------------------------------------------- SPCR

/// SPCR interface types with a 16550 register layout: 16550, 16450, and
/// "16550-compatible with parameters in the GAS".
const SPCR_16550: [u8; 3] = [0x00, 0x01, 0x12];

pub fn parse_spcr(t: &Sdt<'_>) -> Option<SerialConsole> {
    let d = t.data;
    let interface_type = u8_at(d, 36)?;
    let g = gas_at(d, 40)?;
    let addr = match g.space {
        AddrSpace::Io => SerialAddr::Io(u16::try_from(g.address).ok()?),
        AddrSpace::Memory if g.address != 0 => SerialAddr::Mmio(g.address),
        _ => return None,
    };
    let baud = match u8_at(d, 58) {
        Some(3) => Some(9600),
        Some(4) => Some(19200),
        Some(6) => Some(57600),
        Some(7) => Some(115_200),
        _ => None,
    };
    Some(SerialConsole {
        interface_type,
        addr,
        ns16550: SPCR_16550.contains(&interface_type),
        baud,
    })
}

// ---------------------------------------------------------------- discovery

/// Looks for `_S5_` in the DSDT, then in up to [`MAX_SSDTS`] SSDTs.
fn s5_from_acpi<M: PhysMemory>(
    acpi: &Acpi<'_, M>,
    dsdt: u64,
) -> Result<Option<SleepType>, AcpiError> {
    if dsdt != 0
        && let Ok(t) = acpi.table_at(dsdt)
        && let Some(s) = aml::find_s5(t.body())
    {
        return Ok(Some(s));
    }
    let mut seen = 0;
    for pa in acpi.table_addresses()? {
        if let Ok(t) = acpi.table_at(pa)
            && &t.signature == b"SSDT"
        {
            seen += 1;
            if seen > MAX_SSDTS {
                break;
            }
            if let Some(s) = aml::find_s5(t.body()) {
                return Ok(Some(s));
            }
        }
    }
    Ok(None)
}

/// Builds the x86 description, or `None` if the MADT lists no local APIC
/// (not an x86 machine, e.g. an ARM MADT with only GIC entries).
pub fn discover<M: PhysMemory>(acpi: &Acpi<'_, M>) -> Result<Option<X86Info>, AcpiError> {
    let Some(madt) = acpi.find(b"APIC")? else {
        return Ok(None);
    };
    let mut info = X86Info::default();
    parse_madt(&madt, &mut info);
    if info.lapics.is_empty() {
        return Ok(None);
    }
    info.fadt = acpi.find(b"FACP")?.as_ref().and_then(parse_fadt);
    info.hpet = acpi.find(b"HPET")?.as_ref().and_then(parse_hpet);
    info.console = acpi.find(b"SPCR")?.as_ref().and_then(parse_spcr);
    if let Some(mcfg) = acpi.find(b"MCFG")? {
        for e in acpi::mcfg_entries(&mcfg) {
            info.ecams.push(e.into());
        }
    }
    let dsdt = info.fadt.map_or(0, |f| f.dsdt);
    info.s5 = s5_from_acpi(acpi, dsdt)?;
    Ok(Some(info))
}

impl core::fmt::Display for X86Info {
    /// `lapic=0xfee00000 ioapic=1[0@0xfec00000+0] ovr=2 hpet=0xfed00000
    ///  pmtmr=0x608 reset=io:0xcf9=0xf s5=0/0 sci=9`
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "lapic={:#x} ioapic={}[",
            self.lapic_addr,
            self.ioapics.len()
        )?;
        for (i, a) in self.ioapics.as_slice().iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{}@{:#x}+{}", a.id, a.address, a.gsi_base)?;
        }
        write!(f, "] ovr={}", self.overrides.len())?;
        match self.hpet {
            Some(h) => write!(f, " hpet={:#x}", h.address)?,
            None => f.write_str(" hpet=none")?,
        }
        match self.fadt.and_then(|x| x.pm_tmr) {
            Some(p) => write!(f, " pmtmr={p:#x}")?,
            None => f.write_str(" pmtmr=none")?,
        }
        match self.fadt.and_then(|x| x.reset) {
            Some(r) => {
                let sp = match r.space {
                    AddrSpace::Memory => "mem",
                    AddrSpace::Io => "io",
                    AddrSpace::PciConfig => "pci",
                    AddrSpace::Other(_) => "other",
                };
                write!(f, " reset={sp}:{:#x}={:#x}", r.address, r.value)?;
            }
            None => f.write_str(" reset=none")?,
        }
        match self.s5 {
            Some(s) => write!(f, " s5={}/{}", s.a, s.b)?,
            None => f.write_str(" s5=none")?,
        }
        match self.fadt {
            Some(x) => write!(f, " sci={}", x.sci_int),
            None => f.write_str(" sci=none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with(overrides: &[IntOverride]) -> X86Info {
        let mut i = X86Info::default();
        for o in overrides {
            i.overrides.push(*o);
        }
        i
    }

    #[test]
    fn fixed_vec_counts_overflow() {
        let mut v: FixedVec<u8, 2> = FixedVec::default();
        v.push(1);
        v.push(2);
        v.push(3);
        assert_eq!(v.as_slice(), &[1, 2]);
        assert_eq!(v.dropped, 1);
    }

    #[test]
    fn isa_resolution_uses_overrides_and_defaults() {
        let i = info_with(&[IntOverride {
            bus: 0,
            source_irq: 0,
            gsi: 2,
            polarity: Polarity::BusDefault,
            trigger: Trigger::BusDefault,
        }]);
        assert_eq!(
            resolve_isa_irq(&i, 0),
            (2, Polarity::ActiveHigh, Trigger::Edge)
        );
        assert_eq!(
            resolve_isa_irq(&i, 4),
            (4, Polarity::ActiveHigh, Trigger::Edge)
        );
        let i = info_with(&[IntOverride {
            bus: 0,
            source_irq: 9,
            gsi: 9,
            polarity: Polarity::ActiveHigh,
            trigger: Trigger::Level,
        }]);
        assert_eq!(
            resolve_isa_irq(&i, 9),
            (9, Polarity::ActiveHigh, Trigger::Level)
        );
    }

    #[test]
    fn ioapic_for_gsi_picks_greatest_base() {
        let mut i = X86Info::default();
        i.ioapics.push(IoApic {
            id: 0,
            address: 0xfec0_0000,
            gsi_base: 0,
        });
        i.ioapics.push(IoApic {
            id: 1,
            address: 0xfec1_0000,
            gsi_base: 24,
        });
        assert_eq!(i.ioapic_for_gsi(23).map(|a| a.id), Some(0));
        assert_eq!(i.ioapic_for_gsi(24).map(|a| a.id), Some(1));
        assert_eq!(X86Info::default().ioapic_for_gsi(0), None);
    }

    #[test]
    fn inti_flags() {
        assert_eq!(Polarity::from_inti(0b0101), Polarity::ActiveHigh);
        assert_eq!(Trigger::from_inti(0b0101), Trigger::Edge);
        assert_eq!(Polarity::from_inti(0b1111), Polarity::ActiveLow);
        assert_eq!(Trigger::from_inti(0b1111), Trigger::Level);
        assert_eq!(Polarity::from_inti(0b10), Polarity::BusDefault);
        assert_eq!(Trigger::from_inti(0), Trigger::BusDefault);
    }
}
