//! x86 discovery over tables captured from QEMU (`-M q35` and `-M pc`, SeaBIOS)
//! and over hand-built tables for what QEMU does not produce (x2APIC,
//! hot-plug entries, SPCR, hardware-reduced ACPI, extended FADT addresses).
//!
//! The QEMU fixtures were read out of guest memory with the monitor's
//! `pmemsave` after SeaBIOS had run; each file name carries its physical
//! address.

use std::collections::BTreeMap;
use urmqtt_platform::acpi::{Acpi, PhysMemory};
use urmqtt_platform::aml::SleepType;
use urmqtt_platform::x86::{
    ALL_PROCESSORS, AddrSpace, Polarity, SerialAddr, Trigger, X86Info, resolve_isa_irq,
};
use urmqtt_platform::{Source, early_from_acpi};

#[derive(Default, Clone)]
struct Mem(BTreeMap<u64, Vec<u8>>);

impl PhysMemory for Mem {
    fn bytes(&self, pa: u64, len: usize) -> Option<&[u8]> {
        let (base, data) = self.0.range(..=pa).next_back()?;
        let off = usize::try_from(pa - base).ok()?;
        data.get(off..off.checked_add(len)?)
    }
}

const RSDP_PA: u64 = 0xf52e0;

fn q35() -> Mem {
    let mut m = Mem::default();
    m.0.insert(
        RSDP_PA,
        include_bytes!("fixtures/qemu-q35/rsdp@f52e0.bin").to_vec(),
    );
    m.0.insert(
        0xffe0040,
        include_bytes!("fixtures/qemu-q35/DSDT@ffe0040.bin").to_vec(),
    );
    m.0.insert(
        0xffe2196,
        include_bytes!("fixtures/qemu-q35/FACP@ffe2196.bin").to_vec(),
    );
    m.0.insert(
        0xffe228a,
        include_bytes!("fixtures/qemu-q35/APIC@ffe228a.bin").to_vec(),
    );
    m.0.insert(
        0xffe231a,
        include_bytes!("fixtures/qemu-q35/HPET@ffe231a.bin").to_vec(),
    );
    m.0.insert(
        0xffe2352,
        include_bytes!("fixtures/qemu-q35/MCFG@ffe2352.bin").to_vec(),
    );
    m.0.insert(
        0xffe238e,
        include_bytes!("fixtures/qemu-q35/WAET@ffe238e.bin").to_vec(),
    );
    m.0.insert(
        0xffe23b6,
        include_bytes!("fixtures/qemu-q35/RSDT@ffe23b6.bin").to_vec(),
    );
    m
}

fn pc() -> Mem {
    let mut m = Mem::default();
    m.0.insert(
        RSDP_PA,
        include_bytes!("fixtures/qemu-pc/rsdp@f52e0.bin").to_vec(),
    );
    m.0.insert(
        0xffe0040,
        include_bytes!("fixtures/qemu-pc/DSDT@ffe0040.bin").to_vec(),
    );
    m.0.insert(
        0xffe2278,
        include_bytes!("fixtures/qemu-pc/FACP@ffe2278.bin").to_vec(),
    );
    m.0.insert(
        0xffe22ec,
        include_bytes!("fixtures/qemu-pc/APIC@ffe22ec.bin").to_vec(),
    );
    m.0.insert(
        0xffe237c,
        include_bytes!("fixtures/qemu-pc/HPET@ffe237c.bin").to_vec(),
    );
    m.0.insert(
        0xffe23b4,
        include_bytes!("fixtures/qemu-pc/WAET@ffe23b4.bin").to_vec(),
    );
    m.0.insert(
        0xffe23dc,
        include_bytes!("fixtures/qemu-pc/RSDT@ffe23dc.bin").to_vec(),
    );
    m
}

fn x86_of(m: &Mem) -> X86Info {
    let acpi = Acpi::new(m, RSDP_PA).unwrap();
    early_from_acpi(&acpi).unwrap().x86.unwrap()
}

#[test]
fn qemu_q35() {
    let m = q35();
    let acpi = Acpi::new(&m, RSDP_PA).unwrap();
    let p = early_from_acpi(&acpi).unwrap();
    assert_eq!(p.source, Source::Acpi);
    let x = p.x86.unwrap();

    assert_eq!(x.lapic_addr, 0xfee0_0000);
    assert!(x.pcat_compat);
    let ids: Vec<u32> = x.lapics.as_slice().iter().map(|c| c.apic_id).collect();
    assert_eq!(ids, [0, 1, 2, 3]);
    assert!(x.lapics.as_slice().iter().all(|c| c.enabled && !c.x2apic));
    assert_eq!(p.cpus.as_slice(), &[0, 1, 2, 3]);

    assert_eq!(x.ioapics.len(), 1);
    let io = x.ioapics.as_slice()[0];
    assert_eq!((io.address, io.gsi_base), (0xfec0_0000, 0));
    // QEMU maps ISA IRQ 0 to GSI 2 and level-triggers IRQ 5, 9, 10, 11.
    assert_eq!(resolve_isa_irq(&x, 0).0, 2);
    assert_eq!(resolve_isa_irq(&x, 4).0, 4);
    assert_eq!(
        resolve_isa_irq(&x, 9),
        (9, Polarity::ActiveHigh, Trigger::Level)
    );

    assert_eq!(x.nmis.len(), 1);
    assert_eq!(x.nmis.as_slice()[0].acpi_uid, ALL_PROCESSORS);
    assert_eq!(x.nmis.as_slice()[0].lint, 1);

    let f = x.fadt.unwrap();
    assert_eq!(f.revision, 3);
    assert_eq!(f.sci_int, 9);
    assert_eq!(f.smi_cmd, Some(0xb2));
    assert_eq!((f.acpi_enable, f.acpi_disable), (2, 3));
    assert_eq!(f.pm1a_evt, Some(0x600));
    assert_eq!(f.pm1a_cnt, Some(0x604));
    assert_eq!(f.pm1b_cnt, None);
    assert_eq!(f.pm_tmr, Some(0x608));
    assert!(!f.pm_tmr_32bit); // QEMU's PM timer is 24-bit
    assert!(!f.hw_reduced());
    let r = f.reset.unwrap();
    assert_eq!((r.space, r.address, r.value), (AddrSpace::Io, 0xcf9, 0x0f));
    assert_eq!(f.dsdt, 0xffe0040);

    let h = x.hpet.unwrap();
    assert_eq!(h.address, 0xfed0_0000);
    assert!(h.counter_64bit);
    assert_eq!(h.comparators, 3);

    assert_eq!(x.ecams.len(), 1);
    let e = x.ecams.as_slice()[0];
    assert_eq!(
        (e.base, e.segment, e.bus_start, e.bus_end),
        (0xb000_0000, 0, 0, 255)
    );
    assert_eq!(p.pcie.unwrap().ecam, 0xb000_0000);

    assert_eq!(x.s5, Some(SleepType { a: 0, b: 0 }));
    assert_eq!(x.console, None);

    assert_eq!(
        p.to_string(),
        "uart=none psci=none gic=none cpus=4[0x0,0x1,0x2,0x3] pcie=0xb0000000/0:0-255 \
         lapic=0xfee00000 ioapic=1[0@0xfec00000+0] ovr=5 hpet=0xfed00000 pmtmr=0x608 \
         reset=io:0xcf9=0xf s5=0/0 sci=9"
    );
}

#[test]
fn qemu_pc_has_an_old_fadt_without_reset_register() {
    let x = x86_of(&pc());
    assert_eq!(x.lapics.len(), 4);
    assert!(x.ecams.is_empty());
    let f = x.fadt.unwrap();
    assert_eq!(f.revision, 1);
    assert_eq!(f.reset, None);
    assert_eq!(f.pm1a_cnt, Some(0x604));
    assert_eq!(f.pm_tmr, Some(0x608));
    assert_eq!(f.sci_int, 9);
    assert_eq!(f.dsdt, 0xffe0040);
    assert_eq!(x.s5, Some(SleepType { a: 0, b: 0 }));
    assert_eq!(x.hpet.unwrap().address, 0xfed0_0000);
}

#[test]
fn truncating_or_flipping_any_captured_byte_never_panics() {
    for base in [q35(), pc()] {
        for (&pa, table) in &base.0 {
            for i in 0..table.len() {
                for mutate in [0u8, 1, 2] {
                    let mut m = base.clone();
                    let t = m.0.get_mut(&pa).unwrap();
                    match mutate {
                        0 => t.truncate(i),
                        1 => t[i] ^= 0xff,
                        _ => t[i] = 0xff,
                    }
                    if let Ok(acpi) = Acpi::new(&m, RSDP_PA) {
                        let _ = early_from_acpi(&acpi);
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------- hand-built

fn fix_checksum(t: &mut [u8], at: usize) {
    t[at] = 0;
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[at] = 0u8.wrapping_sub(sum);
}

fn sdt(sig: &[u8; 4], rev: u8, body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(sig);
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t[8] = rev;
    fix_checksum(&mut t, 9);
    t
}

fn rsdp_v2(xsdt: u64, rsdt: u32) -> Vec<u8> {
    let mut r = vec![0u8; 36];
    r[..8].copy_from_slice(b"RSD PTR ");
    r[15] = 2;
    r[16..20].copy_from_slice(&rsdt.to_le_bytes());
    r[20..24].copy_from_slice(&36u32.to_le_bytes());
    r[24..32].copy_from_slice(&xsdt.to_le_bytes());
    fix_checksum(&mut r[..20], 8);
    fix_checksum(&mut r, 32);
    r
}

/// Puts `tables` in memory behind an XSDT (and an RSDT when `with_rsdt`).
fn machine(tables: Vec<Vec<u8>>, xsdt_ok: bool, with_rsdt: bool) -> Mem {
    let mut mem = Mem::default();
    let mut addrs = Vec::new();
    for (i, t) in tables.into_iter().enumerate() {
        let pa = 0x4000_0000 + (i as u64) * 0x1_0000;
        addrs.push(pa);
        mem.0.insert(pa, t);
    }
    let x: Vec<u8> = addrs.iter().flat_map(|a| a.to_le_bytes()).collect();
    let mut xsdt = sdt(b"XSDT", 1, &x);
    if !xsdt_ok {
        xsdt[20] ^= 0xff; // corrupt a body byte: checksum fails
    }
    let r: Vec<u8> = addrs
        .iter()
        .flat_map(|&a| (a as u32).to_le_bytes())
        .collect();
    let rsdt_pa = if with_rsdt { 0x3800_0000 } else { 0 };
    if with_rsdt {
        mem.0.insert(rsdt_pa, sdt(b"RSDT", 1, &r));
    }
    mem.0.insert(0x3000_0000, xsdt);
    mem.0.insert(RSDP_PA, rsdp_v2(0x3000_0000, rsdt_pa as u32));
    mem
}

fn madt(lapic_addr: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&lapic_addr.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    for e in entries {
        body.extend_from_slice(e);
    }
    sdt(b"APIC", 4, &body)
}

fn lapic(uid: u8, id: u8, flags: u32) -> Vec<u8> {
    let mut e = vec![0, 8, uid, id];
    e.extend_from_slice(&flags.to_le_bytes());
    e
}

fn x2apic(id: u32, uid: u32, flags: u32) -> Vec<u8> {
    let mut e = vec![9, 16, 0, 0];
    e.extend_from_slice(&id.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e.extend_from_slice(&uid.to_le_bytes());
    e
}

fn ioapic(id: u8, addr: u32, base: u32) -> Vec<u8> {
    let mut e = vec![1, 12, id, 0];
    e.extend_from_slice(&addr.to_le_bytes());
    e.extend_from_slice(&base.to_le_bytes());
    e
}

fn int_override(irq: u8, gsi: u32, flags: u16) -> Vec<u8> {
    let mut e = vec![2, 10, 0, irq];
    e.extend_from_slice(&gsi.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e
}

fn x2apic_nmi(uid: u32, lint: u8) -> Vec<u8> {
    let mut e = vec![10, 12];
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&uid.to_le_bytes());
    e.push(lint);
    e.extend_from_slice(&[0; 3]);
    e
}

fn lapic_addr_override(addr: u64) -> Vec<u8> {
    let mut e = vec![5, 12, 0, 0];
    e.extend_from_slice(&addr.to_le_bytes());
    e
}

fn gas(space: u8, addr: u64) -> [u8; 12] {
    let mut g = [0u8; 12];
    g[0] = space;
    g[1] = 8;
    g[4..].copy_from_slice(&addr.to_le_bytes());
    g
}

#[test]
fn madt_variety() {
    let m = machine(
        vec![madt(
            0xfee0_0000,
            &[
                lapic(0, 0, 1),
                lapic(1, 1, 0b10),      // hot-pluggable, not yet enabled
                lapic(2, 2, 0),         // does not exist
                lapic(3, 0, 1),         // duplicate APIC ID
                x2apic(0x1_0000, 4, 1), // needs x2APIC
                ioapic(2, 0xfec0_0000, 0),
                ioapic(3, 0xfec1_0000, 24),
                int_override(0, 2, 0),
                int_override(5, 5, 0b1101),   // active high, level
                int_override(11, 11, 0b1111), // active low, level
                x2apic_nmi(4, 1),
                lapic_addr_override(0xfee0_1000),
                vec![0xee, 5, 1, 2, 3], // unknown type is skipped
            ],
        )],
        true,
        false,
    );
    let x = x86_of(&m);
    let l = x.lapics.as_slice();
    assert_eq!(l.len(), 3);
    assert_eq!((l[0].apic_id, l[0].enabled, l[0].x2apic), (0, true, false));
    assert_eq!(
        (l[1].apic_id, l[1].enabled, l[1].online_capable),
        (1, false, true)
    );
    assert_eq!(
        (l[2].apic_id, l[2].acpi_uid, l[2].x2apic),
        (0x1_0000, 4, true)
    );
    assert_eq!(x.lapic_addr, 0xfee0_1000);
    assert_eq!(x.ioapics.len(), 2);
    assert_eq!(x.ioapic_for_gsi(30).unwrap().id, 3);
    assert_eq!(
        resolve_isa_irq(&x, 0),
        (2, Polarity::ActiveHigh, Trigger::Edge)
    );
    assert_eq!(
        resolve_isa_irq(&x, 5),
        (5, Polarity::ActiveHigh, Trigger::Level)
    );
    assert_eq!(
        resolve_isa_irq(&x, 11),
        (11, Polarity::ActiveLow, Trigger::Level)
    );
    assert_eq!(x.nmis.as_slice()[0].acpi_uid, 4);
    assert_eq!(x.fadt, None);
    assert_eq!(x.s5, None);
}

#[test]
fn arm_madt_is_not_x86() {
    let gicc = vec![0x0b, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let mut gicc = gicc;
    gicc.resize(82, 0);
    let m = machine(vec![madt(0, &[gicc])], true, false);
    let acpi = Acpi::new(&m, RSDP_PA).unwrap();
    let p = early_from_acpi(&acpi).unwrap();
    assert_eq!(p.x86, None);
    assert_eq!(p.cpus.len(), 1);
}

fn fadt(len: usize, rev: u8, fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut body = vec![0u8; len - 36];
    {
        // Offsets below are table offsets; shift into the body.
        let mut t = vec![0u8; len];
        fill(&mut t);
        body.copy_from_slice(&t[36..]);
    }
    sdt(b"FACP", rev, &body)
}

#[test]
fn fadt_prefers_extended_addresses_and_reports_hw_reduced() {
    let f = fadt(276, 6, |t| {
        t[46..48].copy_from_slice(&0u16.to_le_bytes());
        t[64..68].copy_from_slice(&0x1111u32.to_le_bytes()); // legacy PM1a_CNT
        t[172..184].copy_from_slice(&gas(1, 0x2222)); // X_PM1a_CNT wins
        t[184..196].copy_from_slice(&gas(0, 0xdead_0000)); // memory: unusable
        t[68..72].copy_from_slice(&0x3333u32.to_le_bytes()); // falls back to legacy
        t[76..80].copy_from_slice(&0x1_0000u32.to_le_bytes()); // does not fit a port
        t[112..116].copy_from_slice(&((1u32 << 20) | (1 << 10)).to_le_bytes());
        t[116..128].copy_from_slice(&gas(0, 0xfe00_0000)); // MMIO reset
        t[128] = 1;
        t[140..148].copy_from_slice(&0x9999u64.to_le_bytes()); // X_DSDT
        t[40..44].copy_from_slice(&0x8888u32.to_le_bytes());
    });
    let m = machine(vec![madt(0xfee0_0000, &[lapic(0, 0, 1)]), f], true, false);
    let x = x86_of(&m);
    let f = x.fadt.unwrap();
    assert!(f.hw_reduced());
    assert_eq!(f.pm1a_cnt, Some(0x2222));
    assert_eq!(f.pm1b_cnt, Some(0x3333));
    assert_eq!(f.pm_tmr, None);
    assert_eq!(f.sci_int, 0);
    let r = f.reset.unwrap();
    assert_eq!(
        (r.space, r.address, r.value),
        (AddrSpace::Memory, 0xfe00_0000, 1)
    );
    assert_eq!(f.dsdt, 0x9999);
}

#[test]
fn reset_register_needs_the_supported_flag() {
    let f = fadt(244, 3, |t| {
        t[116..128].copy_from_slice(&gas(1, 0xcf9));
        t[128] = 6;
    });
    let m = machine(vec![madt(0xfee0_0000, &[lapic(0, 0, 1)]), f], true, false);
    assert_eq!(x86_of(&m).fadt.unwrap().reset, None);
}

#[test]
fn spcr_hpet_and_s5_from_ssdt() {
    let mut spcr = vec![0u8; 80 - 36];
    spcr[0] = 0; // 16550
    spcr[4..16].copy_from_slice(&gas(1, 0x3f8));
    spcr[58 - 36] = 7; // 115200
    let spcr = sdt(b"SPCR", 2, &spcr);

    let mut hpet = vec![0u8; 56 - 36];
    hpet[..4].copy_from_slice(&((1u32 << 13) | (2 << 8)).to_le_bytes());
    hpet[4..16].copy_from_slice(&gas(0, 0xfed0_0000));
    hpet[16] = 0;
    hpet[17..19].copy_from_slice(&128u16.to_le_bytes());
    let hpet = sdt(b"HPET", 1, &hpet);

    // No DSDT; the package is in an SSDT after some unrelated AML.
    let mut ssdt = vec![0x10, 0x05, b'_', b'S', b'B', b'_'];
    ssdt.extend_from_slice(&[
        0x08, b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0a, 0x05, 0x0a, 0x05, 0, 0,
    ]);
    let ssdt = sdt(b"SSDT", 2, &ssdt);

    let m = machine(
        vec![madt(0xfee0_0000, &[lapic(0, 0, 1)]), spcr, hpet, ssdt],
        true,
        false,
    );
    let x = x86_of(&m);
    let c = x.console.unwrap();
    assert_eq!(c.addr, SerialAddr::Io(0x3f8));
    assert!(c.ns16550);
    assert_eq!(c.baud, Some(115_200));
    let h = x.hpet.unwrap();
    assert_eq!(
        (h.address, h.comparators, h.min_tick),
        (0xfed0_0000, 3, 128)
    );
    assert_eq!(x.s5, Some(SleepType { a: 5, b: 5 }));
}

#[test]
fn bad_xsdt_falls_back_to_rsdt() {
    let tables = || vec![madt(0xfee0_0000, &[lapic(0, 0, 1), lapic(1, 1, 1)])];
    let m = machine(tables(), false, true);
    assert_eq!(x86_of(&m).lapics.len(), 2);
    // Without an RSDT there is nothing to fall back on.
    let m = machine(tables(), false, false);
    let acpi = Acpi::new(&m, RSDP_PA).unwrap();
    assert!(early_from_acpi(&acpi).is_err());
}

#[test]
fn more_processors_than_slots_are_counted_not_lost_silently() {
    let entries: Vec<Vec<u8>> = (0..70u8).map(|i| lapic(i, i, 1)).collect();
    let m = machine(vec![madt(0xfee0_0000, &entries)], true, false);
    let x = x86_of(&m);
    assert_eq!(x.lapics.len(), 64);
    assert_eq!(x.lapics.dropped, 6);
    let acpi = Acpi::new(&m, RSDP_PA).unwrap();
    assert_eq!(early_from_acpi(&acpi).unwrap().cpus.dropped, 6);
}
