use std::collections::BTreeMap;
use urmqtt_platform::acpi::{Acpi, AcpiError, PhysMemory, parse_fadt_arm_boot_arch, parse_spcr};
use urmqtt_platform::fdt::Fdt;
use urmqtt_platform::{Gic, PsciMethod, Source, TimerIrqs, Uart, early_from_acpi, early_from_fdt};

/// Sparse fake physical memory made of regions.
#[derive(Default)]
struct Mem(BTreeMap<u64, Vec<u8>>);

impl PhysMemory for Mem {
    fn bytes(&self, pa: u64, len: usize) -> Option<&[u8]> {
        let (base, data) = self.0.range(..=pa).next_back()?;
        let off = usize::try_from(pa - base).ok()?;
        data.get(off..off.checked_add(len)?)
    }
}

fn fix_checksum(t: &mut [u8], at: usize) {
    t[at] = 0;
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[at] = 0u8.wrapping_sub(sum);
}

fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(sig);
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t[8] = 2;
    fix_checksum(&mut t, 9);
    t
}

fn rsdp(xsdt: u64) -> Vec<u8> {
    let mut r = vec![0u8; 36];
    r[..8].copy_from_slice(b"RSD PTR ");
    r[15] = 2;
    r[20..24].copy_from_slice(&36u32.to_le_bytes());
    r[24..32].copy_from_slice(&xsdt.to_le_bytes());
    fix_checksum(&mut r[..20], 8); // v1 checksum over first 20 bytes
    let v1: u8 = r[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    assert_eq!(v1, 0);
    fix_checksum(&mut r, 32); // extended checksum over all 36
    r
}

fn spcr(iface: u8, base: u64) -> Vec<u8> {
    let mut body = vec![0u8; 80 - 36];
    body[0] = iface; // offset 36
    body[4] = 0; // GAS space id at 40
    body[8..16].copy_from_slice(&base.to_le_bytes()); // address at 44
    sdt(b"SPCR", &body)
}

fn fadt(flags: u16) -> Vec<u8> {
    let mut body = vec![0u8; 276 - 36];
    body[129 - 36..131 - 36].copy_from_slice(&flags.to_le_bytes());
    sdt(b"FACP", &body)
}

fn machine(tables: Vec<Vec<u8>>) -> Mem {
    let mut mem = Mem::default();
    let mut addrs = Vec::new();
    for (i, t) in tables.into_iter().enumerate() {
        let pa = 0x4000_0000 + (i as u64) * 0x1000;
        addrs.push(pa);
        mem.0.insert(pa, t);
    }
    let body: Vec<u8> = addrs.iter().flat_map(|a| a.to_le_bytes()).collect();
    mem.0.insert(0x3000_0000, sdt(b"XSDT", &body));
    mem.0.insert(0x2000_0000, rsdp(0x3000_0000));
    mem
}

#[test]
fn qemu_like_tables() {
    let mem = machine(vec![
        fadt(0b11),
        sdt(b"APIC", &[0; 8]),
        spcr(0x03, 0x0900_0000),
    ]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let p = early_from_acpi(&acpi).unwrap();
    assert_eq!(p.source, Source::Acpi);
    assert_eq!(p.uart, Some(Uart { base: 0x0900_0000 }));
    assert_eq!(p.psci, Some(PsciMethod::Hvc));
}

#[test]
fn smc_conduit_and_non_pl011_uart() {
    let mem = machine(vec![fadt(0b01), spcr(0x00, 0x3f8)]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let p = early_from_acpi(&acpi).unwrap();
    assert_eq!(p.psci, Some(PsciMethod::Smc));
    assert_eq!(p.uart, None, "16550 is not supported");
    let s = parse_spcr(&acpi.find(b"SPCR").unwrap().unwrap()).unwrap();
    assert!(!s.pl011_compatible);
}

#[test]
fn psci_not_compliant() {
    let mem = machine(vec![fadt(0b10)]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let f = parse_fadt_arm_boot_arch(&acpi.find(b"FACP").unwrap().unwrap()).unwrap();
    assert!(!f.psci_compliant);
    assert_eq!(early_from_acpi(&acpi).unwrap().psci, None);
}

#[test]
fn corrupt_tables_are_skipped_or_rejected() {
    let mut bad = spcr(0x03, 0x0900_0000);
    bad[50] ^= 1; // breaks the checksum
    let mem = machine(vec![bad, fadt(0b11)]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    assert!(acpi.find(b"SPCR").unwrap().is_none());
    assert_eq!(
        acpi.table_at(0x4000_0000).err(),
        Some(AcpiError::BadChecksum(*b"SPCR"))
    );
    assert!(acpi.find(b"FACP").unwrap().is_some());
}

#[test]
fn rsdp_validation() {
    let mut mem = machine(vec![]);
    assert!(matches!(
        Acpi::new(&mem, 0x1234),
        Err(AcpiError::Unmapped(_))
    ));
    mem.0.get_mut(&0x2000_0000).unwrap()[0] = b'X';
    assert!(matches!(
        Acpi::new(&mem, 0x2000_0000),
        Err(AcpiError::BadSignature)
    ));
}

#[test]
fn absurd_lengths_and_dangling_pointers() {
    let mut huge = sdt(b"SPCR", &[0; 8]);
    huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut mem = machine(vec![huge]);
    // Dangling XSDT entry.
    let xsdt = mem.0.get_mut(&0x3000_0000).unwrap();
    xsdt.extend_from_slice(&0xdead_0000u64.to_le_bytes());
    let len = xsdt.len() as u32;
    xsdt[4..8].copy_from_slice(&len.to_le_bytes());
    fix_checksum(xsdt, 9);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    assert!(acpi.find(b"SPCR").unwrap().is_none());
    assert_eq!(acpi.table_addresses().unwrap().count(), 2);
}

fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0u8; 8]; // local controller address + flags
    for e in entries {
        body.extend_from_slice(e);
    }
    sdt(b"APIC", &body)
}

fn gicd(base: u64) -> Vec<u8> {
    let mut e = vec![0u8; 24];
    e[0] = 0x0c;
    e[1] = 24;
    e[8..16].copy_from_slice(&base.to_le_bytes());
    e[20] = 3;
    e
}

fn gicc(gicr: u64, mpidr: u64) -> Vec<u8> {
    let mut e = vec![0u8; 80];
    e[0] = 0x0b;
    e[1] = 80;
    e[12..16].copy_from_slice(&1u32.to_le_bytes());
    e[60..68].copy_from_slice(&gicr.to_le_bytes());
    e[68..76].copy_from_slice(&mpidr.to_le_bytes());
    e
}

fn gicr_range(base: u64, len: u32) -> Vec<u8> {
    let mut e = vec![0u8; 16];
    e[0] = 0x0e;
    e[1] = 16;
    e[4..12].copy_from_slice(&base.to_le_bytes());
    e[12..16].copy_from_slice(&len.to_le_bytes());
    e
}

fn its(base: u64) -> Vec<u8> {
    let mut e = vec![0u8; 20];
    e[0] = 0x0f;
    e[1] = 20;
    e[8..16].copy_from_slice(&base.to_le_bytes());
    e
}

fn gtdt(phys: u32, virt: u32) -> Vec<u8> {
    let mut body = vec![0u8; 104 - 36];
    body[56 - 36..60 - 36].copy_from_slice(&phys.to_le_bytes());
    body[64 - 36..68 - 36].copy_from_slice(&virt.to_le_bytes());
    sdt(b"GTDT", &body)
}

#[test]
fn gic_and_timer_from_madt_gtdt() {
    let mem = machine(vec![
        fadt(0b11),
        madt(&[
            gicd(0x0800_0000),
            gicc(0, 0),
            gicc(0, 1),
            gicr_range(0x080a_0000, 0x40000),
            its(0x0808_0000),
        ]),
        gtdt(30, 27),
        spcr(0x03, 0x0900_0000),
    ]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let p = early_from_acpi(&acpi).unwrap();
    let i = p.interrupts.unwrap();
    assert_eq!(
        i.gic,
        Gic {
            gicd: 0x0800_0000,
            gicr: (0x080a_0000, 0x40000),
            its: Some(0x0808_0000),
            v2m: None
        }
    );
    assert_eq!(i.timer, TimerIrqs { virt: 27, phys: 30 });
}

#[test]
fn gicr_from_gicc_when_no_range() {
    let mem = machine(vec![
        madt(&[
            gicd(0x0800_0000),
            gicc(0x080a_0000, 0),
            gicc(0x080c_0000, 1),
        ]),
        gtdt(30, 27),
    ]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let i = early_from_acpi(&acpi).unwrap().interrupts.unwrap();
    assert_eq!(i.gic.gicr, (0x080a_0000, 2 * 0x2_0000));
}

#[test]
fn malformed_madt_entries_stop_cleanly() {
    let mut bad = gicd(0x0800_0000);
    bad[1] = 0; // zero length would loop forever if not caught
    let mem = machine(vec![madt(&[bad]), gtdt(30, 27)]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    assert_eq!(early_from_acpi(&acpi).unwrap().interrupts, None);
}

fn mcfg(base: u64, seg: u16, start: u8, end: u8) -> Vec<u8> {
    let mut body = vec![0u8; 8];
    body.extend_from_slice(&base.to_le_bytes());
    body.extend_from_slice(&seg.to_le_bytes());
    body.push(start);
    body.push(end);
    body.extend_from_slice(&[0; 4]);
    sdt(b"MCFG", &body)
}

fn msi_frame(base: u64) -> Vec<u8> {
    let mut e = vec![0u8; 24];
    e[0] = 0x0d;
    e[1] = 24;
    e[8..16].copy_from_slice(&base.to_le_bytes());
    e[20..22].copy_from_slice(&64u16.to_le_bytes());
    e[22..24].copy_from_slice(&80u16.to_le_bytes());
    e
}

/// ACPI tables describing the same machine as the HVF DTB fixture must
/// produce the identical platform summary (M5 acceptance, host side).
#[test]
fn acpi_and_dtb_summaries_match() {
    let mem = machine(vec![
        fadt(0b11),
        madt(&[
            gicd(0x0800_0000),
            gicc(0, 0),
            gicc(0, 1),
            gicc(0, 2),
            gicc(0, 3),
            gicr_range(0x080a_0000, 0x80000),
            msi_frame(0x0802_0000),
        ]),
        gtdt(30, 27),
        spcr(0x03, 0x0900_0000),
        mcfg(0x40_1000_0000, 0, 0, 255),
    ]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    let from_acpi = early_from_acpi(&acpi).unwrap();
    let dtb = include_bytes!("fixtures/qemu-virt-hvf-gic3.dtb");
    let from_dtb = early_from_fdt(&Fdt::new(dtb).unwrap()).unwrap();
    assert_eq!(from_acpi.to_string(), from_dtb.to_string());
    assert_eq!(from_acpi.cpus.as_slice(), &[0, 1, 2, 3]);
}

#[test]
fn disabled_cpus_are_skipped() {
    let mut off = gicc(0, 7);
    off[12..16].copy_from_slice(&0u32.to_le_bytes());
    let mem = machine(vec![
        madt(&[gicd(0x0800_0000), gicc(0, 0), off]),
        gtdt(30, 27),
    ]);
    let acpi = Acpi::new(&mem, 0x2000_0000).unwrap();
    assert_eq!(early_from_acpi(&acpi).unwrap().cpus.as_slice(), &[0]);
}
