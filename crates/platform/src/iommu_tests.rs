use super::*;
use crate::acpi::Sdt;

/// A table: 36-byte header (only the signature and length matter to the
/// parsers) followed by `body`.
pub(crate) fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(sig);
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t
}

fn sdt<'a>(sig: &[u8; 4], data: &'a [u8]) -> Sdt<'a> {
    Sdt {
        signature: *sig,
        revision: 1,
        data,
    }
}

/// QEMU's q35 DMAR with `intel-iommu,intremap=on`: HAW 47 (48 bits),
/// interrupt remapping, one DRHD with INCLUDE_PCI_ALL and the I/O APIC scope.
pub(crate) fn qemu_dmar() -> Vec<u8> {
    let mut b = vec![47u8, 1];
    b.extend_from_slice(&[0; 10]);
    let mut drhd = vec![0u8; 16];
    drhd[0..2].copy_from_slice(&0u16.to_le_bytes());
    drhd[4] = 1; // INCLUDE_PCI_ALL
    drhd[8..16].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
    // I/O APIC scope: type 3, length 8, enumeration id 0, bus 0xff, path 0:0.
    drhd.extend_from_slice(&[3, 8, 0, 0, 0, 0xff, 0, 0]);
    let len = drhd.len() as u16;
    drhd[2..4].copy_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&drhd);
    table(b"DMAR", &b)
}

#[test]
fn dmar_qemu_include_all() {
    let t = qemu_dmar();
    let i = parse_dmar(&sdt(b"DMAR", &t));
    assert_eq!(i.units.len(), 1);
    let u = i.units.as_slice()[0];
    assert_eq!((u.kind, u.base, u.segment, u.all), (Kind::VtD, 0xfed9_0000, 0, true));
    assert_eq!(u.unsupported, 0);
    assert_eq!((i.address_bits, i.dmar_flags), (48, 1));
    // Every function of segment 0 is translated with its own requester ID.
    assert_eq!(i.unit_for(0, 0x0018), Some((0, 0x18)));
    assert_eq!(i.unit_for(1, 0x0018), None);
    assert_eq!(i.to_string(), "VT-d@0xfed90000/0:all haw=48 reserved=0");
}

#[test]
fn dmar_scopes_rmrr_and_order() {
    let mut b = vec![38u8, 0];
    b.extend_from_slice(&[0; 10]);
    // A DRHD for one endpoint (00:02.0) and a bridge sub-hierarchy.
    let mut d1 = vec![0u8; 16];
    d1[8..16].copy_from_slice(&0xfed9_1000u64.to_le_bytes());
    d1.extend_from_slice(&[1, 8, 0, 0, 0, 0, 2, 0]);
    d1.extend_from_slice(&[2, 8, 0, 0, 0, 0, 0x1c, 0]);
    let l = d1.len() as u16;
    d1[2..4].copy_from_slice(&l.to_le_bytes());
    // An RMRR.
    let mut rmrr = vec![0u8; 24];
    rmrr[0] = 1;
    rmrr[2..4].copy_from_slice(&24u16.to_le_bytes());
    // The catch-all unit, listed last as the specification wants.
    let mut d2 = vec![0u8; 16];
    d2[2..4].copy_from_slice(&16u16.to_le_bytes());
    d2[4] = 1;
    d2[8..16].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
    b.extend_from_slice(&d1);
    b.extend_from_slice(&rmrr);
    b.extend_from_slice(&d2);
    let t = table(b"DMAR", &b);
    let i = parse_dmar(&sdt(b"DMAR", &t));
    assert_eq!(i.units.len(), 2);
    assert_eq!(i.reserved_regions, 1);
    assert_eq!(i.units.as_slice()[0].unsupported, 1);
    // 00:02.0 belongs to the first unit, everything else to the catch-all.
    assert_eq!(i.unit_for(0, 0x10), Some((0, 0x10)));
    assert_eq!(i.unit_for(0, 0x18), Some((1, 0x18)));
}

#[test]
fn dmar_truncated_and_zero_length_structures_stop_cleanly() {
    let mut b = vec![47u8, 0];
    b.extend_from_slice(&[0; 10]);
    // Length 0 would loop forever if accepted.
    b.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    let t = table(b"DMAR", &b);
    assert!(parse_dmar(&sdt(b"DMAR", &t)).is_empty());
    // A DRHD that claims more bytes than the table has.
    let mut b = vec![47u8, 0];
    b.extend_from_slice(&[0; 10]);
    b.extend_from_slice(&[0, 0, 200, 0, 1, 0, 0, 0, 0, 0, 0xd9, 0xfe, 0, 0, 0, 0]);
    let t = table(b"DMAR", &b);
    assert!(parse_dmar(&sdt(b"DMAR", &t)).is_empty());
    // A scope with a length below its fixed part.
    let mut b = vec![47u8, 0];
    b.extend_from_slice(&[0; 10]);
    let mut d = vec![0u8; 16];
    d[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    d.extend_from_slice(&[1, 2, 0, 0]);
    let l = d.len() as u16;
    d[2..4].copy_from_slice(&l.to_le_bytes());
    b.extend_from_slice(&d);
    let t = table(b"DMAR", &b);
    let i = parse_dmar(&sdt(b"DMAR", &t));
    assert_eq!(i.units.as_slice()[0].unsupported, 1);
}

/// QEMU's IVRS with `amd-iommu`: IVHD 0x10 and 0x11 for the same IOMMU
/// (00:01.0 here), each with "all" and an I/O APIC special entry.
pub(crate) fn qemu_ivrs() -> Vec<u8> {
    let mut b = vec![0u8; 12]; // IVinfo + reserved
    for ty in [0x10u8, 0x11] {
        let head = if ty == 0x10 { 24 } else { 40 };
        let mut h = vec![0u8; head];
        h[0] = ty;
        h[1] = 0xd1;
        h[4..6].copy_from_slice(&0x0008u16.to_le_bytes());
        h[6..8].copy_from_slice(&0x40u16.to_le_bytes());
        h[8..16].copy_from_slice(&0xfed8_0000u64.to_le_bytes());
        h.extend_from_slice(&[1, 0, 0, 0]); // all
        h.extend_from_slice(&[0x48, 0, 0, 0xd7, 0, 0xa0, 0, 2]); // I/O APIC
        let l = h.len() as u16;
        h[2..4].copy_from_slice(&l.to_le_bytes());
        b.extend_from_slice(&h);
    }
    table(b"IVRS", &b)
}

#[test]
fn ivrs_qemu_all_deduplicated() {
    let t = qemu_ivrs();
    let i = parse_ivrs(&sdt(b"IVRS", &t));
    assert_eq!(i.units.len(), 1);
    let u = i.units.as_slice()[0];
    assert_eq!((u.kind, u.base, u.self_id, u.all), (Kind::AmdVi, 0xfed8_0000, 8, true));
    assert_eq!(u.unsupported, 0);
    assert_eq!(i.unit_for(0, 0x20), Some((0, 0x20)));
}

#[test]
fn ivrs_ranges_aliases_and_unknown_entries() {
    let mut b = vec![0u8; 12];
    let mut h = vec![0u8; 24];
    h[0] = 0x10;
    h[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    h.extend_from_slice(&[2, 0x10, 0, 0]); // select 00:02.0
    h.extend_from_slice(&[3, 0x00, 1, 0]); // range start 01:00.0
    h.extend_from_slice(&[4, 0xff, 1, 0]); // range end 01:1f.7
    h.extend_from_slice(&[0x43, 0x00, 2, 0, 0, 0x08, 0, 0]); // alias range 02:00.0 -> 00:01.0
    h.extend_from_slice(&[4, 0x07, 2, 0]); // ... to 02:00.7
    h.extend_from_slice(&[4, 0, 3, 0]); // end without a start: counted
    h.extend_from_slice(&[0x80, 0, 0, 0]); // unknown variable length: stops
    h.extend_from_slice(&[2, 0x18, 0, 0]); // never read
    let l = h.len() as u16;
    h[2..4].copy_from_slice(&l.to_le_bytes());
    b.extend_from_slice(&h);
    // An IVMD.
    let mut m = vec![0u8; 32];
    m[0] = 0x21;
    m[2..4].copy_from_slice(&32u16.to_le_bytes());
    b.extend_from_slice(&m);
    let t = table(b"IVRS", &b);
    let i = parse_ivrs(&sdt(b"IVRS", &t));
    assert_eq!(i.reserved_regions, 1);
    let u = i.units.as_slice()[0];
    assert!(!u.all);
    assert_eq!(u.unsupported, 2);
    assert_eq!(i.unit_for(0, 0x10), Some((0, 0x10)));
    assert_eq!(i.unit_for(0, 0x0105), Some((0, 0x0105)));
    assert_eq!(i.unit_for(0, 0x0203), Some((0, 0x0008)));
    assert_eq!(i.unit_for(0, 0x0208), None);
    assert_eq!(i.unit_for(0, 0x18), None);
}

/// An IORT like QEMU's `virt,iommu=smmuv3` (ACPI): an ITS group, an SMMUv3
/// at 0x9050000 and a root complex whose IDs 0..0xffff go to the SMMU.
pub(crate) fn qemu_iort() -> Vec<u8> {
    let mut nodes = Vec::new();
    let first = 36 + 12;
    // ITS group: 16-byte header, count u32, one identifier.
    let its_off = first;
    let mut its = vec![0u8; 24];
    its[0] = 0;
    its[1..3].copy_from_slice(&24u16.to_le_bytes());
    its[16..20].copy_from_slice(&1u32.to_le_bytes());
    nodes.extend_from_slice(&its);
    // SMMUv3 node: 68 bytes of data, one ID mapping to the ITS.
    let smmu_off = first + its.len();
    let mut s = vec![0u8; 68 + 20];
    s[0] = 4;
    let l = s.len() as u16;
    s[1..3].copy_from_slice(&l.to_le_bytes());
    s[3] = 4;
    s[8..12].copy_from_slice(&1u32.to_le_bytes());
    s[12..16].copy_from_slice(&68u32.to_le_bytes());
    s[16..24].copy_from_slice(&0x0905_0000u64.to_le_bytes());
    s[24..28].copy_from_slice(&1u32.to_le_bytes()); // COHACC
    s[68 + 4..68 + 8].copy_from_slice(&0xffffu32.to_le_bytes());
    s[68 + 12..68 + 16].copy_from_slice(&(its_off as u32).to_le_bytes());
    nodes.extend_from_slice(&s);
    // Root complex: 36 bytes of data, one mapping to the SMMU.
    let mut rc = vec![0u8; 36 + 20];
    rc[0] = 2;
    let l = rc.len() as u16;
    rc[1..3].copy_from_slice(&l.to_le_bytes());
    rc[8..12].copy_from_slice(&1u32.to_le_bytes());
    rc[12..16].copy_from_slice(&36u32.to_le_bytes());
    rc[36 + 4..36 + 8].copy_from_slice(&0xffffu32.to_le_bytes());
    rc[36 + 12..36 + 16].copy_from_slice(&(smmu_off as u32).to_le_bytes());
    nodes.extend_from_slice(&rc);
    let mut b = Vec::new();
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&(first as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&nodes);
    table(b"IORT", &b)
}

#[test]
fn iort_qemu_root_complex_through_smmu() {
    let t = qemu_iort();
    let i = parse_iort(&sdt(b"IORT", &t));
    assert_eq!(i.units.len(), 1);
    let u = i.units.as_slice()[0];
    assert_eq!((u.kind, u.base, u.coherent), (Kind::SmmuV3, 0x0905_0000, true));
    assert_eq!(i.untranslated_hosts, 0);
    assert_eq!(i.unit_for(0, 0x0010), Some((0, 0x10)));
    assert_eq!(i.unit_for(0, 0xffff), Some((0, 0xffff)));
}

#[test]
fn iort_root_complex_straight_to_its_is_untranslated() {
    let mut t = qemu_iort();
    // Point the root complex's mapping at the ITS group (offset 48).
    let rc_map_ref = t.len() - 20 + 12;
    t[rc_map_ref..rc_map_ref + 4].copy_from_slice(&48u32.to_le_bytes());
    let i = parse_iort(&sdt(b"IORT", &t));
    assert_eq!(i.untranslated_hosts, 1);
    assert_eq!(i.unit_for(0, 0x10), None);
}

#[test]
fn iort_garbage_offsets() {
    let mut b = Vec::new();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    let t = table(b"IORT", &b);
    assert!(parse_iort(&sdt(b"IORT", &t)).is_empty());
}

#[test]
fn every_prefix_of_every_table_parses_without_panic() {
    for t in [qemu_dmar(), qemu_ivrs(), qemu_iort()] {
        for n in 0..=t.len() {
            let d = &t[..n];
            let _ = parse_dmar(&sdt(b"DMAR", d));
            let _ = parse_ivrs(&sdt(b"IVRS", d));
            let _ = parse_iort(&sdt(b"IORT", d));
        }
    }
}

#[test]
fn display_lists_ranges() {
    let mut i = IommuInfo::default();
    let mut u = Unit {
        kind: Kind::SmmuV3,
        base: 0x9050000,
        ..Unit::default()
    };
    u.ranges.push(IdRange {
        first: 0,
        count: 0x10000,
        out_base: 0,
        alias: false,
    });
    i.units.push(u);
    assert_eq!(i.to_string(), "SMMUv3@0x9050000/0:0x0+65536->0x0 reserved=0");
    assert_eq!(IommuInfo::default().to_string(), "none");
}
