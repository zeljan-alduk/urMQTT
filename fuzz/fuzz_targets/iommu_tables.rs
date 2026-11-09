//! IOMMU discovery and fault records (H4b, ADR-305): arbitrary bytes as a
//! DMAR, IVRS or IORT table, a device tree, or the records a unit writes into
//! its fault log. The first byte picks which. Nothing may panic, every
//! described range must stay inside the 16-bit requester-ID space, a
//! catch-all unit never answers for an ID another unit may claim, and the
//! summary line must format.
#![no_main]

use std::fmt::Write;

use libfuzzer_sys::fuzz_target;
use urmqtt_iommu::{amdvi, smmuv3, vtd};
use urmqtt_platform::acpi::Sdt;
use urmqtt_platform::fdt::Fdt;
use urmqtt_platform::iommu::{self, IommuInfo};

fn check(info: &IommuInfo) {
    let mut s = String::new();
    let _ = write!(s, "{info}");
    for u in info.units.as_slice() {
        for r in u.ranges.as_slice() {
            assert!(r.count >= 1 && u32::from(r.first) + (r.count - 1) <= 0xffff);
        }
    }
    for rid in [0u16, 0x8, 0x10, 0x18, 0xff, 0x100, 0xffff] {
        if let Some((i, _)) = info.unit_for(0, rid) {
            assert!(i < info.units.len());
            // A catch-all answer only where no other unit may claim the ID.
            if info.units.as_slice()[i].explicit(rid).is_none() {
                assert!(!info.unclear(0, rid));
            }
        }
    }
}

fn u64s(b: &[u8]) -> impl Iterator<Item = u64> + '_ {
    b.chunks(8).map(|c| {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        u64::from_le_bytes(w)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let sdt = |sig: [u8; 4]| Sdt {
        signature: sig,
        revision: 1,
        data: rest,
    };
    match which % 5 {
        0 => check(&iommu::parse_dmar(&sdt(*b"DMAR"))),
        1 => check(&iommu::parse_ivrs(&sdt(*b"IVRS"))),
        2 => check(&iommu::parse_iort(&sdt(*b"IORT"))),
        3 => {
            if let Ok(f) = Fdt::new(rest)
                && let Ok(info) = iommu::from_fdt(&f)
            {
                check(&info);
            }
        }
        _ => {
            let w: Vec<u64> = u64s(rest).collect();
            for p in w.chunks(4) {
                let g = |i: usize| p.get(i).copied().unwrap_or(0);
                let f = vtd::decode_fault(g(0), g(1));
                assert!(f.source <= 0xffff && f.addr & 0xfff == 0);
                let a = amdvi::decode_event(g(0), g(1));
                assert!(a.source <= 0xffff && a.reason <= 0xf);
                let _ = smmuv3::decode_event([g(0), g(1), g(2), g(3)]);
                let _ = vtd::Caps::decode(g(0), g(1)).frame_len();
                let c = smmuv3::Caps::decode(g(0) as u32, (g(0) >> 32) as u32, g(1) as u32);
                assert!(matches!(c.levels(), 3 | 4));
            }
        }
    }
});
