use urmqtt_platform::fdt::{Fdt, FdtError, Visit};
use urmqtt_platform::{Gic, Interrupts, PsciMethod, Source, TimerIrqs, Uart, early_from_fdt};

const HVF_GIC3: &[u8] = include_bytes!("fixtures/qemu-virt-hvf-gic3.dtb");
const TCG_GIC3: &[u8] = include_bytes!("fixtures/qemu-virt-tcg-gic3.dtb");
const TCG_GIC2: &[u8] = include_bytes!("fixtures/qemu-virt-tcg-gic2.dtb");

#[test]
fn qemu_virt_early_platform() {
    for blob in [HVF_GIC3, TCG_GIC3, TCG_GIC2] {
        let fdt = Fdt::new(blob).unwrap();
        let p = early_from_fdt(&fdt).unwrap();
        assert_eq!(p.source, Source::DeviceTree);
        assert_eq!(p.uart, Some(Uart { base: 0x0900_0000 }));
        assert_eq!(p.psci, Some(PsciMethod::Hvc));
    }
}

#[test]
fn find_path_and_props() {
    let fdt = Fdt::new(HVF_GIC3).unwrap();
    let psci = fdt.find_path("/psci").unwrap().unwrap();
    assert!(psci.is_compatible("arm,psci-1.0").unwrap());
    assert_eq!(psci.prop_str("method").unwrap(), Some("hvc"));
    assert!(fdt.find_path("/nope").unwrap().is_none());
    let cpu0 = fdt.find_path("/cpus/cpu@0").unwrap().unwrap();
    assert_eq!(cpu0.prop_str("enable-method").unwrap(), Some("psci"));
    let root = fdt.find_path("/").unwrap().unwrap();
    assert_eq!(root.depth, 0);
    assert!(root.is_compatible("linux,dummy-virt").unwrap());
}

#[test]
fn reg_uses_parent_cells() {
    let fdt = Fdt::new(TCG_GIC3).unwrap();
    // GICv3: distributor then redistributor regions, 2+2 cells under the root.
    let gic = fdt.find_compatible("arm,gic-v3").unwrap().unwrap();
    assert_eq!(gic.reg(0).unwrap(), Some((0x0800_0000, 0x1_0000)));
    assert_eq!(gic.reg(1).unwrap().map(|r| r.0), Some(0x080a_0000));
    // 64-bit ECAM window from highmem.
    let pcie = fdt
        .find_compatible("pci-host-ecam-generic")
        .unwrap()
        .unwrap();
    assert_eq!(pcie.reg(0).unwrap(), Some((0x40_1000_0000, 0x1000_0000)));
    assert_eq!(pcie.base_name(), "pcie");
}

#[test]
fn cpu_count_matches_qemu_smp() {
    let fdt = Fdt::new(HVF_GIC3).unwrap();
    let mut cpus = 0;
    fdt.for_each_node(|n| {
        if n.depth == 2 && n.base_name() == "cpu" {
            cpus += 1;
        }
        Visit::Continue
    })
    .unwrap();
    assert_eq!(cpus, 4);
}

#[test]
fn hvf_has_v2m_tcg_has_its() {
    let hvf = Fdt::new(HVF_GIC3).unwrap();
    assert!(hvf.find_compatible("arm,gic-v2m-frame").unwrap().is_some());
    assert!(hvf.find_compatible("arm,gic-v3-its").unwrap().is_none());
    let tcg = Fdt::new(TCG_GIC3).unwrap();
    assert!(tcg.find_compatible("arm,gic-v3-its").unwrap().is_some());
}

#[test]
fn rejects_garbage() {
    assert_eq!(Fdt::new(&[]).err(), Some(FdtError::TooShort));
    assert_eq!(Fdt::new(&[0u8; 64]).err(), Some(FdtError::BadMagic));
    let mut b = HVF_GIC3.to_vec();
    b.truncate(100);
    assert_eq!(Fdt::new(&b).err(), Some(FdtError::Truncated));
}

#[test]
fn every_truncation_and_bitflip_is_handled() {
    // Exhaustive-ish robustness: no panic for any prefix or single-byte corruption.
    for len in (0..HVF_GIC3.len()).step_by(7) {
        let _ = Fdt::new(&HVF_GIC3[..len]).map(|f| early_from_fdt(&f));
    }
    let mut b = HVF_GIC3.to_vec();
    for i in (0..b.len()).step_by(3) {
        let orig = b[i];
        b[i] ^= 0xff;
        if let Ok(f) = Fdt::new(&b) {
            let _ = early_from_fdt(&f);
            let _ = f.find_path("/cpus/cpu@3");
        }
        b[i] = orig;
    }
}

#[test]
fn gic_and_timer_from_qemu_dtbs() {
    let hvf = early_from_fdt(&Fdt::new(HVF_GIC3).unwrap()).unwrap();
    assert_eq!(
        hvf.interrupts,
        Some(Interrupts {
            gic: Gic {
                gicd: 0x0800_0000,
                gicr: (0x080a_0000, 0x00f6_0000),
                its: None,
                v2m: Some(0x0802_0000),
            },
            timer: TimerIrqs { virt: 27, phys: 30 },
        })
    );
    let tcg = early_from_fdt(&Fdt::new(TCG_GIC3).unwrap()).unwrap();
    assert_eq!(tcg.interrupts.unwrap().gic.its, Some(0x0808_0000));
    // GICv2 machines have no GICv3 description.
    assert_eq!(
        early_from_fdt(&Fdt::new(TCG_GIC2).unwrap())
            .unwrap()
            .interrupts,
        None
    );
}
