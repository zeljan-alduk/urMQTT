//! Names for ids: PCI classes and vendors, hypervisor signatures, Arm cores.
//! Small tables of what is commonly met; an unknown id prints as hex.

use alloc::format;
use alloc::string::String;

/// The PCI class code's meaning (class, subclass).
pub fn pci_class(class: u8, sub: u8) -> &'static str {
    match (class, sub) {
        (0x00, _) => "unclassified",
        (0x01, 0x00) => "SCSI controller",
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x07) => "SAS controller",
        (0x01, 0x08) => "NVMe controller",
        (0x01, _) => "storage controller",
        (0x02, 0x00) => "Ethernet controller",
        (0x02, _) => "network controller",
        (0x03, 0x00) => "VGA controller",
        (0x03, _) => "display controller",
        (0x04, _) => "multimedia",
        (0x05, _) => "memory controller",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "bridge",
        (0x07, _) => "communication controller",
        (0x08, _) => "system peripheral",
        (0x09, _) => "input device",
        (0x0c, 0x03) => "USB controller",
        (0x0c, 0x05) => "SMBus controller",
        (0x0c, _) => "serial bus controller",
        (0x0d, _) => "wireless controller",
        (0x10, _) => "encryption controller",
        (0xff, _) => "vendor specific",
        _ => "other",
    }
}

/// A PCI vendor id's name.
pub fn pci_vendor(id: u16) -> String {
    let n = match id {
        0x1af4 => "Red Hat (virtio)",
        0x1b36 => "Red Hat (QEMU)",
        0x1234 => "QEMU/Bochs",
        0x8086 => "Intel",
        0x1022 => "AMD",
        0x1002 => "AMD/ATI",
        0x10de => "NVIDIA",
        0x10ec => "Realtek",
        0x14e4 => "Broadcom",
        0x15b3 => "Mellanox",
        0x1425 => "Chelsio",
        0x1d0f => "Amazon",
        0x15ad => "VMware",
        0x1414 => "Microsoft",
        0x1ab8 => "Parallels",
        0x80ee => "VirtualBox",
        0x5853 => "Xen",
        0x144d => "Samsung",
        0x1344 => "Micron",
        0x1c5c => "SK hynix",
        0x1b4b => "Marvell",
        0x1000 => "Broadcom/LSI",
        0x1912 => "Renesas",
        0x1b21 => "ASMedia",
        0x1969 => "Qualcomm Atheros",
        0x177d => "Cavium/Marvell",
        _ => return format!("{id:04x}"),
    };
    String::from(n)
}

/// The CPU hypervisor signature (CPUID 0x4000_0000) as a product name.
pub fn hypervisor(sig: &str) -> &'static str {
    match sig.trim_end_matches('\0') {
        "KVMKVMKVM" => "KVM",
        "TCGTCGTCGTCG" => "QEMU TCG",
        "Microsoft Hv" => "Hyper-V",
        "VMwareVMware" => "VMware",
        "XenVMMXenVMM" => "Xen",
        "VBoxVBoxVBox" => "VirtualBox",
        "bhyve bhyve " | "bhyve bhyve" => "bhyve",
        " lrpepyh  vr" | "prl hyperv  " => "Parallels",
        "ACRNACRNACRN" => "ACRN",
        "" => "",
        _ => "unknown hypervisor",
    }
}

/// An Arm MIDR_EL1 implementer byte.
pub fn arm_implementer(id: u8) -> &'static str {
    match id {
        0x41 => "Arm",
        0x42 => "Broadcom",
        0x43 => "Cavium",
        0x46 => "Fujitsu",
        0x48 => "HiSilicon",
        0x4e => "NVIDIA",
        0x50 => "Ampere",
        0x51 => "Qualcomm",
        0x61 => "Apple",
        0x69 => "Intel",
        0x6d => "Microsoft",
        _ => "unknown",
    }
}

/// An Arm core name from MIDR implementer and part number.
pub fn arm_part(implementer: u8, part: u16) -> &'static str {
    match (implementer, part) {
        (0x41, 0xd03) => "Cortex-A53",
        (0x41, 0xd04) => "Cortex-A35",
        (0x41, 0xd05) => "Cortex-A55",
        (0x41, 0xd07) => "Cortex-A57",
        (0x41, 0xd08) => "Cortex-A72",
        (0x41, 0xd09) => "Cortex-A73",
        (0x41, 0xd0a) => "Cortex-A75",
        (0x41, 0xd0b) => "Cortex-A76",
        (0x41, 0xd0c) => "Neoverse N1",
        (0x41, 0xd0d) => "Cortex-A77",
        (0x41, 0xd40) => "Neoverse V1",
        (0x41, 0xd41) => "Cortex-A78",
        (0x41, 0xd44) => "Cortex-X1",
        (0x41, 0xd46) => "Cortex-A510",
        (0x41, 0xd47) => "Cortex-A710",
        (0x41, 0xd48) => "Cortex-X2",
        (0x41, 0xd49) => "Neoverse N2",
        (0x41, 0xd4f) => "Neoverse V2",
        (0x41, 0xd80) => "Cortex-A520",
        (0x41, 0xd81) => "Cortex-A720",
        (0x41, 0xd8e) => "Neoverse N3",
        (0x61, 0x022 | 0x023) => "Apple M1 (Firestorm/Icestorm)",
        (0x61, 0x032 | 0x033) => "Apple M2",
        (0x61, 0x048 | 0x049) => "Apple M3",
        (0x50, 0x000) => "Ampere eMAG",
        (0x6d, 0xd49) => "Azure Cobalt 100",
        _ => "unknown core",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_ids() {
        assert_eq!(pci_class(0x02, 0x00), "Ethernet controller");
        assert_eq!(pci_class(0x01, 0x08), "NVMe controller");
        assert_eq!(pci_class(0x77, 0), "other");
        assert_eq!(pci_vendor(0x1af4), "Red Hat (virtio)");
        assert_eq!(pci_vendor(0x1234), "QEMU/Bochs");
        assert_eq!(pci_vendor(0xabcd), "abcd");
        assert_eq!(hypervisor("KVMKVMKVM\0\0\0"), "KVM");
        assert_eq!(hypervisor("TCGTCGTCGTCG"), "QEMU TCG");
        assert_eq!(hypervisor(""), "");
        assert_eq!(hypervisor("zzzzzzzzzzzz"), "unknown hypervisor");
        assert_eq!(arm_implementer(0x41), "Arm");
        assert_eq!(arm_part(0x41, 0xd0c), "Neoverse N1");
        assert_eq!(arm_part(0x41, 0xfff), "unknown core");
    }
}
