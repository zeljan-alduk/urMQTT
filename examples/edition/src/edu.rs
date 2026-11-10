//! A driver for QEMU's `edu` device (docs/specs/edu.rst of QEMU): BAR 0 is
//! 1 MiB of registers; 0x00 reads the identification `0xRRrr00ed` (major,
//! minor), 0x04 is the liveness check (it reads back the bitwise inverse of
//! what was written). Nothing else is used: the driver proves that a device
//! the open kernel does not drive is bound by its PCI ID, mapped and spoken
//! to through the library's API, with a key of the reserved range.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_edition_example::{EDU_CHECK, EDU_MODE, FIELDS};
use urmqtt_kernel::ext::{self, Edition, Hooks, PciDevice, PciDriver, PciId};
use urmqtt_kernel::log::info;

pub const EDITION: Edition = Edition {
    name: "example",
    pci_drivers: &[PciDriver {
        name: "example-edu",
        ids: &[PciId::device(0x1234, 0x11e8)],
        max: 1,
        probe,
    }],
    config: FIELDS,
    hooks: Hooks {
        early: Some(early),
        devices: Some(devices),
        ready: Some(ready),
        tick: Some(tick),
    },
};

const ID: usize = 0x00;
const LIVENESS: usize = 0x04;

static TICKS: AtomicU64 = AtomicU64::new(0);
static DRIVEN: AtomicU64 = AtomicU64::new(0);

fn early() {
    info!(
        "example: early hook: {} = {:#010x}, {} = \"{}\"",
        EDU_CHECK.key,
        ext::config_uint(&EDU_CHECK),
        EDU_MODE.key,
        ext::config_variant(&EDU_MODE)
    );
}

fn probe(dev: &mut PciDevice<'_>) -> Result<String, String> {
    if ext::config_variant(&EDU_MODE) == "off" {
        return Err(format!("{} = \"off\"", EDU_MODE.key));
    }
    let regs = dev.map_bar(0, 0x1000).map_err(String::from)?;
    dev.enable(false);
    let id = regs.read32(ID);
    if id & 0xff != 0xed {
        return Err(format!("identification {id:#010x} is not an edu device's"));
    }
    let v = ext::config_uint(&EDU_CHECK) as u32;
    regs.write32(LIVENESS, v);
    let back = regs.read32(LIVENESS);
    if back != !v {
        return Err(format!("liveness check {v:#010x} read back {back:#010x}"));
    }
    DRIVEN.fetch_add(1, Ordering::Relaxed);
    Ok(format!(
        "edu {}.{}, liveness check {v:#010x} -> {back:#010x}",
        id >> 24,
        (id >> 16) & 0xff
    ))
}

fn devices() {
    info!(
        "example: devices hook: {} edu device(s) driven",
        DRIVEN.load(Ordering::Relaxed)
    );
}

fn ready() {
    info!(
        "example: ready hook: {} tick(s) seen",
        TICKS.load(Ordering::Relaxed)
    );
}

fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}
