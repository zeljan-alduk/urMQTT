//! The self-installing ISO's install mode (S1b, STORAGE-PLAN §2b): the
//! ISO menu's second entry boots the kernel with `install` and the ESP as a
//! hash-pinned module. The kernel picks the one disk to install onto,
//! shows it and counts down (power off to cancel), writes the raw boot
//! image (`urmqtt_store::install`, mkraw-identical), verifies it and
//! powers off. The next boot from that disk is an ordinary first boot.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use urmqtt_arch::{cpu, time};
use urmqtt_log::{error, info, warn};
use urmqtt_store::BlockDevice;
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::install::{self, Candidate, Choice};

use crate::devices::{self, KernelBlk};
use crate::power;

/// The countdown in production: long enough to read the screen and reach
/// the power button.
pub const COUNTDOWN_S: u64 = 30;

fn mib(sectors: u64) -> u64 {
    (sectors * 512) >> 20
}

fn sleep_s(s: u64) {
    let until = time::uptime_ns() + s * 1_000_000_000;
    while time::uptime_ns() < until {
        cpu::wait_for_interrupt();
    }
}

/// What the bootloader loaded as the installation image.
#[derive(Clone, Copy)]
pub enum Image {
    /// An EFI system partition; the boot disk is built around it.
    Esp(&'static [u8]),
    /// A finished boot disk image (GPT, BIOS boot partition, ESP).
    Disk(&'static [u8]),
}

/// Runs the installer; never returns (the machine powers off).
pub fn run(source: Option<Image>, countdown_s: u64, fault: Option<FaultSpec>) -> ! {
    let Some(source) = source else {
        error!(
            "install: no installation image: boot the ISO's \"Install urMQTT on this machine's disk\" entry"
        );
        power::off()
    };
    let image = match source {
        Image::Esp(esp) => {
            let image = urmqtt_store::gpt::raw_image_len(esp.len() as u64);
            info!(
                "install: installation image: EFI system partition of {} KiB (blake2b checked by the bootloader), boot image {} MiB",
                esp.len() >> 10,
                image >> 20
            );
            image
        }
        Image::Disk(img) => {
            info!(
                "install: installation image: boot disk image of {} KiB for UEFI and BIOS (blake2b checked by the bootloader)",
                img.len() >> 10
            );
            img.len() as u64
        }
    };
    let (cands, names): (Vec<Candidate>, Vec<String>) = {
        let devs = devices::DEVICES.lock();
        devs.install
            .iter()
            .map(|d| {
                (
                    Candidate {
                        sectors: d.sectors,
                        read_only: d.read_only,
                        boot_medium: d.boot_medium,
                    },
                    d.name.clone(),
                )
            })
            .unzip()
    };
    let need = install::needed_sectors(image);
    for (c, n) in cands.iter().zip(&names) {
        info!(
            "install: disk {n}: {} MiB{}",
            mib(c.sectors),
            if c.boot_medium {
                ", the installation medium (skipped)"
            } else if c.read_only {
                ", read-only (skipped)"
            } else if c.sectors < need {
                ", too small (skipped)"
            } else {
                ""
            }
        );
    }
    let target = match install::choose(&cands, image) {
        Choice::Target(i) => i,
        Choice::None => {
            error!(
                "install: no disk to install onto (at least {} MiB, writable, not the installation medium); nothing written",
                mib(need)
            );
            power::off()
        }
        Choice::Several(list) => {
            let names: Vec<&str> = list
                .iter()
                .filter_map(|&i| names.get(i).map(String::as_str))
                .collect();
            error!(
                "install: {} disks could be the target ({}): refusing to guess; leave only the target attached; nothing written",
                list.len(),
                names.join(", ")
            );
            power::off()
        }
    };
    let name = names.get(target).cloned().unwrap_or_default();
    let sectors = cands.get(target).map_or(0, |c| c.sectors);
    let Some(disk) = devices::take_install_disk(target) else {
        error!("install: {name} disappeared; nothing written");
        power::off()
    };
    if !disk.has_flush() {
        error!("install: {name} cannot flush its write cache; nothing written");
        power::off()
    }
    let raw: Box<dyn BlockDevice> = Box::new(KernelBlk {
        blk: disk,
        flush: true,
    });
    let mut dev: Box<dyn BlockDevice> = match fault {
        Some(spec) => {
            warn!("disk-fault: injecting {spec:?} into the installation (dev test)");
            Box::new(FaultDevice::new(raw, spec))
        }
        None => raw,
    };
    let previous = install::holds_urmqtt_data(dev.as_mut());
    warn!(
        "install: ALL DATA ON {name} ({} MiB) WILL BE ERASED{}",
        mib(sectors),
        if previous {
            ", including its urMQTT data partition"
        } else {
            ""
        }
    );
    let mut left = countdown_s;
    while left > 0 {
        warn!("install: writing to {name} in {left} s; power off now to cancel");
        let step = left.min(5);
        sleep_s(step);
        left -= step;
    }
    info!("install: writing {} MiB to {name}", image >> 20);
    let t0 = time::uptime_ns();
    let written = match source {
        Image::Esp(esp) => install::write_image(dev.as_mut(), esp),
        Image::Disk(img) => install::write_boot_image(dev.as_mut(), img),
    };
    match written {
        Ok(n) => {
            info!(
                "install: done: {} MiB written and verified in {} ms; remove the installation medium, then boot from {name}",
                n >> 20,
                (time::uptime_ns() - t0) / 1_000_000
            );
            power::off()
        }
        Err(e) if fault.is_some() => {
            warn!("disk-fault: power cut injected during the installation ({e:?}), powering off");
            power::off()
        }
        Err(e) => {
            error!("install: failed: {e:?}; {name} does not boot now: install again");
            power::off()
        }
    }
}
