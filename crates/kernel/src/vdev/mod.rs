//! The virtio driver table of the kernel (ADR-257) and what the probe found.
//!
//! [`DRIVERS`] has one row per row of `urmqtt_virtio::registry::KINDS`: the
//! drivers with a path of their own in `devices.rs` (net, blk, scsi, rng and
//! the gpu console) are `Builtin`; every other driver is `Generic`, started
//! by [`probe_generic`] through its init function when its `[devices]` key
//! is not "off". A const check makes a compiled driver without an init
//! function (or a row missing) a build error.
//!
//! Every virtio function the scan sees is recorded once with its final
//! state ([`record`]): the boot log line `virtio: <name> at <bdf>: <state>`
//! and the Diagnostic report's `virtio` list come from it.

use alloc::string::String;
use alloc::vec::Vec;

use urmqtt_log::{info, warn};
use urmqtt_pci::Bdf;
use urmqtt_sync::sync::SpinLock;
use urmqtt_virtio::registry::{self, KINDS, State};
use urmqtt_virtio::{Support, VirtioCaps};

use crate::devices::{Cfg, KernelEnv};

pub mod balloon;
pub mod console;
pub mod input;
pub mod vsock;

/// Starts a generic driver on a modern device whose PCI memory and bus
/// mastering are enabled. `Ok`: a detail for the boot line; `Err`: why not.
pub type Init = fn(&mut Cfg, &KernelEnv, Bdf, &VirtioCaps) -> Result<String, String>;

#[derive(Clone, Copy)]
pub enum Path {
    /// Brought up by its own code in `devices.rs`.
    Builtin,
    /// Brought up here; `None` when the driver is not compiled in.
    Generic { init: Option<Init>, max: usize },
}

#[derive(Clone, Copy)]
pub struct Driver {
    pub ty: u16,
    pub path: Path,
}

/// The registration point of the kernel: one row per `KINDS` row.
pub const DRIVERS: &[Driver] = &[
    Driver {
        ty: registry::NET,
        path: Path::Builtin,
    },
    Driver {
        ty: registry::BLOCK,
        path: Path::Builtin,
    },
    Driver {
        ty: registry::CONSOLE,
        path: Path::Generic {
            init: console::INIT,
            max: 1,
        },
    },
    Driver {
        ty: registry::ENTROPY,
        path: Path::Builtin,
    },
    Driver {
        ty: registry::BALLOON,
        path: Path::Generic {
            init: balloon::INIT,
            max: 1,
        },
    },
    Driver {
        ty: registry::SCSI,
        path: Path::Builtin,
    },
    Driver {
        ty: registry::GPU,
        path: Path::Builtin,
    },
    Driver {
        ty: registry::INPUT,
        path: Path::Generic {
            init: input::INIT,
            max: input::MAX_DEVICES,
        },
    },
    Driver {
        ty: registry::VSOCK,
        path: Path::Generic {
            init: vsock::INIT,
            max: 1,
        },
    },
];

/// Every `KINDS` row has a `DRIVERS` row in the same place, and a generic
/// driver has an init function exactly when it is compiled in.
const fn table_is_complete() -> bool {
    if KINDS.len() != DRIVERS.len() {
        return false;
    }
    let mut i = 0;
    while i < KINDS.len() {
        let (k, d) = (&KINDS[i], &DRIVERS[i]);
        if k.ty != d.ty {
            return false;
        }
        if let Path::Generic { init, max } = d.path
            && (init.is_some() != k.compiled || max == 0 || k.key.is_none())
        {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    table_is_complete(),
    "crates/kernel/src/vdev: DRIVERS must have one row per urmqtt_virtio::registry::KINDS row, \
     with an init function exactly for the compiled generic drivers"
);

/// The driver set this kernel was built with, for `urmqtt-config pack`
/// (`--iso`, `--kernel`): kept in the image by `#[used]`.
#[used]
static DRIVER_MARKER: [u8; registry::MARKER_LEN] = registry::marker();

/// The features in this image's marker, comma separated (also keeps the
/// marker in the image: `black_box` makes the compiler and the linker keep
/// the static whole).
pub fn drivers_in_image() -> &'static str {
    let m: &'static [u8; registry::MARKER_LEN] = core::hint::black_box(&DRIVER_MARKER);
    let list = m.get(registry::MARKER_PREFIX.len()..).unwrap_or(&[]);
    let end = list.iter().position(|&b| b == 0).unwrap_or(list.len());
    core::str::from_utf8(list.get(..end).unwrap_or(&[])).unwrap_or("?")
}

/// A virtio function the scan saw, for the Diagnostic report.
#[derive(Clone)]
pub struct Seen {
    pub bdf: String,
    pub ty: u16,
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

pub static SEEN: SpinLock<Vec<Seen>> = SpinLock::new(Vec::new());

/// Records the final state of the virtio function at `bdf` and logs it
/// (warnings for failures; every other state is information).
pub fn record(bdf: Bdf, ty: u16, state: State, detail: &str) {
    let name = registry::type_name(ty);
    let sep = if detail.is_empty() { "" } else { ": " };
    if state == State::Failed {
        warn!("virtio: {name} at {bdf}: {}{sep}{detail}", state.word());
    } else {
        info!("virtio: {name} at {bdf}: {}{sep}{detail}", state.word());
    }
    let bdf = alloc::format!("{bdf}");
    if state == State::Driven
        && let Some(p) = crate::devices::PCI_SEEN
            .lock()
            .iter_mut()
            .find(|p| p.bdf == bdf)
    {
        p.driver.get_or_insert(name);
    }
    let mut seen = SEEN.lock();
    if seen.len() < 64 {
        seen.push(Seen {
            bdf,
            ty,
            name,
            state,
            detail: detail.into(),
        });
    }
}

/// The row of type `ty`.
pub fn driver(ty: u16) -> Option<&'static Driver> {
    DRIVERS.iter().find(|d| d.ty == ty)
}

/// The configured mode of a generic driver's key (`None`: no key).
fn mode_of(ty: u16) -> Option<urmqtt_config::DeviceMode> {
    let key = registry::kind_of(ty)?.key?;
    urmqtt_config::CONFIG.devices.mode(key)
}

/// Brings up the device of a generic type at `bdf` (or records why not):
/// the configuration, whether the driver is compiled in, the device's
/// capabilities and how many of its type are already driven decide.
pub fn probe_generic(cfg: &mut Cfg, env: &KernelEnv, bdf: Bdf, device: u16, ty: u16) {
    let mode = mode_of(ty);
    let on = mode.map(|m| m != urmqtt_config::DeviceMode::Off);
    if let Some(state) = registry::initial_state(ty, on) {
        let detail = match (state, registry::kind_of(ty), mode) {
            (State::Off, Some(k), _) => alloc::format!("{} = \"off\"", k.key.unwrap_or("?")),
            (State::NotCompiled, Some(k), _) => {
                alloc::format!("built without the kernel feature virtio-{}", k.feature)
            }
            (State::NoDriver, _, _) => alloc::format!("type {ty}"),
            _ => String::new(),
        };
        record(bdf, ty, state, &detail);
        return;
    }
    let Some(Driver {
        path: Path::Generic {
            init: Some(init),
            max,
        },
        ..
    }) = driver(ty)
    else {
        record(bdf, ty, State::NoDriver, "");
        return;
    };
    let driven = SEEN
        .lock()
        .iter()
        .filter(|s| s.ty == ty && s.state == State::Driven)
        .count();
    if driven >= *max {
        record(bdf, ty, State::Spare, "");
        return;
    }
    let caps = urmqtt_virtio::find_caps(cfg, bdf);
    let needs_cfg = registry::kind_of(ty).is_none_or(|k| k.needs_device_cfg);
    match caps.support(device, needs_cfg) {
        Support::Modern => {}
        Support::LegacyOnly => {
            record(
                bdf,
                ty,
                State::Legacy,
                "attach it as a modern device (disable-legacy=on)",
            );
            return;
        }
        Support::Incomplete => {
            record(bdf, ty, State::Incomplete, "");
            return;
        }
    }
    urmqtt_pci::enable(
        cfg,
        bdf,
        urmqtt_pci::CMD_MEMORY | urmqtt_pci::CMD_BUS_MASTER,
    );
    match init(cfg, env, bdf, &caps) {
        Ok(detail) => record(bdf, ty, State::Driven, &detail),
        Err(why) => record(bdf, ty, State::Failed, &why),
    }
}

/// After the scan: a `[devices]` key that is not "off" for a driver this
/// image lacks, or "on" with no such device, is a warning (ADR-257: never a
/// silent skip). `urmqtt-config pack` refuses the first case when it sees
/// the kernel; this catches a configuration packed without it.
pub fn check_configuration() {
    for d in DRIVERS {
        let Path::Generic { init, .. } = d.path else {
            continue;
        };
        let (Some(k), Some(mode)) = (registry::kind_of(d.ty), mode_of(d.ty)) else {
            continue;
        };
        let key = k.key.unwrap_or("?");
        if mode == urmqtt_config::DeviceMode::Off {
            continue;
        }
        if init.is_none() {
            warn!(
                "virtio: {key} = \"{}\" but this image has no {} driver (built without the kernel feature virtio-{}): \
                 the device is NOT driven",
                mode.name(),
                k.name,
                k.feature
            );
            continue;
        }
        let found = SEEN.lock().iter().any(|s| s.ty == d.ty);
        if !found && mode == urmqtt_config::DeviceMode::On {
            warn!("virtio: {key} = \"on\" but no {} device was found", k.name);
        }
    }
    #[cfg(not(feature = "virtio-gpu"))]
    if urmqtt_config::CONFIG.console.virtio_gpu != urmqtt_config::VirtioGpuMode::Off {
        warn!(
            "virtio: console.virtio_gpu = \"{}\" but this image has no virtio-gpu driver (built without the kernel \
             feature virtio-gpu)",
            urmqtt_config::CONFIG.console.virtio_gpu.name()
        );
    }
}

/// One byte typed on a driven virtio-console or virtio-input keyboard, for
/// the Diagnostic entry's prompts. Never waits.
pub fn read_byte() -> Option<u8> {
    console::read_byte().or_else(input::read_byte)
}

/// The boot CPU's tick (every 10 ms, interrupt context): the balloon's
/// statistics and the vsock service. Only tries the device locks.
pub fn tick() {
    if crate::smp::current() != 0 {
        return;
    }
    balloon::tick();
    vsock::tick();
}

/// What the drivers did, at READY (after the boot's own lines).
pub fn report() {
    console::report();
    balloon::report();
    input::report();
    vsock::report();
}

/// Lines for the Diagnostic report: (bdf, type, name, state, detail).
pub fn diag_list() -> Vec<urmqtt_diag::report::VirtioFn> {
    SEEN.lock()
        .iter()
        .map(|s| urmqtt_diag::report::VirtioFn {
            bdf: s.bdf.clone(),
            ty: s.ty,
            name: s.name.into(),
            state: s.state.word().into(),
            detail: s.detail.clone(),
        })
        .collect()
}
