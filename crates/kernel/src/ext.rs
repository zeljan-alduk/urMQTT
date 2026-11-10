//! The extension API of the kernel library (NOW-18, ADR-335 to ADR-339).
//!
//! A kernel image names one [`Edition`] with [`image!`](crate::image): the
//! open edition ([`Edition::OPEN`]) adds nothing; an edition built in
//! another repository (docs/EDITIONS.md §5) adds
//!
//! - **PCI drivers** ([`PciDriver`]), bound by vendor/device ID or by class
//!   ([`PciId`]) to the PCI functions the open kernel does not drive. A
//!   function with the virtio vendor ID is never offered to them, and an ID
//!   that names the virtio vendor is refused when the image is compiled: the
//!   open drivers bind exactly as they do without the edition (ADR-336).
//! - **configuration keys** in the reserved tag range `0xF000..=0xFFFE`
//!   under the TOML table `[ext]` (`urmqtt_cfg::ext`, ADR-337), read with
//!   [`config_bool`], [`config_uint`], [`config_variant`], [`config_str`]
//!   and [`config_strs`].
//! - **boot hooks** ([`Hooks`]): once the heap and the self-tests are up, after
//!   the device probe, just before `URMQTT READY`, and on the boot CPU's
//!   10 ms tick (ADR-338).
//!
//! The edition is checked by a `const fn` ([`Edition::check`]) when the image
//! is compiled; a table that breaks a rule is a build error, never a boot
//! surprise. The open edition's image logs nothing more and does nothing
//! more than before the kernel became a library: every path below starts
//! with an empty table or an absent hook.

use alloc::string::String;

use urmqtt_cfg::fields::Field;

/// The PCI vendor ID of every virtio device (docs/EDITIONS.md §1). Never
/// offered to an edition's driver.
pub const VIRTIO_VENDOR: u16 = 0x1af4;
/// The most PCI drivers one edition may register.
pub const MAX_PCI_DRIVERS: usize = 32;
/// The longest driver or edition name.
pub const MAX_NAME: usize = 32;

/// What a kernel image adds to the open kernel.
#[derive(Clone, Copy)]
pub struct Edition {
    /// Named in the boot log (`edition: <name>: ...`) when the edition adds
    /// anything; `[a-z0-9-]`, at most [`MAX_NAME`] bytes.
    pub name: &'static str,
    /// Tried in this order for every PCI function no open driver claims.
    pub pci_drivers: &'static [PciDriver],
    /// The edition's configuration keys (`urmqtt_cfg::ext::check`).
    pub config: &'static [Field],
    pub hooks: Hooks,
}

/// Functions the kernel calls at fixed points of the boot and run time. Each
/// runs on the boot CPU; none may return an error (a hook that cannot go on
/// logs and returns, or calls [`fatal`]).
#[derive(Clone, Copy)]
pub struct Hooks {
    /// On the kernel's own stacks, once the heap and the crypto self-tests
    /// are up (the configuration is loaded and reported), before interrupts
    /// and before any device is probed.
    pub early: Option<fn()>,
    /// After the PCI scan and every probe (the edition's drivers included),
    /// while device memory can still be mapped.
    pub devices: Option<fn()>,
    /// Just before `URMQTT READY`: the broker's services are set up, no
    /// connection is served yet.
    pub ready: Option<fn()>,
    /// Every 10 ms on the boot CPU, in interrupt context: bounded work only,
    /// never a lock that can wait (try locks).
    pub tick: Option<fn()>,
}

impl Hooks {
    pub const NONE: Self = Self {
        early: None,
        devices: None,
        ready: None,
        tick: None,
    };

    const fn is_none(&self) -> bool {
        self.early.is_none()
            && self.devices.is_none()
            && self.ready.is_none()
            && self.tick.is_none()
    }
}

/// Which PCI functions a driver binds. Every field that is `Some` must match;
/// a `device` needs a `vendor`, a `subclass` needs a `class`, and at least a
/// vendor or a class is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciId {
    pub vendor: Option<u16>,
    pub device: Option<u16>,
    pub class: Option<u8>,
    pub subclass: Option<u8>,
}

const fn eq8(want: Option<u8>, got: u8) -> bool {
    match want {
        Some(w) => w == got,
        None => true,
    }
}

const fn eq16(want: Option<u16>, got: u16) -> bool {
    match want {
        Some(w) => w == got,
        None => true,
    }
}

impl PciId {
    /// One vendor:device pair.
    pub const fn device(vendor: u16, device: u16) -> Self {
        Self {
            vendor: Some(vendor),
            device: Some(device),
            class: None,
            subclass: None,
        }
    }

    /// Every device of one vendor.
    pub const fn vendor(vendor: u16) -> Self {
        Self {
            vendor: Some(vendor),
            device: None,
            class: None,
            subclass: None,
        }
    }

    /// Every device of one class and subclass (for example `01:08`, NVMe).
    pub const fn class(class: u8, subclass: u8) -> Self {
        Self {
            vendor: None,
            device: None,
            class: Some(class),
            subclass: Some(subclass),
        }
    }

    /// Whether a function with these IDs matches. A function of the virtio
    /// vendor never does.
    pub const fn matches(&self, vendor: u16, device: u16, class: u8, subclass: u8) -> bool {
        if vendor == VIRTIO_VENDOR {
            return false;
        }
        eq16(self.vendor, vendor)
            && eq16(self.device, device)
            && eq8(self.class, class)
            && eq8(self.subclass, subclass)
    }

    const fn check(&self) -> Result<(), &'static str> {
        if self.vendor.is_none() && self.class.is_none() {
            return Err("a PciId needs a vendor or a class");
        }
        if self.device.is_some() && self.vendor.is_none() {
            return Err("a PciId with a device needs its vendor");
        }
        if self.subclass.is_some() && self.class.is_none() {
            return Err("a PciId with a subclass needs its class");
        }
        if let Some(v) = self.vendor
            && (v == VIRTIO_VENDOR || v == 0xffff)
        {
            return Err(
                "a PciId may not name the virtio vendor 0x1af4 (the open edition's drivers) or 0xffff",
            );
        }
        Ok(())
    }
}

/// Brings up one PCI function. `Ok`: a detail for the boot line
/// (`ext: <name> at <bdf>: driven: <detail>`); `Err`: why not (`failed`).
pub type Probe = fn(&mut PciDevice<'_>) -> Result<String, String>;

/// A PCI driver of an edition.
#[derive(Clone, Copy)]
pub struct PciDriver {
    /// For the boot log and the Diagnostic report; `[a-z0-9-]`, at most
    /// [`MAX_NAME`] bytes, unique in the edition.
    pub name: &'static str,
    /// The functions it binds (any of them).
    pub ids: &'static [PciId],
    /// How many functions it drives at most; the others are left alone and
    /// logged as spare.
    pub max: usize,
    pub probe: Probe,
}

#[allow(clippy::indexing_slicing)] // const fn: every index is below the length the loop checks
const fn name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > MAX_NAME {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

#[allow(clippy::indexing_slicing)] // as in `name_ok`
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl Edition {
    /// The open edition: no driver, no key, no hook.
    pub const OPEN: Self = Self {
        name: "open",
        pci_drivers: &[],
        config: &[],
        hooks: Hooks::NONE,
    };

    /// Whether this edition adds nothing (the open kernel's behaviour).
    pub const fn adds_nothing(&self) -> bool {
        self.pci_drivers.is_empty() && self.config.is_empty() && self.hooks.is_none()
    }

    /// The rules of an edition, checked when its image is compiled
    /// ([`image!`](crate::image)): a valid name; at most [`MAX_PCI_DRIVERS`]
    /// drivers with valid, unique names, at least one ID each, every ID
    /// valid (none names the virtio vendor) and `max` at least 1; the
    /// configuration table valid (`urmqtt_cfg::ext::check`).
    #[allow(clippy::indexing_slicing)] // as in `name_ok`
    pub const fn check(&self) -> Result<(), &'static str> {
        if !name_ok(self.name) {
            return Err("the edition's name must be [a-z0-9-], 1 to 32 bytes");
        }
        let d = self.pci_drivers;
        if d.len() > MAX_PCI_DRIVERS {
            return Err("an edition registers at most 32 PCI drivers");
        }
        let mut i = 0;
        while i < d.len() {
            if !name_ok(d[i].name) {
                return Err("a PCI driver's name must be [a-z0-9-], 1 to 32 bytes");
            }
            let mut j = 0;
            while j < i {
                if same(d[j].name, d[i].name) {
                    return Err("two PCI drivers have the same name");
                }
                j += 1;
            }
            if d[i].ids.is_empty() {
                return Err("a PCI driver needs at least one PciId");
            }
            if d[i].max == 0 {
                return Err("a PCI driver's max must be at least 1");
            }
            let mut k = 0;
            while k < d[i].ids.len() {
                if let Err(e) = d[i].ids[k].check() {
                    return Err(e);
                }
                k += 1;
            }
            i += 1;
        }
        urmqtt_cfg::ext::check(self.config)
    }
}

/// Names the kernel image's edition: in a kernel binary crate's `main.rs`,
///
/// ```text
/// #![cfg_attr(target_os = "none", no_std, no_main)]
/// urmqtt_kernel::image!(urmqtt_kernel::ext::Edition::OPEN);
/// ```
///
/// `$edition` is a constant expression of type [`Edition`]. It is checked
/// when the crate is compiled ([`Edition::check`]). On the kernel target the
/// macro defines `urmqtt_kmain`, the symbol the boot CPU's entry code calls;
/// on the host it defines `main`, which says that this is a bare-metal kernel.
#[macro_export]
macro_rules! image {
    ($edition:expr) => {
        #[cfg(target_os = "none")]
        const _: () = {
            if let Err(e) = $crate::ext::Edition::check(&$edition) {
                panic!("{}", e);
            }
        };

        // SAFETY: `urmqtt_kmain` is a unique symbol (one image per binary);
        // the arch `_start` stubs call it once per boot, on the boot CPU, with
        // the C ABI and no arguments.
        #[cfg(target_os = "none")]
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        extern "C" fn urmqtt_kmain() -> ! {
            static EDITION: $crate::ext::Edition = $edition;
            $crate::__kmain(&EDITION)
        }

        #[cfg(not(target_os = "none"))]
        fn main() {
            $crate::__host_main()
        }
    };
}

#[cfg(not(target_os = "none"))]
pub use host::PciDevice;
#[cfg(target_os = "none")]
pub use kernel::{
    PciDevice, config_bool, config_str, config_strs, config_uint, config_variant, edition, fatal,
};
#[cfg(target_os = "none")]
pub(crate) use kernel::{after_probe, before_ready, early, install, load_config, probe_pci, tick};

/// On the host there is no device: the type exists so that an edition's
/// tables type-check in host builds (clippy, tests); it is never made.
#[cfg(not(target_os = "none"))]
mod host {
    pub struct PciDevice<'a> {
        _never: core::convert::Infallible,
        _cfg: core::marker::PhantomData<&'a mut ()>,
    }
}

#[cfg(target_os = "none")]
mod kernel {
    use alloc::vec::Vec;

    use urmqtt_cfg::blob::{Blob, StrIter};
    use urmqtt_cfg::fields::Field;
    use urmqtt_log::{info, warn};
    use urmqtt_pci::{Bar, Bdf, ConfigSpace, Function};
    use urmqtt_sync::sync::{OnceCell, SpinLock};
    use urmqtt_virtio::{DmaRegion, Env, Region};

    use super::{Edition, VIRTIO_VENDOR};
    use crate::devices::{Cfg, KernelEnv, PCI_SEEN};

    static EDITION: OnceCell<&'static Edition> = OnceCell::new();
    /// The configuration blob as the edition reads it; unset for the open
    /// edition, or when the image has no configuration module (defaults).
    static BLOB: OnceCell<Blob<'static>> = OnceCell::new();
    /// The functions the edition's drivers drive: (driver, bdf).
    static BOUND: SpinLock<Vec<(&'static str, Bdf)>> = SpinLock::new(Vec::new());

    /// The image's edition (the open one until [`install`] runs).
    pub fn edition() -> &'static Edition {
        EDITION.get().copied().unwrap_or(&Edition::OPEN)
    }

    /// Called first thing at boot by `__kmain`.
    pub(crate) fn install(e: &'static Edition) {
        let _ = EDITION.set(e);
    }

    /// The configuration module's blob as the edition sees it (its extension
    /// records accepted). Called right after `urmqtt_config::load_ext`
    /// accepted the same bytes; the open edition does nothing here.
    pub(crate) fn load_config(slot: Option<&'static [u8]>) {
        let e = edition();
        if e.config.is_empty() {
            return;
        }
        let Some(blob) = slot
            .and_then(|s| urmqtt_config::blob_in(s).ok())
            .and_then(|b| Blob::parse_ext(b, e.config).ok())
        else {
            return;
        };
        let _ = BLOB.set(blob);
    }

    fn blob() -> Option<&'static Blob<'static>> {
        BLOB.get()
    }

    /// A `Bool` key of the edition: the configured value or the field's default.
    pub fn config_bool(f: &Field) -> bool {
        urmqtt_cfg::ext::bool_of(blob(), f)
    }

    /// A `UInt` key of the edition.
    pub fn config_uint(f: &Field) -> u64 {
        urmqtt_cfg::ext::uint_of(blob(), f)
    }

    /// An `Enum` key of the edition: the variant's name.
    pub fn config_variant(f: &Field) -> &'static str {
        urmqtt_cfg::ext::variant_of(blob(), f)
    }

    /// A `Str` key of the edition.
    pub fn config_str(f: &Field) -> &'static str {
        urmqtt_cfg::ext::str_of(blob(), f)
    }

    /// A `Strs` key of the edition.
    pub fn config_strs(f: &Field) -> StrIter<'static> {
        urmqtt_cfg::ext::strs_of(blob(), f)
    }

    /// Stops the kernel with a message, as the open kernel does for a
    /// configuration it cannot serve.
    pub fn fatal(msg: &str) -> ! {
        crate::boot::fatal(msg)
    }

    /// After the configuration is reported: one line for an edition that adds
    /// anything (none for the open edition), then its `early` hook.
    pub(crate) fn early() {
        let e = edition();
        if e.adds_nothing() {
            return;
        }
        info!(
            "edition: {}: {} PCI driver(s), {} configuration key(s), hooks:{}{}{}{}",
            e.name,
            e.pci_drivers.len(),
            e.config.len(),
            if e.hooks.early.is_some() {
                " early"
            } else {
                ""
            },
            if e.hooks.devices.is_some() {
                " devices"
            } else {
                ""
            },
            if e.hooks.ready.is_some() {
                " ready"
            } else {
                ""
            },
            if e.hooks.tick.is_some() { " tick" } else { "" },
        );
        if let Some(h) = e.hooks.early {
            h();
        }
    }

    pub(crate) fn after_probe() {
        if let Some(h) = edition().hooks.devices {
            h();
        }
    }

    pub(crate) fn before_ready() {
        if let Some(h) = edition().hooks.ready {
            h();
        }
    }

    /// The boot CPU's tick (interrupt context).
    pub(crate) fn tick() {
        if let Some(h) = edition().hooks.tick
            && crate::smp::current() == 0
        {
            h();
        }
    }

    /// Offers the PCI function `f`, which no open driver claims, to the
    /// edition's drivers: the first whose IDs match and that has room binds it.
    pub(crate) fn probe_pci(cfg: &mut Cfg, f: &Function) {
        let e = edition();
        if e.pci_drivers.is_empty() || f.vendor == VIRTIO_VENDOR || f.bridge {
            return;
        }
        let Some(d) = e.pci_drivers.iter().find(|d| {
            d.ids
                .iter()
                .any(|id| id.matches(f.vendor, f.device, f.class, f.subclass))
        }) else {
            return;
        };
        let bound = BOUND.lock().iter().filter(|(n, _)| *n == d.name).count();
        if bound >= d.max {
            info!("ext: {} at {}: spare (it drives {bound})", d.name, f.bdf);
            return;
        }
        let mut dev = PciDevice {
            cfg,
            f: *f,
            env: KernelEnv::device(f.bdf),
        };
        match (d.probe)(&mut dev) {
            Ok(detail) => {
                let sep = if detail.is_empty() { "" } else { ": " };
                info!("ext: {} at {}: driven{sep}{detail}", d.name, f.bdf);
                BOUND.lock().push((d.name, f.bdf));
                let bdf = alloc::format!("{}", f.bdf);
                if let Some(p) = PCI_SEEN.lock().iter_mut().find(|p| p.bdf == bdf) {
                    p.driver = Some(d.name);
                }
            }
            Err(why) => warn!("ext: {} at {}: failed: {why}", d.name, f.bdf),
        }
    }

    /// One PCI function, handed to a [`super::PciDriver`]'s probe: its
    /// configuration space, its memory BARs and DMA memory in its own IOMMU
    /// domain. A driver reaches only this function through it.
    pub struct PciDevice<'a> {
        cfg: &'a mut Cfg,
        f: Function,
        env: KernelEnv,
    }

    impl PciDevice<'_> {
        pub fn bdf(&self) -> Bdf {
            self.f.bdf
        }

        pub fn vendor(&self) -> u16 {
            self.f.vendor
        }

        pub fn device(&self) -> u16 {
            self.f.device
        }

        pub fn class(&self) -> (u8, u8) {
            (self.f.class, self.f.subclass)
        }

        pub fn subsystem(&self) -> u16 {
            self.f.subsystem
        }

        /// A 32-bit word of the function's configuration space (`off` is
        /// rounded down to 4 bytes; beyond 4 KiB reads as all ones).
        pub fn config_read32(&self, off: u16) -> u32 {
            if off >= 4096 {
                return u32::MAX;
            }
            self.cfg.read32(self.f.bdf, off & !3)
        }

        /// Writes a 32-bit word of the function's configuration space.
        pub fn config_write32(&mut self, off: u16, v: u32) {
            if off < 4096 {
                self.cfg.write32(self.f.bdf, off & !3, v);
            }
        }

        /// Turns on memory decoding and, with `bus_master`, DMA.
        pub fn enable(&mut self, bus_master: bool) {
            let bits = urmqtt_pci::CMD_MEMORY
                | if bus_master {
                    urmqtt_pci::CMD_BUS_MASTER
                } else {
                    0
                };
            urmqtt_pci::enable(self.cfg, self.f.bdf, bits);
        }

        /// Memory BAR `index` as (physical base, size), as the firmware
        /// programmed it.
        pub fn bar(&mut self, index: u8) -> Option<(u64, u64)> {
            let Some(Bar::Memory { base, .. }) = urmqtt_pci::bar(&*self.cfg, self.f.bdf, index)
            else {
                return None;
            };
            let size = urmqtt_pci::bar_size(self.cfg, self.f.bdf, index)?;
            Some((base, size))
        }

        /// Maps the first `len` bytes of memory BAR `index` (at most the BAR,
        /// at most 16 MiB) as device memory for the kernel's lifetime, with
        /// bounds-checked volatile access. Only during the probe (device
        /// memory is mapped before the page tables are locked).
        pub fn map_bar(&mut self, index: u8, len: u64) -> Result<Region, &'static str> {
            const MAX_MAP: u64 = 16 << 20;
            let (base, size) = self.bar(index).ok_or("no such memory BAR")?;
            if len == 0 || len > size || len > MAX_MAP {
                return Err("the length is zero, larger than the BAR or larger than 16 MiB");
            }
            let va = crate::memory::map_mmio(base, len).map_err(|_| "mapping the BAR failed")?;
            let len = usize::try_from(len).map_err(|_| "the length does not fit")?;
            // SAFETY: `[va, va + len)` was just mapped as device memory by
            // `map_mmio`, which never unmaps; `Region` checks every access
            // against `len`.
            #[allow(unsafe_code)]
            let r = unsafe { Region::new(va as usize, len) };
            Ok(r)
        }

        /// Zeroed, physically contiguous memory the device may access by DMA
        /// (mapped into its IOMMU domain when an IOMMU is in use).
        pub fn dma_alloc(&self, bytes: usize) -> Option<DmaRegion> {
            self.env.dma_alloc(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use urmqtt_cfg::fields::Kind;

    fn probe(_: &mut PciDevice<'_>) -> Result<String, String> {
        Ok(String::new())
    }

    const EDU: PciDriver = PciDriver {
        name: "edu",
        ids: &[PciId::device(0x1234, 0x11e8)],
        max: 1,
        probe,
    };

    fn with(d: &'static [PciDriver]) -> Edition {
        Edition {
            name: "test",
            pci_drivers: d,
            ..Edition::OPEN
        }
    }

    #[test]
    fn the_open_edition_adds_nothing_and_is_valid() {
        assert!(Edition::OPEN.adds_nothing());
        assert_eq!(Edition::OPEN.check(), Ok(()));
        assert!(!with(&[EDU]).adds_nothing());
        assert_eq!(with(&[EDU]).check(), Ok(()));
        let hooked = Edition {
            hooks: Hooks {
                tick: Some(|| {}),
                ..Hooks::NONE
            },
            ..Edition::OPEN
        };
        assert!(!hooked.adds_nothing());
    }

    #[test]
    fn a_virtio_function_never_matches() {
        for id in [
            PciId::class(0x02, 0x00),
            PciId::class(0x01, 0x00),
            PciId {
                vendor: None,
                device: None,
                class: Some(0x02),
                subclass: None,
            },
        ] {
            assert_eq!(id.check(), Ok(()));
            // virtio-net (modern and transitional), virtio-blk, virtio-scsi
            assert!(!id.matches(VIRTIO_VENDOR, 0x1041, 0x02, 0x00));
            assert!(!id.matches(VIRTIO_VENDOR, 0x1000, 0x02, 0x00));
            assert!(!id.matches(VIRTIO_VENDOR, 0x1001, 0x01, 0x00));
        }
        assert!(PciId::class(0x02, 0x00).matches(0x1d0f, 0xec20, 0x02, 0x00));
        assert!(!PciId::class(0x02, 0x00).matches(0x1d0f, 0xec20, 0x02, 0x80));
        assert!(PciId::device(0x1234, 0x11e8).matches(0x1234, 0x11e8, 0x00, 0xff));
        assert!(!PciId::device(0x1234, 0x11e8).matches(0x1234, 0x11e9, 0x00, 0xff));
        assert!(PciId::vendor(0x15ad).matches(0x15ad, 0x07b0, 0x02, 0x00));
    }

    #[test]
    fn bad_editions_are_refused() {
        let bad = |e: Edition| e.check().is_err();
        for id in [
            PciId::vendor(VIRTIO_VENDOR),
            PciId::device(VIRTIO_VENDOR, 0x1041),
            PciId::vendor(0xffff),
            PciId {
                vendor: None,
                device: Some(1),
                class: Some(2),
                subclass: None,
            },
            PciId {
                vendor: None,
                device: None,
                class: None,
                subclass: Some(1),
            },
            PciId {
                vendor: None,
                device: None,
                class: None,
                subclass: None,
            },
        ] {
            let d: &'static [PciDriver] = Box::leak(Box::new([PciDriver {
                ids: Box::leak(Box::new([id])),
                ..EDU
            }]));
            assert!(bad(with(d)), "{id:?}");
        }
        for name in ["", "Edu", "a b", "a_b", "123456789012345678901234567890123"] {
            let d: &'static [PciDriver] = Box::leak(Box::new([PciDriver { name, ..EDU }]));
            assert!(bad(with(d)), "{name:?}");
            assert!(bad(Edition {
                name,
                ..Edition::OPEN
            }));
        }
        assert!(bad(with(&[EDU, EDU])), "duplicate names");
        assert!(bad(with(&[PciDriver { ids: &[], ..EDU }])));
        assert!(bad(with(&[PciDriver { max: 0, ..EDU }])));
        let many: &'static [PciDriver] = Box::leak(
            (0..=MAX_PCI_DRIVERS)
                .map(|i| PciDriver {
                    name: Box::leak(format!("d{i}").into_boxed_str()),
                    ..EDU
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        assert!(bad(with(many)));
        // The configuration table follows urmqtt_cfg's rules.
        let key = urmqtt_cfg::ext::field(0x0100, "ext.a.b", Kind::Bool(false), "", 2);
        assert!(bad(Edition {
            config: Box::leak(Box::new([key])),
            ..Edition::OPEN
        }));
        let key = urmqtt_cfg::ext::field(0xF000, "ext.a.b", Kind::Bool(false), "", 2);
        assert!(!bad(Edition {
            config: Box::leak(Box::new([key])),
            ..Edition::OPEN
        }));
    }
}
