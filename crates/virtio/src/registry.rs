//! The registration point of the virtio drivers (ADR-257): one row per
//! device type that has a driver module here, whether or not this build
//! compiled it, plus the names of every other device type of the virtio 1.x
//! specification so a device without a driver is still named.
//!
//! The kernel adds the init function of each compiled driver in its own
//! table (crates/kernel/src/vdev/mod.rs), keyed by [`Kind::ty`]; a const
//! check there makes a compiled row without an init function a build error.

/// A virtio device type with a driver module in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    /// The virtio device ID (virtio 1.x §5); the modern PCI device ID is
    /// `0x1040 + ty`.
    pub ty: u16,
    /// The transitional PCI device ID (0x1000..0x103f), if the type has one.
    pub transitional: Option<u16>,
    /// The name in the boot log and the Diagnostic report.
    pub name: &'static str,
    /// The Cargo feature of this crate (and `virtio-<feature>` of the kernel).
    pub feature: &'static str,
    /// Compiled into this build.
    pub compiled: bool,
    /// The configuration key that switches it on (`[devices]`), `None` for
    /// the drivers the kernel always runs (net, blk, scsi, rng) or that have
    /// their own key elsewhere (gpu: `console.virtio_gpu`).
    pub key: Option<&'static str>,
    /// The device has a device-specific configuration structure.
    pub needs_device_cfg: bool,
}

pub const NET: u16 = 1;
pub const BLOCK: u16 = 2;
pub const CONSOLE: u16 = 3;
pub const ENTROPY: u16 = 4;
pub const BALLOON: u16 = 5;
pub const SCSI: u16 = 8;
pub const GPU: u16 = 16;
pub const INPUT: u16 = 18;
pub const VSOCK: u16 = 19;

const fn kind(
    ty: u16,
    transitional: Option<u16>,
    name: &'static str,
    feature: &'static str,
    compiled: bool,
    key: Option<&'static str>,
) -> Kind {
    Kind {
        ty,
        transitional,
        name,
        feature,
        compiled,
        key,
        needs_device_cfg: true,
    }
}

/// Every driver of this crate, in device-ID order. Adding a driver: one row
/// here (docs/DEVELOPING-DRIVERS.md).
pub const KINDS: &[Kind] = &[
    kind(
        NET,
        Some(0x1000),
        "virtio-net",
        "net",
        cfg!(feature = "net"),
        None,
    ),
    kind(
        BLOCK,
        Some(0x1001),
        "virtio-blk",
        "blk",
        cfg!(feature = "blk"),
        None,
    ),
    kind(
        CONSOLE,
        Some(0x1003),
        "virtio-console",
        "console",
        cfg!(feature = "console"),
        Some("devices.virtio_console"),
    ),
    Kind {
        // virtio-rng has no device configuration.
        needs_device_cfg: false,
        ..kind(
            ENTROPY,
            Some(0x1005),
            "virtio-rng",
            "rng",
            cfg!(feature = "rng"),
            None,
        )
    },
    kind(
        BALLOON,
        Some(0x1002),
        "virtio-balloon",
        "balloon",
        cfg!(feature = "balloon"),
        Some("devices.virtio_balloon"),
    ),
    kind(
        SCSI,
        Some(0x1004),
        "virtio-scsi",
        "scsi",
        cfg!(feature = "scsi"),
        None,
    ),
    kind(GPU, None, "virtio-gpu", "gpu", cfg!(feature = "gpu"), None),
    kind(
        INPUT,
        None,
        "virtio-input",
        "input",
        cfg!(feature = "input"),
        Some("devices.virtio_input"),
    ),
    kind(
        VSOCK,
        None,
        "virtio-vsock",
        "vsock",
        cfg!(feature = "vsock"),
        Some("devices.virtio_vsock"),
    ),
];

/// The row of device type `ty`.
pub fn kind_of(ty: u16) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.ty == ty)
}

/// The row whose configuration key is `key`.
pub fn kind_by_key(key: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.key == Some(key))
}

/// The virtio device type of a PCI function: modern IDs are 0x1040 + type,
/// transitional IDs 0x1000..0x103f carry the type in the subsystem ID.
pub fn type_of(vendor: u16, device: u16, subsystem: u16) -> Option<u16> {
    if vendor != crate::VENDOR {
        return None;
    }
    match device {
        0x1040..=0x107f => Some(device - 0x1040),
        0x1000..=0x103f => Some(subsystem),
        _ => None,
    }
}

/// A name for any virtio device type (virtio 1.x §5 and the IDs reserved
/// in §5), driven here or not.
pub fn type_name(ty: u16) -> &'static str {
    if let Some(k) = kind_of(ty) {
        return k.name;
    }
    match ty {
        0 => "virtio (reserved id 0)",
        6 => "virtio-ioMemory",
        7 => "virtio-rpmsg",
        9 => "virtio-9p",
        10 => "virtio-mac80211-wlan",
        11 => "virtio-rproc-serial",
        12 => "virtio-caif",
        13 => "virtio-memory-balloon",
        17 => "virtio-timer",
        20 => "virtio-crypto",
        21 => "virtio-signal-distribution",
        22 => "virtio-pstore",
        23 => "virtio-iommu",
        24 => "virtio-mem",
        25 => "virtio-sound",
        26 => "virtio-fs",
        27 => "virtio-pmem",
        28 => "virtio-rpmb",
        29 => "virtio-mac80211-hwsim",
        30 => "virtio-video-encoder",
        31 => "virtio-video-decoder",
        32 => "virtio-scmi",
        33 => "virtio-nitro-secure-module",
        34 => "virtio-i2c-adapter",
        35 => "virtio-watchdog",
        36 => "virtio-can",
        38 => "virtio-dmabuf",
        39 => "virtio-param-server",
        40 => "virtio-audio-policy",
        41 => "virtio-bluetooth",
        42 => "virtio-gpio",
        43 => "virtio-rdma",
        _ => "virtio (unknown type)",
    }
}

/// What the kernel does with a device the PCI scan found (the Diagnostic
/// entry and the boot line `virtio: <name> at <bdf>: <state>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The driver runs it.
    Driven,
    /// Found, the driver is compiled in, the configuration says "off".
    Off,
    /// The type has a driver module, but not in this image.
    NotCompiled,
    /// No driver exists for this type.
    NoDriver,
    /// Another device of the same type is already driven (one per type).
    Spare,
    /// A pre-1.0 device (no virtio 1.0 capabilities): not driven.
    Legacy,
    /// The capabilities the driver needs are missing.
    Incomplete,
    /// The driver's own choice (the gpu console's "auto"), or the boot path
    /// does not use it (a disk that is not the boot disk).
    NotUsed,
    /// The driver failed to bring it up.
    Failed,
}

impl State {
    /// The state as the boot log and the JSON report write it.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Driven => "driven",
            Self::Off => "off",
            Self::NotCompiled => "no driver in this image",
            Self::NoDriver => "no driver",
            Self::Spare => "not used (another device of this type is driven)",
            Self::Legacy => "legacy device (no virtio 1.0 capabilities), not driven",
            Self::Incomplete => "missing virtio 1.0 capabilities, not driven",
            Self::NotUsed => "not used",
            Self::Failed => "failed",
        }
    }
}

/// The state of a device of type `ty` before its driver is asked: what the
/// registry and the configuration (`mode_on`: the key is not "off", `None`
/// for a type without a key) already decide. `None`: the driver decides.
pub fn initial_state(ty: u16, mode_on: Option<bool>) -> Option<State> {
    match kind_of(ty) {
        None => Some(State::NoDriver),
        Some(k) if !k.compiled => Some(State::NotCompiled),
        Some(k) if k.key.is_some() && mode_on == Some(false) => Some(State::Off),
        Some(_) => None,
    }
}

/// The marker a kernel image carries so `urmqtt-config pack` can tell which
/// drivers it has without running it: `URMQTT-VIRTIO-DRIVERS:` followed by
/// the compiled features, comma separated, and a NUL.
pub const MARKER_PREFIX: &[u8] = b"URMQTT-VIRTIO-DRIVERS:";
/// Room for the marker (prefix, every feature name, separators, NUL).
pub const MARKER_LEN: usize = 256;

/// The marker of this build, NUL padded. Evaluated at compile time: an
/// index out of range is a build error, not a panic at run time.
#[allow(clippy::indexing_slicing)]
pub const fn marker() -> [u8; MARKER_LEN] {
    let mut out = [0u8; MARKER_LEN];
    let mut n = 0;
    let mut i = 0;
    while i < MARKER_PREFIX.len() {
        out[n] = MARKER_PREFIX[i];
        n += 1;
        i += 1;
    }
    let mut k = 0;
    let mut first = true;
    while k < KINDS.len() {
        let row = KINDS[k];
        if row.compiled {
            if !first {
                out[n] = b',';
                n += 1;
            }
            first = false;
            let f = row.feature.as_bytes();
            let mut j = 0;
            while j < f.len() {
                out[n] = f[j];
                n += 1;
                j += 1;
            }
        }
        k += 1;
    }
    out
}

/// The driver sets named by the markers in `image` (a kernel ELF, or an ISO
/// holding one or more): one list per marker found.
pub fn markers_in(image: &[u8]) -> alloc_free::Markers<'_> {
    alloc_free::Markers { rest: image }
}

/// Iteration over markers without an allocator (the crate is `no_std`).
pub mod alloc_free {
    use super::MARKER_PREFIX;

    pub struct Markers<'a> {
        pub(super) rest: &'a [u8],
    }

    impl<'a> Iterator for Markers<'a> {
        /// The comma-separated feature list of one marker.
        type Item = &'a [u8];

        fn next(&mut self) -> Option<&'a [u8]> {
            let at = self
                .rest
                .windows(MARKER_PREFIX.len())
                .position(|w| w == MARKER_PREFIX)?;
            let after = self.rest.get(at + MARKER_PREFIX.len()..)?;
            let end = after
                .iter()
                .take(super::MARKER_LEN)
                .position(|&b| b == 0)
                .unwrap_or(0);
            self.rest = after.get(end..).unwrap_or(&[]);
            let list = after.get(..end).unwrap_or(&[]);
            // Only feature names and commas: anything else is not a marker
            // (the prefix inside other text, e.g. this crate's source).
            if list
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b',' || *b == b'-')
            {
                Some(list)
            } else {
                self.next()
            }
        }
    }
}

/// Whether the feature list `list` (one marker) names `feature`.
pub fn list_has(list: &[u8], feature: &str) -> bool {
    list.split(|&b| b == b',').any(|f| f == feature.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_unique_and_consistent() {
        for (i, a) in KINDS.iter().enumerate() {
            for b in KINDS.iter().skip(i + 1) {
                assert_ne!(a.ty, b.ty);
                assert_ne!(a.name, b.name);
                assert_ne!(a.feature, b.feature);
                assert!(a.key.is_none() || a.key != b.key);
            }
            if let Some(t) = a.transitional {
                assert!((0x1000..=0x103f).contains(&t));
            }
            if let Some(k) = a.key {
                assert!(k.starts_with("devices.virtio_"), "{k}");
            }
            // The default features build every driver.
            assert!(a.compiled, "{}", a.name);
        }
        assert_eq!(kind_of(CONSOLE).map(|k| k.name), Some("virtio-console"));
        assert_eq!(
            kind_by_key("devices.virtio_vsock").map(|k| k.ty),
            Some(VSOCK)
        );
        assert_eq!(type_name(9), "virtio-9p");
        assert_eq!(type_name(500), "virtio (unknown type)");
    }

    #[test]
    fn the_configuration_format_names_the_same_keys_features_and_marker() {
        use urmqtt_cfg::fields::DEVICE_KEYS;
        let keyed: Vec<(&str, &str)> = KINDS
            .iter()
            .filter_map(|k| k.key.map(|key| (key, k.feature)))
            .collect();
        let cfg: Vec<(&str, &str)> = DEVICE_KEYS.iter().map(|(_, k, f)| (*k, *f)).collect();
        assert_eq!(keyed, cfg);
        assert_eq!(MARKER_PREFIX, urmqtt_cfg::drivers::MARKER_PREFIX);
        // The configuration side finds this build's marker.
        let m = marker();
        assert_eq!(urmqtt_cfg::drivers::markers(&m).count(), 1);
    }

    #[test]
    fn pci_ids_map_to_types() {
        let v = crate::VENDOR;
        assert_eq!(type_of(v, 0x1043, 0), Some(CONSOLE));
        assert_eq!(type_of(v, 0x1003, 3), Some(CONSOLE));
        assert_eq!(type_of(v, 0x1045, 0), Some(BALLOON));
        assert_eq!(type_of(v, 0x1052, 0), Some(INPUT));
        assert_eq!(type_of(v, 0x1053, 0), Some(VSOCK));
        assert_eq!(type_of(0x8086, 0x1043, 0), None);
        assert_eq!(type_of(v, 0x1100, 0), None);
        for k in KINDS {
            assert_eq!(type_of(v, 0x1040 + k.ty, 0), Some(k.ty));
            if let Some(t) = k.transitional {
                assert_eq!(type_of(v, t, k.ty), Some(k.ty));
            }
        }
    }

    #[test]
    fn the_registry_and_the_configuration_decide_first() {
        assert_eq!(initial_state(9, None), Some(State::NoDriver));
        assert_eq!(initial_state(CONSOLE, Some(false)), Some(State::Off));
        assert_eq!(initial_state(CONSOLE, Some(true)), None);
        // net has no key: the configuration never turns it off.
        assert_eq!(initial_state(NET, Some(false)), None);
        assert_eq!(State::NotCompiled.word(), "no driver in this image");
    }

    #[test]
    fn the_marker_lists_the_compiled_features_and_is_found_in_an_image() {
        let m = marker();
        let mut image = b"junk URMQTT-VIRTIO-DRIVERS:not a list!\0 more ".to_vec();
        image.extend_from_slice(&m);
        image.extend_from_slice(b"tail");
        let found: Vec<&[u8]> = markers_in(&image).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0],
            b"net,blk,console,rng,balloon,scsi,gpu,input,vsock".as_slice()
        );
        assert!(list_has(found[0], "vsock") && !list_has(found[0], "vso"));
        // Two kernels in one ISO: two markers.
        let mut two = m.to_vec();
        two.extend_from_slice(&m);
        assert_eq!(markers_in(&two).count(), 2);
        assert_eq!(markers_in(b"nothing here").count(), 0);
    }
}
