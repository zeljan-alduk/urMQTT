//! Which optional virtio drivers a configuration asks for, and whether a
//! kernel image has them (ADR-257).
//!
//! A kernel carries a marker, `URMQTT-VIRTIO-DRIVERS:` followed by the
//! features it was built with, comma separated, and a NUL
//! (`urmqtt_virtio::registry::marker`). `urmqtt-config pack --iso` and
//! `--kernel` look for it, so a `[devices]` key that is not "off" for a
//! driver the image lacks is refused when the image is made, not discovered
//! at boot. An image without any marker predates the `[devices]` keys and
//! cannot read them anyway (its configuration format is older than 6).

use crate::blob::Blob;
use crate::fields::DEVICE_KEYS;

/// The marker's prefix (equal to `urmqtt_virtio::registry::MARKER_PREFIX`).
pub const MARKER_PREFIX: &[u8] = b"URMQTT-VIRTIO-DRIVERS:";
/// Longest feature list a marker holds.
const MARKER_MAX: usize = 256;

/// The feature lists of every marker in `image` (a kernel ELF, or an ISO
/// with one or more kernels).
pub fn markers(image: &[u8]) -> Markers<'_> {
    Markers { rest: image }
}

pub struct Markers<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Markers<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let at = self
                .rest
                .windows(MARKER_PREFIX.len())
                .position(|w| w == MARKER_PREFIX)?;
            let after = self.rest.get(at + MARKER_PREFIX.len()..)?;
            let end = after.iter().take(MARKER_MAX).position(|&b| b == 0);
            self.rest = after.get(end.unwrap_or(0)..).unwrap_or(&[]);
            let Some(end) = end else { continue };
            let list = after.get(..end).unwrap_or(&[]);
            // Feature names and commas only: the prefix inside other text
            // (a source file, a log) is not a marker.
            if list
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b',' | b'-'))
            {
                return Some(list);
            }
        }
    }
}

fn has(list: &[u8], feature: &str) -> bool {
    list.split(|&b| b == b',').any(|f| f == feature.as_bytes())
}

/// The `[devices]` keys of `blob` that are not "off", with the driver
/// feature each needs.
pub fn wanted<'a>(blob: &'a Blob<'_>) -> impl Iterator<Item = (&'static str, &'static str)> + 'a {
    DEVICE_KEYS
        .iter()
        .filter(|(t, _, _)| blob.variant(*t) != 0)
        .map(|(_, k, f)| (*k, *f))
}

/// The first key of `blob` asking for a driver that a kernel in `image`
/// lacks, as `(key, feature)`; `None` if every kernel found has every driver
/// asked for, or if `image` has no marker at all (an older kernel: its
/// configuration format already refuses the keys).
pub fn first_missing(blob: &Blob<'_>, image: &[u8]) -> Option<(&'static str, &'static str)> {
    for list in markers(image) {
        if let Some(m) = wanted(blob).find(|(_, f)| !has(list, f)) {
            return Some(m);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::Builder;
    use crate::fields::tag;

    fn image(lists: &[&str]) -> std::vec::Vec<u8> {
        let mut v = b"ELF junk URMQTT-VIRTIO-DRIVERS:not, a list\0".to_vec();
        for l in lists {
            v.extend_from_slice(b"..");
            v.extend_from_slice(MARKER_PREFIX);
            v.extend_from_slice(l.as_bytes());
            v.extend_from_slice(&[0; 20]);
        }
        v
    }

    #[test]
    fn a_driver_asked_for_must_be_in_every_kernel_of_the_image() {
        let mut b = Builder::new();
        b.variant(tag::DEV_VIRTIO_VSOCK, 2).unwrap();
        b.variant(tag::DEV_VIRTIO_INPUT, 1).unwrap();
        let bytes = b.finish(false).unwrap();
        let blob = Blob::parse(&bytes).unwrap();
        assert_eq!(
            wanted(&blob).collect::<std::vec::Vec<_>>(),
            [
                ("devices.virtio_input", "input"),
                ("devices.virtio_vsock", "vsock")
            ]
        );
        let full = "net,blk,console,rng,balloon,scsi,gpu,input,vsock";
        assert_eq!(first_missing(&blob, &image(&[full, full])), None);
        // The x86_64 kernel of a universal ISO was built without vsock.
        assert_eq!(
            first_missing(&blob, &image(&[full, "net,blk,rng,scsi,gpu,input,vsockx"])),
            Some(("devices.virtio_vsock", "vsock"))
        );
        // No marker: an older kernel, nothing to say here.
        assert_eq!(first_missing(&blob, b"old kernel"), None);
        // Everything off: nothing is needed.
        let empty = Builder::new().finish(false).unwrap();
        let e = Blob::parse(&empty).unwrap();
        assert_eq!(first_missing(&e, &image(&["net"])), None);
        assert_eq!(markers(&image(&[full, "x"])).count(), 2);
    }
}
