//! Sealed boot images (LATER-6, ADR-320): an EFI system partition whose
//! `limine.conf` pins the configuration module by its BLAKE2b, as Limine
//! requires under UEFI Secure Boot ("Secure Boot is active and URI ... has
//! no associated hash").
//!
//! Before LATER-6 the installed disk's configuration listed the module
//! without a hash (ADR-217), so a configuration written later never tripped
//! the loader, and the disk did not boot with Secure Boot enforced (AUDIT
//! H8-W1). A sealed image is built for one configuration (`mkiso.sh` with a
//! Secure Boot key): its no-menu `limine.conf` names
//! `boot():/boot/urmqtt.cfg#<128 hex digits>`, and everything that puts a
//! configuration into such an image (the installer, `urmqtt-disk`,
//! `urmqtt-config`) must put exactly that one in, or refuse: any other
//! configuration makes the disk unbootable, with or without Secure Boot.
//!
//! This module only finds the pins (by text, as `urmqtt-config` finds the
//! ISO's module hashes: no FAT is parsed) and compares them with a slot. The
//! image comes from a disk or a download, so nothing here trusts it: every
//! index is checked and a malformed pin (not 128 hex digits) is no pin.

use crate::blake2b;

/// What precedes the hash in a pinned module path.
pub const MODULE_REF: &[u8] = b"/boot/urmqtt.cfg#";
/// Hex digits of a BLAKE2b-512 pin.
pub const HASH_HEX: usize = 128;

/// The pins of `data`: the offset of each run of 128 hex digits that
/// follows [`MODULE_REF`], outside `skip` (the configuration slot itself,
/// whose blob may hold any text a customer wrote).
pub fn pins(data: &[u8], skip: core::ops::Range<usize>) -> Pins<'_> {
    Pins { data, skip, at: 0 }
}

/// Iterator returned by [`pins`].
pub struct Pins<'a> {
    data: &'a [u8],
    skip: core::ops::Range<usize>,
    at: usize,
}

impl Iterator for Pins<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            let rest = self.data.get(self.at..)?;
            let p = rest
                .windows(MODULE_REF.len())
                .position(|w| w == MODULE_REF)?;
            let start = self.at.checked_add(p)?;
            let hex_at = start.checked_add(MODULE_REF.len())?;
            self.at = hex_at;
            let end = hex_at.checked_add(HASH_HEX)?;
            let overlaps = start < self.skip.end && self.skip.start < end;
            if overlaps {
                continue;
            }
            if self
                .data
                .get(hex_at..end)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
            {
                return Some(hex_at);
            }
        }
    }
}

/// What a boot image says about the configuration it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seal {
    /// No pinned module: any configuration boots (without Secure Boot).
    Open,
    /// `count` pins, every one equal to the slot's BLAKE2b.
    Matches { count: usize },
    /// At least one pin is not the slot's BLAKE2b: the loader would refuse
    /// this image with that slot (`hash_mismatch_panic`).
    Differs { count: usize },
}

impl Seal {
    /// Whether the image is sealed at all.
    pub fn sealed(&self) -> bool {
        !matches!(self, Seal::Open)
    }
}

fn hex_eq(text: &[u8], digest: &[u8; 64]) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    text.len() == HASH_HEX
        && digest.iter().enumerate().all(|(i, b)| {
            let hi = HEX.get(usize::from(b >> 4)).copied();
            let lo = HEX.get(usize::from(b & 15)).copied();
            text.get(2 * i).map(u8::to_ascii_lowercase) == hi
                && text.get(2 * i + 1).map(u8::to_ascii_lowercase) == lo
        })
}

/// Compares every pin of `data` (outside `skip`) with the BLAKE2b of `slot`,
/// the 256 KiB slot as it is (or will be) on the disk.
pub fn check(data: &[u8], skip: core::ops::Range<usize>, slot: &[u8]) -> Seal {
    let mut count = 0usize;
    let mut differs = false;
    let mut digest: Option<[u8; 64]> = None;
    for at in pins(data, skip) {
        count += 1;
        let d = *digest.get_or_insert_with(|| blake2b::hash(slot));
        let ok = data
            .get(at..at.saturating_add(HASH_HEX))
            .is_some_and(|h| hex_eq(h, &d));
        differs |= !ok;
    }
    match (count, differs) {
        (0, _) => Seal::Open,
        (n, false) => Seal::Matches { count: n },
        (n, true) => Seal::Differs { count: n },
    }
}

/// The first pin of `data` outside `skip`, as text (for messages: which
/// configuration an image is sealed to).
pub fn first_pin(data: &[u8], skip: core::ops::Range<usize>) -> Option<&[u8]> {
    let at = pins(data, skip).next()?;
    data.get(at..at.checked_add(HASH_HEX)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn image(slot: &[u8], pin: &str, copies: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..copies {
            v.extend_from_slice(b"timeout: 0\n    module_path: boot():/boot/urmqtt.cfg#");
            v.extend_from_slice(pin.as_bytes());
            v.extend_from_slice(b"\n# end of limine.conf\n");
        }
        v.extend_from_slice(slot);
        v
    }

    #[test]
    fn open_matches_and_differs() {
        let slot = [7u8; 1024];
        let good = hex(&blake2b::hash(&slot));
        let bad = hex(&blake2b::hash(&[8u8; 1024]));
        let none = b"module_path: boot():/boot/urmqtt.cfg\n".to_vec();
        assert_eq!(check(&none, 0..0, &slot), Seal::Open);
        assert_eq!(
            check(&image(&slot, &good, 2), 0..0, &slot),
            Seal::Matches { count: 2 }
        );
        assert_eq!(
            check(&image(&slot, &bad, 1), 0..0, &slot),
            Seal::Differs { count: 1 }
        );
        // Upper-case hex is the same pin (Limine compares case-insensitively too).
        assert_eq!(
            check(&image(&slot, &good.to_uppercase(), 1), 0..0, &slot),
            Seal::Matches { count: 1 }
        );
        // One good and one bad copy is a refusal.
        let mut mixed = image(&slot, &good, 1);
        mixed.extend_from_slice(&image(&[], &bad, 1));
        assert_eq!(check(&mixed, 0..0, &slot), Seal::Differs { count: 2 });
    }

    #[test]
    fn malformed_pins_are_no_pins() {
        let slot = [1u8; 64];
        for tail in ["", "abc", &"g".repeat(128), &"0".repeat(127)] {
            let mut v = b"boot():/boot/urmqtt.cfg#".to_vec();
            v.extend_from_slice(tail.as_bytes());
            assert_eq!(check(&v, 0..0, &slot), Seal::Open, "{tail:?}");
        }
        // Cut off at every length: no panic, no pin.
        let full = image(&slot, &hex(&blake2b::hash(&slot)), 1);
        for n in 0..full.len() {
            let _ = check(&full[..n], 0..0, &slot);
        }
    }

    #[test]
    fn the_slot_itself_is_skipped() {
        // A configuration whose text happens to look like a pin does not seal the image.
        let mut slot = b"topic /boot/urmqtt.cfg#".to_vec();
        slot.extend_from_slice("ab".repeat(64).as_bytes());
        let img = image(&slot, "", 0);
        assert_eq!(check(&img, 0..img.len(), &slot), Seal::Open);
        assert!(check(&img, 0..0, &slot).sealed());
        assert_eq!(first_pin(&img, 0..img.len()), None);
        assert!(first_pin(&img, 0..0).is_some());
    }
}
