//! Sealed boot images (LATER-6, ADR-320): the pins of an ESP or disk image come from a disk or a
//! download, and the installer reads them in the kernel before it erases a disk. The input is split
//! into an image and a slot (first byte: where; second: how long the skipped range is). Nothing may
//! panic; every pin must sit right after `/boot/urmqtt.cfg#` and be 128 hex digits outside the
//! skipped range; and an image built from the input with the slot's own hash appended must check
//! as sealed to that slot (and a slot that differs in one byte as sealed to another).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_cfg::blake2b;
use urmqtt_cfg::seal::{HASH_HEX, MODULE_REF, Seal, check, first_pin, pins};

fuzz_target!(|data: &[u8]| {
    let (Some(&a), Some(&b)) = (data.first(), data.get(1)) else {
        return;
    };
    let rest = &data[2..];
    let cut = usize::from(a) * rest.len() / 256;
    let (img, slot) = rest.split_at(cut);
    let skip_start = usize::from(b) * img.len() / 256;
    let skip = skip_start..skip_start.saturating_add(usize::from(b));
    let mut n = 0;
    for at in pins(img, skip.clone()) {
        n += 1;
        assert!(at >= MODULE_REF.len());
        assert_eq!(&img[at - MODULE_REF.len()..at], MODULE_REF);
        let hex = &img[at..at + HASH_HEX];
        assert!(hex.iter().all(u8::is_ascii_hexdigit));
        let start = at - MODULE_REF.len();
        assert!(
            !(start < skip.end && skip.start < at + HASH_HEX),
            "a pin inside the skipped range"
        );
    }
    let verdict = check(img, skip.clone(), slot);
    assert_eq!(verdict.sealed(), n > 0);
    assert_eq!(first_pin(img, skip.clone()).is_some(), n > 0);
    match verdict {
        Seal::Open => assert_eq!(n, 0),
        Seal::Matches { count } | Seal::Differs { count } => assert_eq!(count, n),
    }
    // Append a pin of the slot's hash after the image, outside any skipped range: the image is then
    // sealed, and to this slot exactly when every earlier pin was this slot's too.
    let hex: String = blake2b::hash(slot)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let mut sealed = img.to_vec();
    sealed.extend_from_slice(b"\n    module_path: boot():");
    sealed.extend_from_slice(MODULE_REF);
    sealed.extend_from_slice(hex.as_bytes());
    sealed.push(b'\n');
    let v = check(&sealed, 0..0, slot);
    assert!(v.sealed());
    if check(img, 0..0, slot) != Seal::Open {
        // Whatever the earlier pins say, the new one is counted.
        match (check(img, 0..0, slot), v) {
            (Seal::Matches { count: a }, Seal::Matches { count: b }) => assert_eq!(b, a + 1),
            (Seal::Differs { .. }, Seal::Differs { .. }) => {}
            (x, y) => {
                // The appended text can complete a pin that was cut off at the image's end only if
                // it starts with hex, which it does not ("\n"): the verdicts must agree.
                panic!("{x:?} then {y:?}");
            }
        }
    } else {
        assert_eq!(v, Seal::Matches { count: 1 });
    }
    let mut other = slot.to_vec();
    other.push(0);
    assert!(matches!(check(&sealed, 0..0, &other), Seal::Differs { .. }));
});
