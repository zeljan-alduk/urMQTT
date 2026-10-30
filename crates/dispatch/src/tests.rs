use super::*;

const ALL: CpuFeatures = CpuFeatures::NONE
    .with(Feature::Aes, true)
    .with(Feature::Pmull, true)
    .with(Feature::Sha2, true)
    .with(Feature::Crc32, true);

/// A table as X0b will have it: hardware backends built.
const BUILT: Table = [
    (
        Primitive::AesGcm,
        &[
            Backend {
                name: "armv8-aes",
                needs: &[Feature::Aes, Feature::Pmull],
                built: true,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::Ghash,
        &[
            Backend {
                name: "armv8-pmull",
                needs: &[Feature::Pmull],
                built: true,
            },
            soft("soft"),
        ],
    ),
    (Primitive::ChaCha20Poly1305, &[soft("soft")]),
    (
        Primitive::Sha256,
        &[
            Backend {
                name: "armv8-sha2",
                needs: &[Feature::Sha2],
                built: true,
            },
            soft("soft"),
        ],
    ),
    (
        Primitive::Crc32c,
        &[
            Backend {
                name: "armv8-crc",
                needs: &[Feature::Crc32],
                built: true,
            },
            soft("table"),
        ],
    ),
    (Primitive::Toeplitz, &[soft("bitwise")]),
];

#[test]
fn this_image_selects_portable_code_whatever_the_cpu_has() {
    // Host builds list every hardware backend as not built.
    for cpu in [CpuFeatures::NONE, ALL] {
        assert_eq!(
            select(&TABLE, cpu).to_string(),
            "aes-gcm=soft ghash=soft chacha=soft sha256=soft crc32c=table toeplitz=bitwise"
        );
    }
}

#[test]
fn every_row_ends_in_a_portable_backend() {
    for table in [&TABLE, &BUILT] {
        for p in Primitive::ALL {
            let (_, row) = table.iter().find(|(q, _)| *q == p).unwrap();
            let last = row.last().unwrap();
            assert!(last.built && last.needs.is_empty(), "{}", p.name());
        }
    }
}

#[test]
fn selection_follows_the_feature_mask() {
    assert_eq!(
        select(&BUILT, ALL).to_string(),
        "aes-gcm=armv8-aes ghash=armv8-pmull chacha=soft sha256=armv8-sha2 crc32c=armv8-crc toeplitz=bitwise"
    );
    assert_eq!(
        select(&BUILT, CpuFeatures::NONE).to_string(),
        "aes-gcm=soft ghash=soft chacha=soft sha256=soft crc32c=table toeplitz=bitwise"
    );
    // A backend needs all of its features: AES without PMULL is not enough.
    let aes_only = CpuFeatures::NONE.with(Feature::Aes, true);
    let s = select(&BUILT, aes_only);
    assert_eq!(s.backend(Primitive::AesGcm), "soft");
    assert_eq!(s.backend(Primitive::Ghash), "soft");
}

#[test]
fn opt_out_applies_before_selection() {
    let cell = SealCell::new();
    let s = cell.seal(&BUILT, ALL, &["pmull", "crc32"]).unwrap();
    assert_eq!(s.detected, ALL);
    assert_eq!(s.disabled.to_string(), "pmull crc32");
    assert_eq!(s.usable.to_string(), "aes sha2");
    assert_eq!(s.selection.backend(Primitive::AesGcm), "soft");
    assert_eq!(s.selection.backend(Primitive::Ghash), "soft");
    assert_eq!(s.selection.backend(Primitive::Sha256), "armv8-sha2");
    assert_eq!(s.selection.backend(Primitive::Crc32c), "table");
}

#[test]
fn double_seal_is_rejected_and_keeps_the_first_result() {
    let cell = SealCell::new();
    let first = *cell.seal(&BUILT, ALL, &[]).unwrap();
    assert_eq!(
        cell.seal(&BUILT, CpuFeatures::NONE, &["aes"]),
        Err(SealError::AlreadySealed)
    );
    assert_eq!(cell.get(), Some(&first));
}

#[test]
fn disable_list_is_validated() {
    assert_eq!(parse_disable(&[]), Ok(CpuFeatures::NONE));
    assert_eq!(parse_disable(&["aesni"]), Err(DisableError::Unknown));
    assert_eq!(parse_disable(&["AES"]), Err(DisableError::Unknown));
    assert_eq!(parse_disable(&["aes", "aes"]), Err(DisableError::Duplicate));
    assert_eq!(
        parse_disable_csv("aes,crc32")
            .map(|s| s.to_string())
            .as_deref(),
        Ok("aes crc32")
    );
    assert_eq!(parse_disable_csv("aes,"), Err(DisableError::Unknown));
    // A failed seal leaves the cell empty.
    let cell = SealCell::new();
    assert_eq!(
        cell.seal(&TABLE, ALL, &["bti"]),
        Err(SealError::Disable(DisableError::Unknown))
    );
    assert!(cell.get().is_none());
}

#[test]
fn feature_names_round_trip() {
    for f in Feature::ALL {
        assert_eq!(Feature::from_name(f.name()), Some(f));
    }
    // Security features are not switchable.
    for name in ["pauth", "bti", "pac", "wxn", "rndr"] {
        assert_eq!(Feature::from_name(name), None);
    }
}

/// The answers RustCrypto gets: "aes" needs AES and PMULL (POLYVAL uses
/// PMULL under that name), disabled features are refused, unknown names
/// are refused.
#[test]
fn cpufeatures_answers_follow_the_usable_set() {
    let cell = SealCell::new();
    let s = cell.seal(&BUILT, ALL, &[]).unwrap();
    assert!(s.cpufeatures("aes") && s.cpufeatures("sha2"));
    assert!(!s.cpufeatures("sha3") && !s.cpufeatures("dit") && !s.cpufeatures("sm4"));
    let cell = SealCell::new();
    let s = cell.seal(&BUILT, ALL, &["pmull"]).unwrap();
    assert!(
        !s.cpufeatures("aes"),
        "AES without PMULL would let POLYVAL fault"
    );
    let cell = SealCell::new();
    let s = cell.seal(&BUILT, ALL, &["sha2"]).unwrap();
    assert!(!s.cpufeatures("sha2"));
    let none = CpuFeatures::NONE.with(Feature::Aes, true);
    let cell = SealCell::new();
    assert!(!cell.seal(&BUILT, none, &[]).unwrap().cpufeatures("aes"));
}
