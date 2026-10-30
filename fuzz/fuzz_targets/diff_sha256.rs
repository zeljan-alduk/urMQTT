//! X0b differential test: SHA-256 from both `sha2` versions in the kernel
//! (0.11 for TLS and the store, 0.10 inside ed25519-dalek; ARMv8 SHA2
//! instructions on an aarch64 host) against `ring`, in one shot and fed in
//! pieces whose sizes come from the input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use sha2::Digest as _;
    use sha2_010::Digest as _;
    let want = ring::digest::digest(&ring::digest::SHA256, data);
    assert_eq!(sha2::Sha256::digest(data).as_slice(), want.as_ref());
    assert_eq!(sha2_010::Sha256::digest(data).as_slice(), want.as_ref());
    let mut h = sha2::Sha256::new();
    let mut rest = data;
    while let Some((&n, tail)) = rest.split_first() {
        let take = usize::from(n).min(tail.len());
        h.update(&tail[..take]);
        rest = &tail[take..];
    }
    let mut r = ring::digest::Context::new(&ring::digest::SHA256);
    let mut rest = data;
    while let Some((&n, tail)) = rest.split_first() {
        let take = usize::from(n).min(tail.len());
        r.update(&tail[..take]);
        rest = &tail[take..];
    }
    assert_eq!(h.finalize().as_slice(), r.finish().as_ref());
});
