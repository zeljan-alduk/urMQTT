//! H4 (ADR-170): a dropped generator leaves none of its state behind.

#![allow(
    unsafe_code,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]

use core::mem::{ManuallyDrop, size_of};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use urmqtt_tls::rng::{Csprng, EntropyPool, Source};

fn generator() -> Csprng {
    let mut pool = EntropyPool::new();
    pool.add(Source::VirtioRng, &[0x5a; 64]);
    pool.finish().ok().unwrap_or_else(|| unreachable!())
}

/// The bytes a value occupies.
fn image<T>(v: &T) -> Vec<u8> {
    unsafe { core::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
}

#[test]
fn a_dropped_generator_is_overwritten_in_place() {
    let mut g = ManuallyDrop::new(generator());
    // Use it, so its buffer holds output as well as the key.
    let mut out = [0u8; 100];
    g.fill(&mut out);
    let before = image(&*g);
    assert_ne!(before, image(&ChaCha20Rng::from_seed([0; 32])));
    // Drop it in place and look at the memory it occupied.
    let p: *mut Csprng = &mut *g;
    unsafe { core::ptr::drop_in_place(p) };
    let after = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), size_of::<Csprng>()) }.to_vec();
    assert_eq!(
        after,
        image(&ChaCha20Rng::from_seed([0; 32])),
        "the state of a dropped generator was left in memory"
    );
    // And nothing of the old state survives at all (not one 8-byte run).
    for w in before.chunks_exact(8) {
        if w.iter().any(|&b| b != 0) {
            assert!(
                !after.chunks_exact(8).any(|a| a == w),
                "a word of the old state survived"
            );
        }
    }
}
