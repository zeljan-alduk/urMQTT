//! `cargo test --release -p urmqtt-x25519 -- --ignored --nocapture timings`

use super::*;

#[test]
#[ignore = "timing only"]
fn timings() {
    use std::time::Instant;
    let k = [0x42u8; 32];
    let mut u = [0u8; 32];
    u[0] = 9;
    for be in [Some(Backend::Portable), Backend::adx_if_available()]
        .into_iter()
        .flatten()
    {
        let mut best = u128::MAX;
        for _ in 0..40 {
            let t = Instant::now();
            for _ in 0..20 {
                std::hint::black_box(x25519(be, std::hint::black_box(&k), &u));
            }
            best = best.min(t.elapsed().as_nanos() / 20);
        }
        std::println!("{be:?} x25519: {best} ns");
    }
    let mut best = u128::MAX;
    for _ in 0..40 {
        let t = Instant::now();
        for _ in 0..20 {
            std::hint::black_box(x25519_dalek::x25519(std::hint::black_box(k), u));
        }
        best = best.min(t.elapsed().as_nanos() / 20);
    }
    std::println!("dalek x25519: {best} ns");
    let a = decode(&[0x77; 32]);
    let b = decode(&[0x31; 32]);
    let t = Instant::now();
    let mut x = a;
    for _ in 0..1_000_000 {
        x = mul_portable(&x, &b);
    }
    std::println!(
        "portable mul {} ns {x:?}",
        t.elapsed().as_nanos() / 1_000_000
    );
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    if Backend::adx_if_available().is_some() {
        let t = Instant::now();
        let mut x = a;
        for _ in 0..1_000_000 {
            x = adx::mul(&x, &b);
        }
        std::println!("adx mul {} ns {x:?}", t.elapsed().as_nanos() / 1_000_000);
    }
}
