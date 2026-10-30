//! `test=crypto-bench` (dev): throughput of the dispatched primitives, to
//! decide per backend whether it is enabled by default (X0b acceptance:
//! only if faster on real hardware). Compare boots with and without
//! `cpu-disable=aes,pmull,sha2,crc32`.

use alloc::vec;

use urmqtt_arch::time;
use urmqtt_log::info;

const BUF: usize = 64 * 1024;
/// Each primitive runs for about this long.
const RUN_NS: u64 = 300_000_000;

fn rate(f: &mut dyn FnMut()) -> u64 {
    let t0 = time::uptime_ns();
    let mut bytes = 0u64;
    while time::uptime_ns() - t0 < RUN_NS {
        f();
        bytes += BUF as u64;
    }
    let ns = (time::uptime_ns() - t0).max(1);
    bytes * 1_000_000_000 / ns / (1 << 20)
}

pub fn run() {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let mut buf = vec![0x5au8; BUF];
    let nonce = [7u8; 12];
    let aes = aes_gcm::Aes128Gcm::new_from_slice(&[1u8; 16]);
    let cc = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&[2u8; 32]);
    let (Ok(aes), Ok(cc)) = (aes, cc) else {
        info!("crypto-bench: cipher setup failed");
        return;
    };
    let gcm = rate(&mut || {
        let _ = aes.encrypt_in_place_detached((&nonce).into(), b"", &mut buf);
    });
    let chacha = rate(&mut || {
        let _ = cc.encrypt_in_place_detached((&nonce).into(), b"", &mut buf);
    });
    let sha = rate(&mut || {
        use sha2::Digest;
        core::hint::black_box(sha2::Sha256::digest(&buf));
    });
    let crc = rate(&mut || {
        core::hint::black_box(urmqtt_store::crc::crc32c(&buf));
    });
    let sel = crate::cpu_dispatch::sealed().map(|s| s.selection);
    info!(
        "crypto-bench: AES-128-GCM {gcm} MiB/s, ChaCha20-Poly1305 {chacha} MiB/s, SHA-256 {sha} MiB/s, CRC-32C {crc} MiB/s ({})",
        sel.map_or_else(|| "unsealed".into(), |s| alloc::format!("{s}"))
    );
}
