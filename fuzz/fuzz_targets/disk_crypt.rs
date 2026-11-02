//! Encryption at rest (STORAGE-PLAN S7, S8, ADR-240): the sector cipher, the
//! key file parser, and an encrypted disk whose medium is damaged, opened
//! with the right key and with wrong ones. Nothing may panic; a wrong key is
//! never accepted; the right key reads back what was written.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use urmqtt_store::crypt::{DiskKey, KEY_BYTES, parse_key};
use urmqtt_store::{Disk, MemDisk};

const DISK: usize = 16 << 20;
const UUID: [u8; 16] = *b"urmqtt-fuzz-disk";

fn key(seed: u8) -> [u8; KEY_BYTES] {
    let mut k = [0u8; KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(29).wrapping_add(seed);
    }
    k
}

/// A formatted, encrypted disk (made once).
fn base() -> &'static MemDisk {
    static B: OnceLock<MemDisk> = OnceLock::new();
    B.get_or_init(|| {
        let m = MemDisk::sparse(DISK as u64);
        let k = key(1);
        let (mut d, _) = Disk::open_keyed(m.device(), || UUID, 8, Some(&k)).expect("format");
        d.sync().expect("sync");
        m
    })
}

fuzz_target!(|data: &[u8]| {
    // Key files: any bytes; an accepted key has the right shape.
    if let Ok(k) = parse_key(data) {
        assert_eq!(k.len(), KEY_BYTES);
        assert_ne!(k[..32], k[32..]);
    }
    let Some((head, rest)) = data.split_first_chunk::<10>() else {
        return;
    };
    // The cipher: a round trip with the key, and with another key the
    // plaintext does not come back.
    let (ka, kb) = (key(head[0]), key(head[1] | 0x80));
    let lba = u64::from_le_bytes([
        head[2], head[3], head[4], head[5], head[6], head[7], head[8], head[9],
    ]);
    let mut sector = [0u8; 512];
    let n = rest.len().min(512);
    sector[..n].copy_from_slice(&rest[..n]);
    let (a, b) = (DiskKey::new(&ka), DiskKey::new(&kb));
    let mut c = sector;
    a.sector(lba, &mut c, true);
    let mut p = c;
    a.sector(lba, &mut p, false);
    assert_eq!(p, sector);
    if ka != kb {
        let mut w = c;
        b.sector(lba, &mut w, false);
        assert_ne!(w, sector, "a wrong key must not give the plaintext back");
    }
    // The medium: the base disk with up to four sectors the input names
    // overwritten with garbage. Open with the key, a wrong key and none.
    let m = base().fork();
    for ch in rest.get(512..).unwrap_or(&[]).chunks_exact(6).take(4) {
        let at = u64::from(u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]])) % (DISK as u64 / 512);
        m.scribble(at, 1, u64::from(ch[4]) << 8 | u64::from(ch[5]));
    }
    let right = key(1);
    match Disk::open_keyed(m.device(), || UUID, 8, Some(&right)) {
        Ok((mut d, _)) => {
            let mut buf = vec![0u8; 4096];
            for kind in [
                urmqtt_store::layout::RegionKind::Db,
                urmqtt_store::layout::RegionKind::Telemetry,
            ] {
                let _ = d.read_at(kind, 0, &mut buf);
            }
        }
        Err(_) => {}
    }
    let r = Disk::open_keyed(m.device(), || UUID, 8, Some(&key(2)));
    assert!(r.is_err(), "a wrong key opened the disk");
    let r = Disk::open_keyed(m.device(), || UUID, 8, None);
    assert!(r.is_err(), "an encrypted disk opened without a key");
});
