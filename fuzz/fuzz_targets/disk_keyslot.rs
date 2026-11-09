//! A disk key that is not in the image (LATER-7, ADR-325, ADR-329): the key
//! slot decoder, the AES key unwrap, a superblock whose key slot area, flags
//! and key check are attacker-chosen (with a valid CRC), unlocked with the
//! right passphrase and a wrong one, and the console's line editor.
//! Nothing may panic; an accepted slot re-encodes to the same bytes; an
//! unwrap that succeeds is the inverse of the wrap; a wrong passphrase never
//! unlocks; whatever key an edited header yields is the disk's own key; the
//! line editor keeps printable ASCII within its bound.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use urmqtt_store::crc::crc32c;
use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::disk::unlock;
use urmqtt_store::keyslot::{
    self, KeySlot, LineEditor, LineEvent, MAX_PASSPHRASE, MIN_ITERATIONS, SLOT_BYTES, SLOTS,
    WRAPPED_BYTES,
};
use urmqtt_store::layout::{BLOCK, KEY_SLOTS_AT, Layout, SB_SLOT_LBA};
use urmqtt_store::{BlockDevice, Disk, MemDisk};

const DISK: u64 = 16 << 20;
const UUID: [u8; 16] = *b"urmqtt-fuzz-keys";
const PASS: &[u8] = b"fuzzing passphrase";

fn key() -> [u8; KEY_BYTES] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(1))
}

/// A wrapped disk (made once) and its superblock A.
fn base() -> &'static (MemDisk, [u8; BLOCK]) {
    static B: OnceLock<(MemDisk, [u8; BLOCK])> = OnceLock::new();
    B.get_or_init(|| {
        let m = MemDisk::sparse(DISK);
        let k = key();
        let mut d = Disk::format_sealed(
            m.device(),
            || UUID,
            8,
            &k,
            |u| KeySlot::seal(&k, PASS, u, [3; 32], MIN_ITERATIONS),
        )
        .expect("format");
        d.sync().expect("sync");
        drop(d);
        let mut sb = [0u8; BLOCK];
        m.device().read(SB_SLOT_LBA[0], &mut sb).expect("read");
        (m, sb)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    // 1. The slot decoder: any bytes; an accepted area re-encodes exactly.
    if let Ok(slots) = keyslot::decode_all(rest) {
        let mut again = vec![0u8; SLOTS * SLOT_BYTES];
        keyslot::encode_all(&slots, &mut again);
        let n = rest.len().min(SLOTS * SLOT_BYTES);
        assert_eq!(&again[..n], &rest[..n]);
    }
    // 2. The key unwrap: any key-encryption key and wrapped bytes. A success
    //    is the inverse of the wrap (the wrap is a permutation).
    if let Some((kek, w)) = rest.split_first_chunk::<32>()
        && let Some((wrapped, _)) = w.split_first_chunk::<WRAPPED_BYTES>()
        && let Some(k) = keyslot::unwrap(kek, wrapped)
    {
        assert_eq!(&keyslot::wrap(kek, &k), wrapped);
    }
    // 3. The line editor: printable ASCII, bounded, whatever is typed.
    let mut ed = LineEditor::new();
    for &b in rest {
        let ev = ed.feed(b);
        assert!(ed.line().len() <= MAX_PASSPHRASE);
        assert!(ed.line().iter().all(|c| (0x20..0x7f).contains(c)));
        if ev == LineEvent::Done {
            ed.clear();
        }
    }
    // 4. An edited header (1 input in 8: each unlock costs PBKDF2): the
    //    flags, the key check and the slot area from the input, the CRC
    //    made valid. A wrong passphrase never unlocks; the right one yields
    //    the disk's key or an error, never another key.
    if sel & 7 != 0 {
        return;
    }
    let (m, sb) = base();
    let mut b = *sb;
    let mut it = rest.iter().copied();
    if sel & 8 != 0 {
        b[56] = it.next().unwrap_or(0) & 7;
    }
    for i in KEY_SLOTS_AT - 32..KEY_SLOTS_AT + SLOTS * SLOT_BYTES {
        if let Some(x) = it.next() {
            b[i] ^= x;
        }
    }
    let c = crc32c(&b[..BLOCK - 4]);
    b[BLOCK - 4..].copy_from_slice(&c.to_le_bytes());
    // Never derive with a cost the fuzzer cannot afford (a valid header may
    // name up to ten million iterations).
    if let Ok(Some(l)) = Layout::decode(&b, DISK / 512)
        && l.key_slots
            .iter()
            .flatten()
            .any(|s| s.iterations > 4 * MIN_ITERATIONS)
    {
        return;
    }
    let f = m.fork();
    f.device().write(SB_SLOT_LBA[0], &b).expect("write");
    if let Ok((k, _)) = unlock(f.device().as_mut(), PASS) {
        assert_eq!(*k, key(), "an edited header gave another key");
    }
    assert!(unlock(f.device().as_mut(), b"not the passphrase").is_err());
});
