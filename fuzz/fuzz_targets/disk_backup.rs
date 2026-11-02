//! The in-disk backup region's headers (STORAGE-PLAN S5, S8): a slot header
//! and the control block are read from a device the kernel does not trust.
//! Decoding must never panic, and an accepted header must be consistent
//! with the capacity it was judged against and round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_store::backup::{CONTROL_MAGIC, Control, SLOT_MAGIC, SlotHeader};
use urmqtt_store::layout::BLOCK;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&head[..16]);
    let capacity = u64::from_le_bytes(head[16..24].try_into().unwrap_or([0; 8]));
    let mut block = [0u8; BLOCK];
    let n = rest.len().min(BLOCK);
    block[..n].copy_from_slice(&rest[..n]);
    // Fuzzed bytes almost never carry the right magic, UUID and CRC: also
    // try the block stamped as a slot header and as a control block, so the
    // field checks behind them are reached.
    for b in [
        block,
        stamp(block, &SLOT_MAGIC, 24, &uuid),
        stamp(block, &CONTROL_MAGIC, 16, &uuid),
    ] {
        if let Some(h) = SlotHeader::decode(&b, &uuid, capacity) {
            assert!(h.seq > 0 && h.payload_bytes <= capacity);
            assert_eq!(
                h.page_count.checked_mul(u64::from(h.page_size)),
                Some(h.payload_bytes)
            );
            assert_eq!(
                SlotHeader::decode(&h.encode(&uuid), &uuid, capacity),
                Some(h)
            );
        }
        if let Some(c) = Control::decode(&b, &uuid) {
            assert_eq!(Control::decode(&c.encode(&uuid), &uuid), Some(c));
        }
    }
});

/// The block with `magic` at 0, `uuid` at `at` and the CRC-32C of the first
/// 4092 bytes in the last four.
fn stamp(mut b: [u8; BLOCK], magic: &[u8; 8], at: usize, uuid: &[u8; 16]) -> [u8; BLOCK] {
    b[..8].copy_from_slice(magic);
    b[at..at + 16].copy_from_slice(uuid);
    let crc = urmqtt_store::crc::crc32c(&b[..BLOCK - 4]);
    b[BLOCK - 4..].copy_from_slice(&crc.to_le_bytes());
    b
}
