//! The data disk's superblock and size-table slots are read from a device
//! the kernel does not trust blindly: decoding must never panic, and an
//! accepted layout must be self-consistent and round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_store::layout::{BLOCK, Layout, SizeTable};

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_first_chunk::<8>() else {
        return;
    };
    let total = u64::from_le_bytes(*head) % (1 << 40);
    let mut block = [0u8; BLOCK];
    let n = rest.len().min(BLOCK);
    block[..n].copy_from_slice(&rest[..n]);
    if let Ok(Some(l)) = Layout::decode(&block, total) {
        assert!(l.total_sectors <= total);
        for r in &l.regions {
            assert!(r.start + r.sectors <= l.total_sectors);
        }
        assert_eq!(Layout::decode(&l.encode(), total), Ok(Some(l)));
    }
    if let Some(t) = SizeTable::decode(&block) {
        assert_eq!(SizeTable::decode(&t.encode()), Some(t));
    }
});
