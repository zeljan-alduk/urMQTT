//! The data disk's superblock slots and size-table slots are read from a
//! device the kernel does not trust blindly: decoding must never panic, and
//! an accepted layout must be self-consistent and round-trip (v2, both slots,
//! the legacy v1 view the migration tool reads, and the migration record).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_store::layout::{BLOCK, Layout, SizeTable, v1};
use urmqtt_store::mig::Record;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_first_chunk::<8>() else {
        return;
    };
    let total = u64::from_le_bytes(*head) % (1 << 40);
    let mut block = [0u8; BLOCK];
    let n = rest.len().min(BLOCK);
    block[..n].copy_from_slice(&rest[..n]);
    // A second slot from the bytes after the first block, when there are any.
    let mut other = [0u8; BLOCK];
    if let Some(tail) = rest.get(BLOCK..) {
        let m = tail.len().min(BLOCK);
        other[..m].copy_from_slice(&tail[..m]);
    }
    if let Ok(Some(l)) = Layout::decode(&block, total) {
        assert!(l.total_sectors <= total);
        for r in &l.regions {
            assert!(r.start + r.sectors <= l.total_sectors);
        }
        assert_eq!(Layout::decode(&l.encode(), total), Ok(Some(l)));
    }
    // Choosing between two slots never panics and, if it picks one, the
    // pick decodes on its own.
    if let Ok(Some((l, slot))) = Layout::select(&block, &other, total) {
        let src = if slot == 0 { &block } else { &other };
        assert_eq!(Layout::decode(src, total), Ok(Some(l)));
    }
    if let Ok(Some(l)) = v1::decode(&block, total) {
        assert!(l.total_sectors <= total);
        assert!(l.is_v1_view());
    }
    if let Some(t) = SizeTable::decode(&block) {
        assert_eq!(SizeTable::decode(&t.encode()), Some(t));
    }
    if let Some(r) = Record::decode(&block) {
        assert_eq!(Record::decode(&r.encode()), Some(r));
    }
});
