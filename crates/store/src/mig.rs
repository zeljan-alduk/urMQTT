//! The migration record of `urmqtt-disk migrate` (STORAGE-PLAN S2,
//! ADR-141): a copy of the v1 superblock and two alternating state blocks
//! in the otherwise unused header sectors 32..63. The kernel never reads
//! them; the tool writes and reads them so an interrupted run can be
//! finished (`--resume`) or undone (`--rollback`).

use crate::crc::crc32c;
use crate::layout::BLOCK;

pub const MAGIC: [u8; 8] = *b"URMQMIG1";
/// A copy of the v1 superblock exactly as it was (LBA 0 before the run).
pub const BACKUP_LBA: u64 = 32;
/// State blocks A and B: the higher valid `seq` wins.
pub const STATE_LBA: [u64; 2] = [40, 48];

/// The run has been planned and the v1 superblock saved.
pub const PLANNED: u32 = 1;
/// The live files are copied into the new regions and verified.
pub const COPIED: u32 = 2;
/// The v2 superblock is in slot B: the disk is v2.
pub const SWITCHED: u32 = 3;
/// Slot A holds v2 as well: the v1 superblock is gone from LBA 0.
pub const DONE: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub state: u32,
    /// CRC-32C of the saved v1 superblock block.
    pub v1_crc: u32,
    /// CRC-32C of the planned v2 superblock block (generation 1).
    pub v2_crc: u32,
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn rd32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl Record {
    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put(&mut b, 0, &MAGIC);
        put(&mut b, 8, &self.seq.to_le_bytes());
        put(&mut b, 16, &self.state.to_le_bytes());
        put(&mut b, 20, &self.v1_crc.to_le_bytes());
        put(&mut b, 24, &self.v2_crc.to_le_bytes());
        let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
        put(&mut b, BLOCK - 4, &crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; BLOCK]) -> Option<Self> {
        if b.get(..8) != Some(&MAGIC[..]) || crc32c(b.get(..BLOCK - 4)?) != rd32(b, BLOCK - 4)? {
            return None;
        }
        let state = rd32(b, 16)?;
        if !(PLANNED..=DONE).contains(&state) {
            return None;
        }
        Some(Self {
            seq: u64::from_le_bytes(b.get(8..16)?.try_into().ok()?),
            state,
            v1_crc: rd32(b, 20)?,
            v2_crc: rd32(b, 24)?,
        })
    }

    /// The newer of the two state blocks.
    pub fn newest(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(x), Some(y)) => Some(if y.seq > x.seq { y } else { x }),
            (x, y) => x.or(y),
        }
    }

    /// State block index the next record (with `seq + 1`) goes to.
    pub fn next_slot(&self) -> usize {
        ((self.seq + 1) % 2) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_damage() {
        let r = Record {
            seq: 7,
            state: COPIED,
            v1_crc: 0xdead_beef,
            v2_crc: 0x1234_5678,
        };
        assert_eq!(Record::decode(&r.encode()), Some(r));
        let mut b = r.encode();
        b[100] ^= 1;
        assert_eq!(Record::decode(&b), None);
        let mut bad_state = Record { state: 9, ..r }.encode();
        let crc = crc32c(&bad_state[..BLOCK - 4]);
        bad_state[BLOCK - 4..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(Record::decode(&bad_state), None);
        let s = Record { seq: 8, ..r };
        assert_eq!(Record::newest(Some(r), Some(s)), Some(s));
        assert_ne!(r.next_slot(), s.next_slot());
    }
}
