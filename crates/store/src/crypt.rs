//! Encryption at rest (STORAGE-PLAN S7, ADR-240): AES-256-XTS over the data
//! disk, one 512-byte sector per data unit, the tweak being the sector's
//! number on the device the store sees (the data partition's window).
//!
//! [`CryptDev`] wraps a [`BlockDevice`] below [`crate::Disk`], so the layout,
//! the size table, the database, the telemetry ring and the backup region are
//! all ciphertext on the medium and plaintext above this layer. Left in
//! the clear are the two superblock slots (they hold the flag, the key check
//! and the layout, never the key). Page cache and telemetry buffers are
//! plaintext in RAM, as before.
//!
//! **An all-zero sector on the medium is read as an all-zero sector.** A
//! sector that was never written, discarded or zeroed (S4) therefore still
//! reads as zeros above this layer, which is what the telemetry ring's
//! blank test and the grow code rely on. XTS produces an all-zero 512-byte
//! ciphertext with probability 2^-4096 per sector, so a written sector is
//! never mistaken for a hole. The price is that the medium shows which
//! sectors were never written, which a thin-provisioned disk shows anyway.
//!
//! XTS gives confidentiality, not integrity: a flipped ciphertext bit
//! scrambles one 16-byte block of plaintext (the CRCs above catch it), and
//! an attacker with two snapshots can swap or roll back sectors.

#![allow(clippy::chunks_exact_to_as_chunks)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{KeyInit as _, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::disk::{BlockDevice, DiscardCaps, IoError};
use crate::layout::{SB_SLOT_LBA, SECTOR, Topology};

pub use urmqtt_cfg::diskkey::{KEY_BYTES, KeyError, check_key};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
cpufeatures::new!(cpu_aes, "aes");

/// Whether this CPU has AES instructions that the `aes` crate uses (AES-NI,
/// FEAT_AES). Without them AES-XTS would run in software at a fraction of the
/// speed, so the kernel refuses `storage.encryption` instead of falling back
/// silently (ADR-240). On aarch64 the answer honours `[cpu] disable`.
pub fn hardware_aes() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        cpu_aes::get()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

const SECTOR_BYTES: usize = SECTOR as usize;
const BLOCKS: usize = SECTOR_BYTES / 16;
/// The key check is the HMAC of this and the disk's UUID.
const CHECK_LABEL: &[u8] = b"urMQTT disk key check v1";

pub use urmqtt_cfg::diskkey::parse_key_file as parse_key;

/// Overwrites key material (not optimised away).
pub fn wipe(b: &mut [u8]) {
    b.zeroize();
}

/// The expanded key. The round keys are wiped when it is dropped (the
/// `aes` crate's `zeroize` feature).
pub struct DiskKey {
    data: Aes256,
    tweak: Aes256,
    /// HMAC key: the raw material, wiped on drop.
    raw: [u8; KEY_BYTES],
}

impl Drop for DiskKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl DiskKey {
    pub fn new(key: &[u8; KEY_BYTES]) -> Self {
        let (k1, k2) = key.split_at(KEY_BYTES / 2);
        Self {
            data: Aes256::new(GenericArray::from_slice(k1)),
            tweak: Aes256::new(GenericArray::from_slice(k2)),
            raw: *key,
        }
    }

    /// The value the superblock stores for this key and disk.
    pub fn key_check(&self, uuid: &[u8; 16]) -> [u8; 32] {
        let mut m = match hmac::Hmac::<Sha256>::new_from_slice(&self.raw) {
            Ok(m) => m,
            Err(_) => return [0; 32],
        };
        m.update(CHECK_LABEL);
        m.update(uuid);
        let out = m.finalize().into_bytes();
        let mut r = [0u8; 32];
        r.copy_from_slice(&out);
        r
    }

    /// Whether `stored` is this key's check for the disk (constant time).
    pub fn matches(&self, uuid: &[u8; 16], stored: &[u8; 32]) -> bool {
        let want = self.key_check(uuid);
        let mut d = 0u8;
        for (a, b) in want.iter().zip(stored.iter()) {
            d |= a ^ b;
        }
        d == 0
    }

    /// Encrypts (`enc`) or decrypts one 512-byte sector in place.
    pub fn sector(&self, lba: u64, buf: &mut [u8], enc: bool) {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&lba.to_le_bytes());
        let mut tw = GenericArray::clone_from_slice(&t);
        self.tweak.encrypt_block(&mut tw);
        let mut tweaks = [[0u8; 16]; BLOCKS];
        let mut cur: [u8; 16] = tw.into();
        for slot in tweaks.iter_mut() {
            *slot = cur;
            cur = mul_alpha(cur);
        }
        let mut blocks: [GenericArray<u8, aes::cipher::consts::U16>; BLOCKS] =
            core::array::from_fn(|_| GenericArray::default());
        for ((blk, chunk), tk) in blocks.iter_mut().zip(buf.chunks_exact(16)).zip(&tweaks) {
            for ((o, i), k) in blk.iter_mut().zip(chunk).zip(tk) {
                *o = i ^ k;
            }
        }
        if enc {
            self.data.encrypt_blocks(&mut blocks);
        } else {
            self.data.decrypt_blocks(&mut blocks);
        }
        for ((blk, chunk), tk) in blocks.iter().zip(buf.chunks_exact_mut(16)).zip(&tweaks) {
            for ((o, i), k) in chunk.iter_mut().zip(blk.iter()).zip(tk) {
                *o = i ^ k;
            }
        }
    }
}

/// Multiplication by the primitive element of GF(2^128), little-endian
/// (IEEE 1619).
fn mul_alpha(t: [u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    let mut carry = 0u8;
    for (o, i) in r.iter_mut().zip(t.iter()) {
        *o = (i << 1) | carry;
        carry = i >> 7;
    }
    // Branch-free: the tweak is derived from the key, so no condition may
    // depend on it (`0u8 - carry` is 0xff for a carry of 1, 0 for none).
    if let Some(b) = r.first_mut() {
        *b ^= 0x87 & 0u8.wrapping_sub(carry);
    }
    r
}

/// Sectors that stay plaintext: the two superblock slots.
fn is_plain(lba: u64) -> bool {
    SB_SLOT_LBA
        .iter()
        .any(|&s| lba >= s && lba < s + crate::layout::BLOCK_SECTORS)
}

/// The encrypting layer.
pub struct CryptDev {
    inner: Box<dyn BlockDevice>,
    key: DiskKey,
    scratch: Vec<u8>,
}

impl CryptDev {
    pub fn new(inner: Box<dyn BlockDevice>, key: DiskKey) -> Self {
        Self {
            inner,
            key,
            scratch: Vec::new(),
        }
    }

    /// The device underneath (ciphertext), for tools.
    pub fn into_inner(self) -> Box<dyn BlockDevice> {
        self.inner
    }
}

impl BlockDevice for CryptDev {
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.inner.read(lba, buf)?;
        for (i, s) in buf.chunks_exact_mut(SECTOR_BYTES).enumerate() {
            let at = lba + i as u64;
            if !is_plain(at) && s.iter().any(|&b| b != 0) {
                self.key.sector(at, s, false);
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        self.scratch.clear();
        self.scratch.extend_from_slice(buf);
        for (i, s) in self.scratch.chunks_exact_mut(SECTOR_BYTES).enumerate() {
            let at = lba + i as u64;
            if !is_plain(at) {
                self.key.sector(at, s, true);
            }
        }
        self.inner.write(lba, &self.scratch)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.inner.flush()
    }

    fn max_io(&self) -> usize {
        self.inner.max_io()
    }

    fn topology(&self) -> Topology {
        self.inner.topology()
    }

    fn base_lba(&self) -> u64 {
        self.inner.base_lba()
    }

    fn refresh_size(&mut self) -> Option<u64> {
        self.inner.refresh_size()
    }

    /// The partition table is not encrypted: the whole disk is the raw one.
    fn whole_disk(&mut self) -> Option<&mut dyn BlockDevice> {
        self.inner.whole_disk()
    }

    fn resize_window(&mut self, sectors: u64) {
        self.inner.resize_window(sectors);
    }

    fn discard_caps(&self) -> Option<DiscardCaps> {
        self.inner.discard_caps()
    }

    fn discard(&mut self, ranges: &[(u64, u64)]) -> Result<(), IoError> {
        self.inner.discard(ranges)
    }
}

#[cfg(test)]
mod tests;
