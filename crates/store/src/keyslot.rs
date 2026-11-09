//! Key slots: the disk key wrapped under an operator's passphrase, so that
//! it is not in the image (LATER-7, ADR-325 to ADR-329).
//!
//! An encrypted data partition (S7, ADR-240) is AES-256-XTS under a 64-byte
//! **disk key**. With `storage.disk_key_source = "image"` (the S7 default)
//! that key is in the configuration, so whoever has the ISO has it. With
//! `"console"` the configuration holds no key: the superblock carries up to
//! [`SLOTS`] **key slots**, each the disk key wrapped (AES-256 key wrap,
//! RFC 3394) under a key derived from a passphrase (PBKDF2-HMAC-SHA-256 over
//! a per-slot random salt and the disk's UUID). The kernel asks for the
//! passphrase on the console at boot; nothing in the image or the ISO is
//! enough to read the disk.
//!
//! Why a wrapped key and not a key derived straight from the passphrase:
//! changing the passphrase rewrites one superblock (two slots of 4 KiB,
//! one at a time, the A/B rule of every superblock change), not the disk;
//! two slots let an operator keep a recovery passphrase beside the daily
//! one; and the data key stays 512 random bits whatever the passphrase is.
//!
//! The key wrap's integrity check (its 64-bit initial value) tells a wrong
//! passphrase from a right one; the superblock's key check (HMAC of the
//! unwrapped key over the UUID) then tells an intact header from one whose
//! slot was swapped in from elsewhere. Neither is secret.
//!
//! This module is pure: no device, no allocation. [`LineEditor`] is the
//! console line discipline the kernel's prompt uses, here so the host tests
//! and the fuzzer drive it.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use zeroize::{Zeroize, Zeroizing};

pub use urmqtt_cfg::diskkey::KEY_BYTES;

/// Key slots a superblock holds.
pub const SLOTS: usize = 2;
/// Bytes of one encoded slot.
pub const SLOT_BYTES: usize = 128;
/// Salt bytes of a slot.
pub const SALT_BYTES: usize = 32;
/// The wrapped key: the disk key plus the key wrap's 8-byte check.
pub const WRAPPED_BYTES: usize = KEY_BYTES + 8;
/// Slot kinds (the first word of a slot).
pub const KIND_EMPTY: u32 = 0;
/// PBKDF2-HMAC-SHA-256 from a passphrase, AES-256 key wrap.
pub const KIND_PASSPHRASE: u32 = 1;
/// The fewest PBKDF2 iterations a slot may name (a reader refuses fewer:
/// a header edited to make guessing cheaper is refused, not followed).
pub const MIN_ITERATIONS: u32 = 10_000;
/// The most: a header cannot make the boot spend hours deriving.
pub const MAX_ITERATIONS: u32 = 10_000_000;
/// What the kernel and the tool use unless told otherwise (ADR-326).
pub const DEFAULT_ITERATIONS: u32 = 300_000;
/// Passphrase length, bytes (printable ASCII).
pub const MIN_PASSPHRASE: usize = 12;
pub const MAX_PASSPHRASE: usize = 256;

/// The derivation's label; with the UUID and the salt it is PBKDF2's salt.
const KDF_LABEL: &[u8] = b"urMQTT disk key slot v1";
/// RFC 3394's default initial value.
const KW_IV: [u8; 8] = [0xa6; 8];

/// One wrapped copy of the disk key. `Debug` shows the cost only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeySlot {
    pub iterations: u32,
    pub salt: [u8; SALT_BYTES],
    pub wrapped: [u8; WRAPPED_BYTES],
}

impl core::fmt::Debug for KeySlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeySlot(passphrase, {} iterations)", self.iterations)
    }
}

/// The slots of a superblock, in order; `None` is an empty slot.
pub type KeySlots = [Option<KeySlot>; SLOTS];

/// Why a slot's bytes are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// A kind this code does not know.
    UnknownKind,
    /// Iterations outside [`MIN_ITERATIONS`]..=[`MAX_ITERATIONS`].
    Iterations,
    /// An empty slot with non-zero bytes, or non-zero reserved bytes.
    Reserved,
}

/// Why a passphrase is refused before anything is derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseError {
    TooShort,
    TooLong,
    /// A byte outside printable ASCII (a console keyboard layout could not
    /// type it again reliably).
    NotPrintable,
}

/// The rules for a passphrase: [`MIN_PASSPHRASE`] to [`MAX_PASSPHRASE`]
/// bytes of printable ASCII (space included).
pub fn check_passphrase(p: &[u8]) -> Result<(), PassphraseError> {
    if p.len() < MIN_PASSPHRASE {
        return Err(PassphraseError::TooShort);
    }
    if p.len() > MAX_PASSPHRASE {
        return Err(PassphraseError::TooLong);
    }
    if !p.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(PassphraseError::NotPrintable);
    }
    Ok(())
}

impl KeySlot {
    /// Encodes the slot into its 128 bytes: kind u32, iterations u32, salt,
    /// wrapped key, 16 zero bytes (DISK-FORMAT §14.2).
    pub fn encode(slot: Option<&Self>, out: &mut [u8]) {
        out.iter_mut().for_each(|b| *b = 0);
        let Some(s) = slot else { return };
        put(out, 0, &KIND_PASSPHRASE.to_le_bytes());
        put(out, 4, &s.iterations.to_le_bytes());
        put(out, 8, &s.salt);
        put(out, 8 + SALT_BYTES, &s.wrapped);
    }

    /// Decodes one slot's bytes (at least [`SLOT_BYTES`]).
    pub fn decode(b: &[u8]) -> Result<Option<Self>, SlotError> {
        let b = b.get(..SLOT_BYTES).ok_or(SlotError::Reserved)?;
        let kind = u32_at(b, 0);
        if kind == KIND_EMPTY {
            return if b.iter().all(|&x| x == 0) {
                Ok(None)
            } else {
                Err(SlotError::Reserved)
            };
        }
        if kind != KIND_PASSPHRASE {
            return Err(SlotError::UnknownKind);
        }
        let iterations = u32_at(b, 4);
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(SlotError::Iterations);
        }
        let end = 8 + SALT_BYTES + WRAPPED_BYTES;
        if b.get(end..).is_some_and(|r| r.iter().any(|&x| x != 0)) {
            return Err(SlotError::Reserved);
        }
        let mut salt = [0u8; SALT_BYTES];
        salt.copy_from_slice(b.get(8..8 + SALT_BYTES).ok_or(SlotError::Reserved)?);
        let mut wrapped = [0u8; WRAPPED_BYTES];
        wrapped.copy_from_slice(b.get(8 + SALT_BYTES..end).ok_or(SlotError::Reserved)?);
        Ok(Some(Self {
            iterations,
            salt,
            wrapped,
        }))
    }

    /// Wraps `key` under `passphrase` for the disk `uuid`. The caller checks
    /// the passphrase and brings a fresh random salt.
    pub fn seal(
        key: &[u8; KEY_BYTES],
        passphrase: &[u8],
        uuid: &[u8; 16],
        salt: [u8; SALT_BYTES],
        iterations: u32,
    ) -> Self {
        let iterations = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
        let kek = derive(passphrase, uuid, &salt, iterations);
        Self {
            iterations,
            salt,
            wrapped: wrap(&kek, key),
        }
    }

    /// The disk key, if `passphrase` is this slot's. Costs `iterations`
    /// HMACs whatever the answer.
    pub fn open(&self, passphrase: &[u8], uuid: &[u8; 16]) -> Option<Zeroizing<[u8; KEY_BYTES]>> {
        let kek = derive(passphrase, uuid, &self.salt, self.iterations);
        unwrap(&kek, &self.wrapped)
    }
}

/// The key-encryption key: PBKDF2-HMAC-SHA-256(passphrase, label | uuid |
/// salt, iterations), 32 bytes. Wiped when dropped.
fn derive(
    passphrase: &[u8],
    uuid: &[u8; 16],
    salt: &[u8; SALT_BYTES],
    iterations: u32,
) -> Zeroizing<[u8; 32]> {
    let mut s = [0u8; KDF_LABEL.len() + 16 + SALT_BYTES];
    put(&mut s, 0, KDF_LABEL);
    put(&mut s, KDF_LABEL.len(), uuid);
    put(&mut s, KDF_LABEL.len() + 16, salt);
    Zeroizing::new(urmqtt_cfg::passwd::pbkdf2_hmac_sha256(
        passphrase, &s, iterations,
    ))
}

const N: usize = KEY_BYTES / 8;

/// RFC 3394 section 2.2.1 over `r` in place (n = `r.len()` 64-bit blocks);
/// returns the integrity value `A`.
pub fn wrap_blocks(kek: &[u8; 32], r: &mut [[u8; 8]]) -> [u8; 8] {
    let aes = Aes256::new(GenericArray::from_slice(kek));
    let n = r.len() as u64;
    let mut a = KW_IV;
    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = GenericArray::from([0u8; 16]);
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            aes.encrypt_block(&mut b);
            let t = n * j + i as u64 + 1;
            for ((o, x), y) in a.iter_mut().zip(&b[..8]).zip(t.to_be_bytes()) {
                *o = x ^ y;
            }
            ri.copy_from_slice(&b[8..]);
            b.zeroize();
        }
    }
    a
}

/// RFC 3394 section 2.2.2 over `r` in place, starting from `a`; whether the
/// integrity check holds (compared in constant time).
pub fn unwrap_blocks(kek: &[u8; 32], mut a: [u8; 8], r: &mut [[u8; 8]]) -> bool {
    let aes = Aes256::new(GenericArray::from_slice(kek));
    let n = r.len() as u64;
    for j in (0..6u64).rev() {
        for (i, ri) in r.iter_mut().enumerate().rev() {
            let t = n * j + i as u64 + 1;
            let mut b = GenericArray::from([0u8; 16]);
            for ((o, x), y) in b[..8].iter_mut().zip(&a).zip(t.to_be_bytes()) {
                *o = x ^ y;
            }
            b[8..].copy_from_slice(ri);
            aes.decrypt_block(&mut b);
            a.copy_from_slice(&b[..8]);
            ri.copy_from_slice(&b[8..]);
            b.zeroize();
        }
    }
    a.iter().zip(KW_IV).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// RFC 3394 key wrap of the 64-byte disk key.
pub fn wrap(kek: &[u8; 32], key: &[u8; KEY_BYTES]) -> [u8; WRAPPED_BYTES] {
    let mut r = Zeroizing::new([[0u8; 8]; N]);
    for (ri, c) in r.iter_mut().zip(key.chunks_exact(8)) {
        ri.copy_from_slice(c);
    }
    let a = wrap_blocks(kek, &mut r[..]);
    let mut out = [0u8; WRAPPED_BYTES];
    put(&mut out, 0, &a);
    for (i, ri) in r.iter().enumerate() {
        put(&mut out, 8 + 8 * i, ri);
    }
    out
}

/// RFC 3394 key unwrap; `None` when the integrity check fails (a wrong
/// key-encryption key or damaged bytes).
pub fn unwrap(kek: &[u8; 32], c: &[u8; WRAPPED_BYTES]) -> Option<Zeroizing<[u8; KEY_BYTES]>> {
    let mut a = [0u8; 8];
    a.copy_from_slice(c.get(..8)?);
    let mut r = Zeroizing::new([[0u8; 8]; N]);
    for (ri, ch) in r.iter_mut().zip(c.get(8..)?.chunks_exact(8)) {
        ri.copy_from_slice(ch);
    }
    if !unwrap_blocks(kek, a, &mut r[..]) {
        return None;
    }
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    for (i, ri) in r.iter().enumerate() {
        put(&mut key[..], 8 * i, ri);
    }
    Some(key)
}

/// Encodes the slots of a superblock into `out` (`SLOTS * SLOT_BYTES`).
pub fn encode_all(slots: &KeySlots, out: &mut [u8]) {
    for (s, chunk) in slots.iter().zip(out.chunks_mut(SLOT_BYTES)) {
        KeySlot::encode(s.as_ref(), chunk);
    }
}

/// Decodes the slots of a superblock.
pub fn decode_all(b: &[u8]) -> Result<KeySlots, SlotError> {
    let mut out: KeySlots = [None; SLOTS];
    for (o, chunk) in out.iter_mut().zip(b.chunks(SLOT_BYTES)) {
        *o = KeySlot::decode(chunk)?;
    }
    Ok(out)
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    if let Some(s) = b.get(at..at + 4) {
        w.copy_from_slice(s);
    }
    u32::from_le_bytes(w)
}

/// What one typed byte did to the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEvent {
    /// Nothing visible (a byte taken, or ignored).
    None,
    /// Enter: the line is complete ([`LineEditor::line`]).
    Done,
    /// The line was too long and has been dropped; start again.
    Overflow,
    /// Ctrl-U or Ctrl-C: the line was cleared.
    Cleared,
}

/// The console line discipline of the passphrase prompt: printable ASCII
/// is kept, backspace and delete remove one byte, Ctrl-U and Ctrl-C clear
/// the line, CR or LF ends it (a CR LF pair ends it once: the LF of a CR LF
/// is ignored), escape sequences (arrow keys) and other control bytes are
/// ignored, and a line longer than [`MAX_PASSPHRASE`] is dropped whole.
/// Nothing is echoed: the caller prints nothing per byte. The buffer is
/// wiped on drop and on [`clear`](Self::clear).
pub struct LineEditor {
    buf: [u8; MAX_PASSPHRASE],
    len: usize,
    /// Inside an escape sequence: 1 after ESC, 2 after ESC [ (CSI).
    esc: u8,
    /// Over the length limit: bytes are dropped until the end of the line.
    over: bool,
    last_cr: bool,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LineEditor {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_PASSPHRASE],
            len: 0,
            esc: 0,
            over: false,
            last_cr: false,
        }
    }

    /// The line so far (complete after [`LineEvent::Done`]).
    pub fn line(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Wipes the line for the next one.
    pub fn clear(&mut self) {
        self.buf.zeroize();
        self.len = 0;
        self.esc = 0;
        self.over = false;
    }

    /// Takes one typed byte.
    pub fn feed(&mut self, b: u8) -> LineEvent {
        let after_cr = core::mem::replace(&mut self.last_cr, b == b'\r');
        match self.esc {
            1 => {
                self.esc = if b == b'[' || b == b'O' { 2 } else { 0 };
                return LineEvent::None;
            }
            2 => {
                // CSI parameters and intermediates until a final byte.
                if (0x40..=0x7e).contains(&b) {
                    self.esc = 0;
                }
                return LineEvent::None;
            }
            _ => {}
        }
        match b {
            b'\n' if after_cr => LineEvent::None,
            b'\r' | b'\n' => {
                if self.over {
                    self.clear();
                    LineEvent::Overflow
                } else {
                    LineEvent::Done
                }
            }
            0x1b => {
                self.esc = 1;
                LineEvent::None
            }
            0x08 | 0x7f => {
                if !self.over && self.len > 0 {
                    self.len -= 1;
                    if let Some(x) = self.buf.get_mut(self.len) {
                        *x = 0;
                    }
                }
                LineEvent::None
            }
            0x15 | 0x03 => {
                self.clear();
                LineEvent::Cleared
            }
            0x20..=0x7e => {
                if self.over {
                    return LineEvent::None;
                }
                match self.buf.get_mut(self.len) {
                    Some(x) => {
                        *x = b;
                        self.len += 1;
                    }
                    None => {
                        self.buf.zeroize();
                        self.len = 0;
                        self.over = true;
                    }
                }
                LineEvent::None
            }
            _ => LineEvent::None,
        }
    }
}

#[cfg(test)]
mod tests;
