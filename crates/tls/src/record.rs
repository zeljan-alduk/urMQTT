//! In-house TLS 1.3 record layer used after the handshake (PROMPT §6).
//!
//! State per direction is the traffic secret (needed for KeyUpdate) and
//! the sequence number: 40 bytes. The AEAD key and IV are derived from the
//! secret for every record (two HKDF-Expand-Labels) and the cipher
//! instantiated on the stack, so an idle connection keeps neither keys nor
//! an expanded key schedule (M15: memory over a few µs of CPU per record).

use alloc::vec::Vec;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::provider::AES_GCM_RECORD_LIMIT;

const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APP_DATA: u8 = 23;
const HS_KEY_UPDATE: u8 = 24;
const TAG: usize = 16;
pub const HEADER: usize = 5;
/// Largest plaintext per record (RFC 8446 §5.1).
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Largest ciphertext a peer may send (plaintext + type + padding + tag).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Suite {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    const fn record_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm => AES_GCM_RECORD_LIMIT,
            Self::ChaCha20Poly1305 => u64::MAX,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "TLS13_AES_128_GCM_SHA256",
            Self::ChaCha20Poly1305 => "TLS13_CHACHA20_POLY1305_SHA256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Outer header not `application_data` / TLS 1.2.
    BadHeader,
    /// Ciphertext over 2^14 + 256 or inner plaintext over 2^14 + 1 bytes.
    Overflow,
    /// Authentication failed (bad key, tampering, wrong order).
    BadRecord,
    /// Inner content type unknown or message not allowed here.
    UnexpectedMessage,
    /// The peer sent a fatal alert (description code).
    PeerAlert(u8),
    /// Sequence number exhausted without a key update.
    SequenceExhausted,
}

impl RecordError {
    /// The fatal alert we send for it (RFC 8446 §6.2), if any: none for
    /// the peer's own alert.
    pub fn alert(self) -> Option<u8> {
        match self {
            Self::BadHeader | Self::UnexpectedMessage => Some(ALERT_UNEXPECTED_MESSAGE),
            Self::Overflow => Some(ALERT_RECORD_OVERFLOW),
            Self::BadRecord => Some(ALERT_BAD_RECORD_MAC),
            Self::SequenceExhausted => Some(ALERT_INTERNAL_ERROR),
            Self::PeerAlert(_) => None,
        }
    }
}

const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
const ALERT_BAD_RECORD_MAC: u8 = 20;
const ALERT_RECORD_OVERFLOW: u8 = 22;
const ALERT_INTERNAL_ERROR: u8 = 80;

/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context.
pub fn expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) -> bool {
    let Ok(hk) = Hkdf::<Sha256>::from_prk(secret) else {
        return false;
    };
    let mut info = [0u8; 2 + 1 + 6 + 32 + 1];
    let full = 6 + label.len();
    if full > 32 + 6 || out.len() > u16::MAX as usize {
        return false;
    }
    let len = out.len() as u16;
    let mut n = 0;
    for b in len
        .to_be_bytes()
        .iter()
        .chain(&[full as u8])
        .chain(b"tls13 ")
        .chain(label)
        .chain(&[0u8])
    {
        if let Some(slot) = info.get_mut(n) {
            *slot = *b;
        }
        n += 1;
    }
    hk.expand(info.get(..n).unwrap_or(&[]), out).is_ok()
}

/// One direction's secrets.
pub struct Direction {
    secret: [u8; 32],
    seq: u64,
}

impl Drop for Direction {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// A record key derived on the stack, wiped when dropped.
pub struct Key {
    bytes: [u8; 32],
    len: usize,
}

impl Key {
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Direction {
    fn new(secret: [u8; 32], seq: u64) -> Self {
        Self { secret, seq }
    }

    /// Next generation (RFC 8446 §7.2) with the sequence reset.
    fn update(&mut self) -> bool {
        let mut next = [0u8; 32];
        if !expand_label(&self.secret, b"traffic upd", &mut next) {
            return false;
        }
        self.secret = next;
        next.zeroize();
        self.seq = 0;
        true
    }

    /// The per-record nonce (RFC 8446 §5.3): the IV, derived afresh, XOR
    /// the sequence number. None only if HKDF fails (it cannot for 12 B).
    fn nonce(&self) -> Option<[u8; 12]> {
        let mut n = self.iv()?;
        for (b, s) in n.iter_mut().skip(4).zip(self.seq.to_be_bytes()) {
            *b ^= s;
        }
        Some(n)
    }

    /// The record key for `suite`, derived from the traffic secret.
    pub fn key(&self, suite: Suite) -> Key {
        let mut k = Key {
            bytes: [0; 32],
            len: suite.key_len(),
        };
        let ok = k
            .bytes
            .get_mut(..suite.key_len())
            .is_some_and(|b| expand_label(&self.secret, b"key", b));
        if !ok {
            k.len = 0;
        }
        k
    }

    pub fn iv(&self) -> Option<[u8; 12]> {
        let mut iv = [0u8; 12];
        expand_label(&self.secret, b"iv", &mut iv).then_some(iv)
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

fn seal_in_place(
    suite: Suite,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut Vec<u8>,
) -> bool {
    match suite {
        Suite::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key)
            .is_ok_and(|c| c.encrypt_in_place(nonce.into(), aad, buf).is_ok()),
        Suite::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .is_ok_and(|c| c.encrypt_in_place(nonce.into(), aad, buf).is_ok()),
    }
}

fn open_in_place(
    suite: Suite,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    body: &mut [u8],
) -> Option<usize> {
    let ct_len = body.len().checked_sub(TAG)?;
    let (ct, tag) = body.split_at_mut(ct_len);
    let ok = match suite {
        Suite::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key).is_ok_and(|c| {
            c.decrypt_in_place_detached(nonce.into(), aad, ct, (&*tag).into())
                .is_ok()
        }),
        Suite::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .is_ok_and(|c| {
                c.decrypt_in_place_detached(nonce.into(), aad, ct, (&*tag).into())
                    .is_ok()
            }),
    };
    ok.then_some(ct_len)
}

/// What one inbound record turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// Application data at `range` of the record buffer.
    Data(core::ops::Range<usize>),
    /// close_notify received.
    Closed,
    /// The peer rotated its keys; if `respond`, our KeyUpdate was queued.
    KeyUpdated { respond: bool },
}

pub struct RecordLayer {
    suite: Suite,
    rx: Direction,
    tx: Direction,
}

/// Total length (header + body) of the record at the start of `buf`, if
/// the header is complete.
pub fn record_len(buf: &[u8]) -> Option<usize> {
    let len = u16::from_be_bytes([*buf.get(3)?, *buf.get(4)?]) as usize;
    Some(HEADER + len)
}

impl RecordLayer {
    pub fn new(
        suite: Suite,
        rx_secret: [u8; 32],
        rx_seq: u64,
        tx_secret: [u8; 32],
        tx_seq: u64,
    ) -> Option<Self> {
        Some(Self {
            suite,
            rx: Direction::new(rx_secret, rx_seq),
            tx: Direction::new(tx_secret, tx_seq),
        })
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    pub fn rx(&self) -> &Direction {
        &self.rx
    }

    pub fn tx(&self) -> &Direction {
        &self.tx
    }

    /// Decrypts the complete record `rec` (header included) in place.
    pub fn open(&mut self, rec: &mut [u8], out: &mut Vec<u8>) -> Result<Opened, RecordError> {
        let (header, body) = rec
            .split_at_mut_checked(HEADER)
            .ok_or(RecordError::BadHeader)?;
        if header.first() != Some(&CT_APP_DATA) || header.get(1..3) != Some(&[3, 3][..]) {
            return Err(RecordError::BadHeader);
        }
        if body.len() > MAX_CIPHERTEXT {
            return Err(RecordError::Overflow);
        }
        if body.len() < TAG + 1 {
            // Too short to hold a tag and a content type: cannot verify.
            return Err(RecordError::BadRecord);
        }
        if self.rx.seq == u64::MAX {
            return Err(RecordError::SequenceExhausted);
        }
        let nonce = self.rx.nonce().ok_or(RecordError::BadRecord)?;
        let key = self.rx.key(self.suite);
        let pt_len = open_in_place(self.suite, key.as_slice(), &nonce, header, body)
            .ok_or(RecordError::BadRecord)?;
        self.rx.seq += 1;
        if pt_len > MAX_PLAINTEXT + 1 {
            // TLSInnerPlaintext over 2^14 + 1 bytes (RFC 8446 §5.4).
            return Err(RecordError::Overflow);
        }
        // Strip zero padding; the last non-zero byte is the content type.
        let inner = body.get(..pt_len).ok_or(RecordError::BadRecord)?;
        let type_at = inner
            .iter()
            .rposition(|&b| b != 0)
            .ok_or(RecordError::UnexpectedMessage)?;
        let ctype = inner
            .get(type_at)
            .copied()
            .ok_or(RecordError::UnexpectedMessage)?;
        let content = inner.get(..type_at).ok_or(RecordError::UnexpectedMessage)?;
        match ctype {
            CT_APP_DATA => Ok(Opened::Data(HEADER..HEADER + type_at)),
            CT_ALERT => match content {
                [_, 0] => Ok(Opened::Closed),
                [_, desc] => Err(RecordError::PeerAlert(*desc)),
                _ => Err(RecordError::UnexpectedMessage),
            },
            // Post-handshake messages from a client: only KeyUpdate, one per
            // record (fragmented post-handshake messages are not accepted).
            CT_HANDSHAKE => match content {
                [HS_KEY_UPDATE, 0, 0, 1, req @ (0 | 1)] => {
                    let respond = *req == 1;
                    if !self.rx.update() {
                        return Err(RecordError::BadRecord);
                    }
                    if respond {
                        self.send_key_update(out)?;
                    }
                    Ok(Opened::KeyUpdated { respond })
                }
                _ => Err(RecordError::UnexpectedMessage),
            },
            _ => Err(RecordError::UnexpectedMessage),
        }
    }

    fn seal(&mut self, ctype: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.tx.seq >= self.suite.record_limit() - 1 {
            // Rotate before the AEAD confidentiality limit.
            self.send_key_update(out)?;
        }
        let len = data.len() + 1 + TAG;
        let header = [CT_APP_DATA, 3, 3, (len >> 8) as u8, len as u8];
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(data);
        buf.push(ctype);
        let nonce = self.tx.nonce().ok_or(RecordError::BadRecord)?;
        if !seal_in_place(
            self.suite,
            self.tx.key(self.suite).as_slice(),
            &nonce,
            &header,
            &mut buf,
        ) {
            return Err(RecordError::BadRecord);
        }
        self.tx.seq += 1;
        out.extend_from_slice(&header);
        out.extend_from_slice(&buf);
        buf.zeroize();
        Ok(())
    }

    fn send_key_update(&mut self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        // KeyUpdate(update_not_requested) under the current keys, then rotate.
        let len = 5 + 1 + TAG;
        let header = [CT_APP_DATA, 3, 3, 0, len as u8];
        let mut buf = alloc::vec![HS_KEY_UPDATE, 0, 0, 1, 0, CT_HANDSHAKE];
        let nonce = self.tx.nonce().ok_or(RecordError::BadRecord)?;
        if !seal_in_place(
            self.suite,
            self.tx.key(self.suite).as_slice(),
            &nonce,
            &header,
            &mut buf,
        ) {
            return Err(RecordError::BadRecord);
        }
        out.extend_from_slice(&header);
        out.extend_from_slice(&buf);
        if self.tx.update() {
            Ok(())
        } else {
            Err(RecordError::BadRecord)
        }
    }

    /// Encrypts application data into records of at most 16 KiB.
    pub fn send(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), RecordError> {
        for chunk in data.chunks(MAX_PLAINTEXT) {
            self.seal(CT_APP_DATA, chunk, out)?;
        }
        Ok(())
    }

    /// Queues close_notify.
    pub fn close(&mut self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        self.seal(CT_ALERT, &[1, 0], out)
    }

    /// Queues the fatal alert `desc` (the connection ends after it).
    pub fn alert(&mut self, desc: u8, out: &mut Vec<u8>) -> Result<(), RecordError> {
        self.seal(CT_ALERT, &[2, desc], out)
    }

    /// Initiates a key update of our sending keys (tests, long sessions).
    pub fn update_tx(&mut self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        self.send_key_update(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8448 §3 (simple 1-RTT): server application traffic secret and
    /// the derived AES-128-GCM key and IV.
    #[test]
    fn rfc8448_application_keys() {
        let secret: [u8; 32] =
            hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        assert!(expand_label(&secret, b"key", &mut key));
        assert!(expand_label(&secret, b"iv", &mut iv));
        assert_eq!(key, hex::<16>("9f02283b6c9c07efc26bb9f2ac92e356"));
        assert_eq!(iv, hex::<12>("cf782b88dd83549aadf1e984"));
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn pair(suite: Suite) -> (RecordLayer, RecordLayer) {
        let a = [7u8; 32];
        let b = [9u8; 32];
        (
            RecordLayer::new(suite, a, 0, b, 0).unwrap(),
            RecordLayer::new(suite, b, 0, a, 0).unwrap(),
        )
    }

    fn deliver(from: &mut RecordLayer, to: &mut RecordLayer, data: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        from.send(data, &mut wire).unwrap();
        let mut got = Vec::new();
        let mut off = 0;
        while off < wire.len() {
            let n = record_len(&wire[off..]).unwrap();
            let mut rec = wire[off..off + n].to_vec();
            let mut reply = Vec::new();
            match to.open(&mut rec, &mut reply).unwrap() {
                Opened::Data(r) => got.extend_from_slice(&rec[r]),
                other => panic!("{other:?}"),
            }
            off += n;
        }
        got
    }

    #[test]
    fn roundtrip_and_fragmentation_both_suites() {
        for suite in [Suite::Aes128Gcm, Suite::ChaCha20Poly1305] {
            let (mut s, mut c) = pair(suite);
            let big: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            assert_eq!(deliver(&mut s, &mut c, &big), big);
            assert_eq!(deliver(&mut c, &mut s, b"hello"), b"hello");
            assert_eq!(s.tx().seq(), 3, "40000 bytes = 3 records");
        }
    }

    #[test]
    fn tampering_and_reordering_are_rejected() {
        let (mut s, mut c) = pair(Suite::Aes128Gcm);
        let mut wire = Vec::new();
        s.send(b"one", &mut wire).unwrap();
        s.send(b"two", &mut wire).unwrap();
        let n = record_len(&wire).unwrap();
        let mut second = wire[n..].to_vec();
        assert_eq!(
            c.open(&mut second, &mut Vec::new()),
            Err(RecordError::BadRecord),
            "out of order"
        );
        let mut first = wire[..n].to_vec();
        first[7] ^= 1;
        assert_eq!(
            c.open(&mut first, &mut Vec::new()),
            Err(RecordError::BadRecord)
        );
        let mut bad_type = wire[..n].to_vec();
        bad_type[0] = 22;
        assert_eq!(
            c.open(&mut bad_type, &mut Vec::new()),
            Err(RecordError::BadHeader)
        );
    }

    #[test]
    fn key_update_requested_by_peer() {
        let (mut s, mut c) = pair(Suite::ChaCha20Poly1305);
        // Client asks for an update (update_requested = 1).
        let mut wire = Vec::new();
        c.seal(CT_HANDSHAKE, &[HS_KEY_UPDATE, 0, 0, 1, 1], &mut wire)
            .unwrap();
        assert!(c.tx.update());
        let mut reply = Vec::new();
        assert_eq!(
            s.open(&mut wire, &mut reply).unwrap(),
            Opened::KeyUpdated { respond: true }
        );
        // Our KeyUpdate goes out under the old keys; the client applies it.
        let n = record_len(&reply).unwrap();
        assert_eq!(
            c.open(&mut reply[..n], &mut Vec::new()).unwrap(),
            Opened::KeyUpdated { respond: false }
        );
        // Traffic still flows both ways with the new generation.
        assert_eq!(deliver(&mut s, &mut c, b"after"), b"after");
        assert_eq!(deliver(&mut c, &mut s, b"back"), b"back");
    }

    #[test]
    fn alerts() {
        let (mut s, mut c) = pair(Suite::Aes128Gcm);
        let mut wire = Vec::new();
        c.close(&mut wire).unwrap();
        assert_eq!(s.open(&mut wire, &mut Vec::new()).unwrap(), Opened::Closed);
        let mut wire = Vec::new();
        c.seal(CT_ALERT, &[2, 40], &mut wire).unwrap();
        assert_eq!(
            s.open(&mut wire, &mut Vec::new()),
            Err(RecordError::PeerAlert(40))
        );
        let mut wire = Vec::new();
        c.seal(CT_HANDSHAKE, &[4, 0, 0, 0], &mut wire).unwrap();
        assert_eq!(
            s.open(&mut wire, &mut Vec::new()),
            Err(RecordError::UnexpectedMessage)
        );
    }

    /// RFC 8446 §5.4: an inner plaintext of 2^14 + 1 bytes (content, type
    /// and padding) is the most a record may carry; one byte more is a
    /// record_overflow, even if the ciphertext still fits.
    #[test]
    fn inner_plaintext_over_the_limit_is_record_overflow() {
        for suite in [Suite::Aes128Gcm, Suite::ChaCha20Poly1305] {
            for (pad, want_ok) in [(0usize, true), (1, false)] {
                let (mut client, mut server) = pair(suite);
                // content 2^14 - 1 || type || zeros
                let mut inner = alloc::vec![0x41u8; MAX_PLAINTEXT - 1 + pad];
                inner.push(CT_APP_DATA);
                inner.push(0);
                let len = inner.len() + TAG;
                let header = [CT_APP_DATA, 3, 3, (len >> 8) as u8, len as u8];
                let nonce = client.tx.nonce().unwrap();
                assert!(seal_in_place(
                    suite,
                    client.tx.key(suite).as_slice(),
                    &nonce,
                    &header,
                    &mut inner
                ));
                client.tx.seq += 1;
                let mut wire = header.to_vec();
                wire.extend_from_slice(&inner);
                let r = server.open(&mut wire, &mut Vec::new());
                if want_ok {
                    assert!(matches!(r, Ok(Opened::Data(_))), "{suite:?}: {r:?}");
                } else {
                    assert_eq!(r, Err(RecordError::Overflow), "{suite:?}");
                }
            }
        }
    }

    #[test]
    fn errors_map_to_their_alerts() {
        assert_eq!(RecordError::BadRecord.alert(), Some(20));
        assert_eq!(RecordError::Overflow.alert(), Some(22));
        assert_eq!(RecordError::UnexpectedMessage.alert(), Some(10));
        assert_eq!(RecordError::BadHeader.alert(), Some(10));
        assert_eq!(RecordError::PeerAlert(40).alert(), None);
    }
}
