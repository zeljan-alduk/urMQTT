//! Control messages for the identity lifecycle (H1, docs/SECURITY.md
//! "Control channel").
//!
//! A message is published by a control service identity to
//! `$urmqtt/control`. It changes the revocation list or the device
//! allowlist, nothing else. The encoding is fixed and bounded, so the
//! decoder is small and exact:
//!
//! | Offset | Size | Field |
//! |---:|---:|---|
//! | 0 | 8 | magic `URMQCTL1` |
//! | 8 | 8 | `seq`, u64 LE, strictly increasing, never 0 |
//! | 16 | 8 | `not_before`, Unix seconds, u64 LE |
//! | 24 | 8 | `not_after`, Unix seconds, u64 LE |
//! | 32 | 1 | command: 1 revoke, 2 unrevoke, 3 allow, 4 disallow |
//! | 33 | 1 | item count, 1..=[`MAX_ITEMS`] |
//! | 34 | … | items: a length byte, then that many bytes |
//! | end − 64 | 64 | Ed25519 signature |
//!
//! Revoke items are certificate serials (big-endian bytes, 1..=20, the
//! RFC 5280 bound). Allowlist items are device ids (UTF-8, valid MQTT
//! identities: no `/`, `+`, `#`, NUL or leading `$`, at most
//! [`MAX_ID_LEN`] bytes). Items must be unique. Nothing may follow the
//! signature.
//!
//! The signature covers `DOMAIN || env || 0x00 || message-without-signature`.
//! The environment name binds a message to one deployment, and a dev
//! signature never verifies in prod even if the same key were used.
//! Verification is `verify_strict` (RFC 8032 with canonical encodings and
//! no small-order public keys).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

extern crate alloc;

use alloc::vec::Vec;

/// The topic control messages are published to.
pub const TOPIC: &str = "$urmqtt/control";
/// The reserved namespace: nobody subscribes, only control services
/// publish, and only to [`TOPIC`].
pub const NAMESPACE: &str = "$urmqtt/";

pub const MAGIC: &[u8; 8] = b"URMQCTL1";
pub const DOMAIN: &[u8] = b"urMQTT control message v1\0";
pub const HEADER: usize = 34;
pub const SIGNATURE: usize = 64;
pub const MAX_ITEMS: usize = 64;
pub const MAX_SERIAL_LEN: usize = 20;
pub const MAX_ID_LEN: usize = 128;
/// The largest valid message.
pub const MAX_LEN: usize = HEADER + MAX_ITEMS * (1 + MAX_ID_LEN) + SIGNATURE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Revoke = 1,
    Unrevoke = 2,
    Allow = 3,
    Disallow = 4,
}

impl Command {
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Revoke),
            2 => Some(Self::Unrevoke),
            3 => Some(Self::Allow),
            4 => Some(Self::Disallow),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Revoke => "revoke",
            Self::Unrevoke => "unrevoke",
            Self::Allow => "allow",
            Self::Disallow => "disallow",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        [Self::Revoke, Self::Unrevoke, Self::Allow, Self::Disallow]
            .into_iter()
            .find(|c| c.name() == s)
    }

    /// Whether the items are certificate serials (else device ids).
    pub const fn on_serials(self) -> bool {
        matches!(self, Self::Revoke | Self::Unrevoke)
    }
}

/// A decoded (and, from [`verify`], authenticated) control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub seq: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub command: Command,
    pub items: Vec<Vec<u8>>,
}

/// Why a message was not applied. Each reason has its own counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Not a well-formed v1 message.
    Malformed,
    /// The signature does not verify under the image's control key.
    BadSignature,
    /// `seq` is not greater than the last accepted one.
    Replay,
    NotYetValid,
    Expired,
    /// The window is longer than `control.max_message_age_s`.
    WindowTooLong,
    /// The broker's wall clock is unknown (H7): nothing is accepted.
    NoClock,
    /// `unrevoke` while `control.allow_unrevoke` is off.
    UnrevokeDisabled,
    /// An allowlist command while `registry.mode` is not "allowlist".
    NotAllowlistMode,
    /// No durable storage: an effect would not survive a reboot.
    NoStorage,
    /// Published by an identity that may not issue control messages.
    Unauthorized,
    /// Unrevoking a serial the image itself lists (the image wins).
    ImageListed,
    /// The store could not commit the change.
    StorageFailed,
}

impl Reject {
    pub const ALL: [Reject; 13] = [
        Self::Malformed,
        Self::BadSignature,
        Self::Replay,
        Self::NotYetValid,
        Self::Expired,
        Self::WindowTooLong,
        Self::NoClock,
        Self::UnrevokeDisabled,
        Self::NotAllowlistMode,
        Self::NoStorage,
        Self::Unauthorized,
        Self::ImageListed,
        Self::StorageFailed,
    ];

    /// Metric and log name (no message content, ever).
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::Replay => "replay",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::WindowTooLong => "window_too_long",
            Self::NoClock => "no_clock",
            Self::UnrevokeDisabled => "unrevoke_disabled",
            Self::NotAllowlistMode => "not_allowlist_mode",
            Self::NoStorage => "no_storage",
            Self::Unauthorized => "unauthorized",
            Self::ImageListed => "image_listed",
            Self::StorageFailed => "storage_failed",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&r| r == self).unwrap_or(0)
    }
}

/// A device id as the broker accepts it (the same rule as MQTT CONNECT).
pub fn valid_id(id: &[u8]) -> bool {
    match core::str::from_utf8(id) {
        Ok(s) => {
            !s.is_empty()
                && s.len() <= MAX_ID_LEN
                && !s.contains(['/', '+', '#', '\0'])
                && !s.starts_with('$')
        }
        Err(_) => false,
    }
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let a: [u8; 8] = b.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(a))
}

/// Encodes `m` without its signature (the bytes that get signed, after the
/// domain prefix). Returns `None` if `m` would not decode.
pub fn encode_body(m: &Message) -> Option<Vec<u8>> {
    let n = u8::try_from(m.items.len()).ok()?;
    let mut out = Vec::with_capacity(HEADER + m.items.iter().map(|i| 1 + i.len()).sum::<usize>());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&m.seq.to_le_bytes());
    out.extend_from_slice(&m.not_before.to_le_bytes());
    out.extend_from_slice(&m.not_after.to_le_bytes());
    out.push(m.command as u8);
    out.push(n);
    for i in &m.items {
        out.push(u8::try_from(i.len()).ok()?);
        out.extend_from_slice(i);
    }
    let check = decode_body(&out).ok()?;
    (check == *m).then_some(out)
}

/// What is signed: domain, environment, body.
pub fn signing_input(env: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + env.len() + 1 + body.len());
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(env.as_bytes());
    v.push(0);
    v.extend_from_slice(body);
    v
}

/// Decodes a message body (everything before the signature).
pub fn decode_body(b: &[u8]) -> Result<Message, Reject> {
    if b.len() < HEADER || b.get(..8) != Some(&MAGIC[..]) {
        return Err(Reject::Malformed);
    }
    let field = |off| u64_at(b, off).ok_or(Reject::Malformed);
    let (seq, not_before, not_after) = (field(8)?, field(16)?, field(24)?);
    let command = b
        .get(32)
        .and_then(|&c| Command::from_byte(c))
        .ok_or(Reject::Malformed)?;
    let n = usize::from(*b.get(33).ok_or(Reject::Malformed)?);
    if seq == 0 || n == 0 || n > MAX_ITEMS || not_after < not_before {
        return Err(Reject::Malformed);
    }
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut off = HEADER;
    for _ in 0..n {
        let len = usize::from(*b.get(off).ok_or(Reject::Malformed)?);
        let item = b.get(off + 1..off + 1 + len).ok_or(Reject::Malformed)?;
        let ok = if command.on_serials() {
            (1..=MAX_SERIAL_LEN).contains(&len)
        } else {
            valid_id(item)
        };
        if !ok || items.iter().any(|i| i.as_slice() == item) {
            return Err(Reject::Malformed);
        }
        items.push(item.to_vec());
        off += 1 + len;
    }
    if off != b.len() {
        return Err(Reject::Malformed);
    }
    Ok(Message {
        seq,
        not_before,
        not_after,
        command,
        items,
    })
}

/// Splits a signed message into body and signature, without verifying.
pub fn split(msg: &[u8]) -> Result<(&[u8], [u8; SIGNATURE]), Reject> {
    if msg.len() > MAX_LEN || msg.len() < HEADER + SIGNATURE {
        return Err(Reject::Malformed);
    }
    let (body, sig) = msg.split_at(msg.len() - SIGNATURE);
    let sig: [u8; SIGNATURE] = sig.try_into().map_err(|_| Reject::Malformed)?;
    Ok((body, sig))
}

/// Decodes `msg` and verifies its signature for environment `env` under
/// `public_key`. The decoder runs first (it is bounded and cheap); the
/// signature then authenticates exactly the decoded bytes.
pub fn verify(env: &str, public_key: &[u8; 32], msg: &[u8]) -> Result<Message, Reject> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (body, sig) = split(msg)?;
    let m = decode_body(body)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Reject::BadSignature)?;
    key.verify_strict(&signing_input(env, body), &Signature::from_bytes(&sig))
        .map_err(|_| Reject::BadSignature)?;
    Ok(m)
}

/// The deployment's rules for accepting an authenticated message.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub max_message_age_s: u64,
    pub allow_unrevoke: bool,
    pub allowlist_mode: bool,
}

/// Freshness, replay and permission checks on an authenticated message.
/// `now` is the broker's wall clock (`None`: unknown, fail closed);
/// `last_seq` the highest sequence number accepted so far.
pub fn check(m: &Message, now: Option<u64>, last_seq: u64, p: &Policy) -> Result<(), Reject> {
    let now = now.ok_or(Reject::NoClock)?;
    if m.not_after.saturating_sub(m.not_before) > p.max_message_age_s {
        return Err(Reject::WindowTooLong);
    }
    if now < m.not_before {
        return Err(Reject::NotYetValid);
    }
    if now > m.not_after {
        return Err(Reject::Expired);
    }
    if m.seq <= last_seq {
        return Err(Reject::Replay);
    }
    match m.command {
        Command::Unrevoke if !p.allow_unrevoke => Err(Reject::UnrevokeDisabled),
        Command::Allow | Command::Disallow if !p.allowlist_mode => Err(Reject::NotAllowlistMode),
        _ => Ok(()),
    }
}

/// The 32-byte key of an Ed25519 public key in PEM (`BEGIN PUBLIC KEY`,
/// SubjectPublicKeyInfo) or DER, as OpenSSL writes it.
pub fn parse_public_key(pem_or_der: &[u8]) -> Option<[u8; 32]> {
    // SPKI for Ed25519 (RFC 8410): SEQUENCE { SEQUENCE { OID 1.3.101.112 },
    // BIT STRING (0 unused bits) <32 bytes> }.
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let der = if pem_or_der.starts_with(b"-----BEGIN PUBLIC KEY-----") {
        pem_body(pem_or_der, "PUBLIC KEY")?
    } else {
        pem_or_der.to_vec()
    };
    let key = der.strip_prefix(&PREFIX[..])?;
    key.try_into().ok()
}

/// The 32-byte seed of an Ed25519 private key in PKCS#8 PEM (`BEGIN
/// PRIVATE KEY`) or DER, as OpenSSL writes it (host tool only).
pub fn parse_private_key(pem_or_der: &[u8]) -> Option<[u8; 32]> {
    // PKCS#8 v1 (RFC 8410): SEQUENCE { INTEGER 0, SEQUENCE { OID
    // 1.3.101.112 }, OCTET STRING { OCTET STRING <32 bytes> } }.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let der = if pem_or_der.starts_with(b"-----BEGIN PRIVATE KEY-----") {
        pem_body(pem_or_der, "PRIVATE KEY")?
    } else {
        pem_or_der.to_vec()
    };
    let key = der.strip_prefix(&PREFIX[..])?;
    key.try_into().ok()
}

/// Base64 body of a single-block PEM with `label`.
fn pem_body(pem: &[u8], label: &str) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(pem).ok()?;
    let begin = alloc::format!("-----BEGIN {label}-----");
    let end = alloc::format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text.get(start..)?.find(&end)?;
    base64_decode(text.get(start..stop)?)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut padding = false;
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            _ => return None,
        };
        if padding {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
