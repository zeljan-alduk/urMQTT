//! H2 differential test of the in-house TLS 1.3 record layer against
//! rustls's own, with rustls's key schedule (HKDF-Expand-Label) and `ring`
//! for the AEAD: nothing shared with our code but the traffic secret.
//!
//! - Sealing: for any secret, sequence number and payload, our records
//!   (application data, close_notify) are byte-identical to rustls's.
//! - Opening: records sealed by rustls with any content type and padding,
//!   optionally with one byte changed, open in our layer exactly when they
//!   open in rustls's, to the same content.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls::crypto::cipher::{
    InboundOpaqueMessage, MessageDecrypter, MessageEncrypter, OutboundPlainMessage,
};
use rustls::crypto::ring::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::crypto::tls13::OkmBlock;
use rustls::{ContentType, ProtocolVersion, SupportedCipherSuite, Tls13CipherSuite};
use urmqtt_tls::record::{MAX_PLAINTEXT, Opened, RecordLayer, Suite};

fn suite(b: u8) -> (Suite, &'static Tls13CipherSuite) {
    let (ours, theirs) = if b & 1 == 0 {
        (Suite::Aes128Gcm, TLS13_AES_128_GCM_SHA256)
    } else {
        (Suite::ChaCha20Poly1305, TLS13_CHACHA20_POLY1305_SHA256)
    };
    // Only TLS 1.3 suites exist without rustls's `tls12` feature.
    #[allow(irrefutable_let_patterns)]
    let SupportedCipherSuite::Tls13(t) = theirs else {
        unreachable!()
    };
    (ours, t)
}

fn keys(
    s: &Tls13CipherSuite,
    secret: &[u8; 32],
) -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
    let okm = OkmBlock::new(secret);
    let ex = s.hkdf_provider.expander_for_okm(&okm);
    let enc = s.aead_alg.encrypter(
        rustls::internal::derive_traffic_key(ex.as_ref(), s.aead_alg),
        rustls::internal::derive_traffic_iv(ex.as_ref()),
    );
    let dec = s.aead_alg.decrypter(
        rustls::internal::derive_traffic_key(ex.as_ref(), s.aead_alg),
        rustls::internal::derive_traffic_iv(ex.as_ref()),
    );
    (enc, dec)
}

fn seal(enc: &mut dyn MessageEncrypter, typ: ContentType, payload: &[u8], seq: u64) -> Vec<u8> {
    let msg = OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_2,
        payload: payload.into(),
    };
    enc.encrypt(msg, seq).unwrap().encode()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 44 {
        return;
    }
    let (ours_suite, theirs) = suite(data[0]);
    let secret: [u8; 32] = data[1..33].try_into().unwrap();
    // Below the AES-GCM limit, where our layer rotates keys by itself.
    let seq = u64::from_le_bytes(data[33..41].try_into().unwrap()) % (1 << 23);
    let mode = data[41];
    let knob = data[42];
    let payload = &data[43..];
    let payload = &payload[..payload.len().min(MAX_PLAINTEXT)];
    let (mut enc, mut dec) = keys(theirs, &secret);
    // Our server sends with `secret` and receives with `secret` (one
    // direction each way is enough: the two are independent).
    let mut ours = RecordLayer::new(ours_suite, secret, seq, secret, seq).unwrap();

    match mode % 3 {
        0 if !payload.is_empty() => {
            let mut wire = Vec::new();
            ours.send(payload, &mut wire).unwrap();
            assert_eq!(
                wire,
                seal(enc.as_mut(), ContentType::ApplicationData, payload, seq),
                "application data record differs"
            );
        }
        1 => {
            let mut wire = Vec::new();
            ours.close(&mut wire).unwrap();
            assert_eq!(
                wire,
                seal(enc.as_mut(), ContentType::Alert, &[1, 0], seq),
                "close_notify differs"
            );
        }
        _ => {
            // Any content type with any zero padding (RFC 8446 §5.2), sealed
            // with `ring` under rustls's key and IV: rustls's encrypter
            // never pads, but peers may.
            let typ = match knob % 4 {
                0 => ContentType::ApplicationData,
                1 => ContentType::Alert,
                2 => ContentType::Handshake,
                _ => ContentType::ChangeCipherSpec,
            };
            let pad = usize::from(knob >> 2) * 5;
            let mut wire = seal_padded(theirs, &secret, seq, u8::from(typ), payload, pad);
            // One changed byte, sometimes.
            let flip = data.get(43).copied().unwrap_or(0);
            if flip & 0x80 != 0 {
                let i = usize::from(flip & 0x7f) % wire.len();
                wire[i] ^= 1 << (knob % 8);
            }
            let mut theirs_buf = wire.clone();
            let theirs_out = parse(&mut theirs_buf).and_then(|m| {
                dec.decrypt(m, seq)
                    .ok()
                    .map(|p| (p.typ, p.payload.to_vec()))
            });
            let mut ours_buf = wire;
            let mut out = Vec::new();
            let got = ours.open(&mut ours_buf, &mut out);
            match (theirs_out, got) {
                (Some((ContentType::ApplicationData, p)), Ok(Opened::Data(r))) => {
                    assert_eq!(ours_buf[r].to_vec(), p, "content differs");
                }
                (Some((ContentType::ApplicationData, p)), r) => {
                    // rustls accepts empty application data; we too (an
                    // empty range). Anything else is a disagreement.
                    panic!("rustls opened {} bytes of data, ours: {r:?}", p.len());
                }
                (Some((ContentType::Alert, p)), r) => match p.as_slice() {
                    [_, 0] => assert_eq!(r, Ok(Opened::Closed)),
                    _ => assert!(r.is_err(), "alert {p:?}: {r:?}"),
                },
                (Some((ContentType::Handshake, p)), r) => match p.as_slice() {
                    [24, 0, 0, 1, 0 | 1] => {
                        assert!(matches!(r, Ok(Opened::KeyUpdated { .. })), "{r:?}")
                    }
                    _ => assert!(r.is_err(), "handshake {p:?}: {r:?}"),
                },
                (Some((t, _)), r) => assert!(r.is_err(), "{t:?} accepted: {r:?}"),
                (None, r) => assert!(
                    !matches!(
                        r,
                        Ok(Opened::Data(_)) | Ok(Opened::Closed) | Ok(Opened::KeyUpdated { .. })
                    ),
                    "rustls refused, ours accepted: {r:?}"
                ),
            }
        }
    }
});

/// `content || type || zeros(pad)` sealed with `ring` at `seq`.
fn seal_padded(
    s: &Tls13CipherSuite,
    secret: &[u8; 32],
    seq: u64,
    typ: u8,
    content: &[u8],
    pad: usize,
) -> Vec<u8> {
    use ring::aead;
    let okm = OkmBlock::new(secret);
    let ex = s.hkdf_provider.expander_for_okm(&okm);
    let key = rustls::internal::derive_traffic_key(ex.as_ref(), s.aead_alg);
    let iv = rustls::internal::derive_traffic_iv(ex.as_ref());
    let alg = if s.aead_alg.key_len() == 16 {
        &aead::AES_128_GCM
    } else {
        &aead::CHACHA20_POLY1305
    };
    let k = aead::LessSafeKey::new(aead::UnboundKey::new(alg, key.as_ref()).unwrap());
    let mut nonce: [u8; 12] = iv.as_ref().try_into().unwrap();
    for (n, b) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= b;
    }
    let mut inner = content.to_vec();
    inner.push(typ);
    inner.resize(inner.len() + pad, 0);
    let len = inner.len() + 16;
    let hdr = [23, 3, 3, (len >> 8) as u8, len as u8];
    k.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(hdr),
        &mut inner,
    )
    .unwrap();
    let mut out = hdr.to_vec();
    out.extend_from_slice(&inner);
    out
}

/// The record header as rustls's deframer would: type, version, length.
fn parse(buf: &mut [u8]) -> Option<InboundOpaqueMessage<'_>> {
    let (hdr, body) = buf.split_at_mut_checked(5)?;
    let typ = ContentType::from(hdr[0]);
    let version = ProtocolVersion::from(u16::from_be_bytes([hdr[1], hdr[2]]));
    let len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    if len != body.len()
        || typ != ContentType::ApplicationData
        || version != ProtocolVersion::TLSv1_2
        || len > 16384 + 256
    {
        return None;
    }
    Some(InboundOpaqueMessage::new(typ, version, body))
}
