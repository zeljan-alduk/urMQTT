//! SHA-1 (FIPS 180-4, RFC 3174), for one purpose only: the
//! `Sec-WebSocket-Accept` value of the opening handshake (RFC 6455 section
//! 4.2.2), which the protocol defines as base64(SHA-1(key || GUID)).
//!
//! **Not used for security.** The accept value proves nothing to anyone: it
//! only tells a client that the server understood the WebSocket handshake (and
//! is not, say, an HTTP cache replaying a response). SHA-1's collision
//! weakness is irrelevant there, and nothing else in urMQTT may use this
//! module; it is `pub(crate)` for that reason. The input is at most one block
//! and a half (24 bytes of key and 36 of GUID), so the implementation is the
//! plain textbook one, without unrolling.

/// The digest of `data`.
pub(crate) fn digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let (blocks, rest) = data.as_chunks::<64>();
    for block in blocks {
        compress(&mut h, block);
    }
    // The tail, the 0x80 marker, zeros and the 64-bit length: one or two blocks.
    let mut last = [0u8; 128];
    let n = rest.len();
    if let Some(d) = last.get_mut(..n) {
        d.copy_from_slice(rest);
    }
    if let Some(b) = last.get_mut(n) {
        *b = 0x80;
    }
    let total = if n < 56 { 64 } else { 128 };
    if let Some(d) = last.get_mut(total - 8..total) {
        d.copy_from_slice(&bit_len.to_be_bytes());
    }
    for block in last.get(..total).unwrap_or(&[]).as_chunks::<64>().0 {
        compress(&mut h, block);
    }
    let mut out = [0u8; 20];
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *o = w.to_be_bytes();
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (wi, b) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *wi = u32::from_be_bytes(*b);
    }
    for i in 16..80 {
        let x = w.get(i - 3).copied().unwrap_or(0)
            ^ w.get(i - 8).copied().unwrap_or(0)
            ^ w.get(i - 14).copied().unwrap_or(0)
            ^ w.get(i - 16).copied().unwrap_or(0);
        if let Some(wi) = w.get_mut(i) {
            *wi = x.rotate_left(1);
        }
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(y);
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    fn hex(d: [u8; 20]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 3174 section 7.3, test cases 1, 2 and 4 (TEST3 is a million
    /// repetitions of "a", below), and the empty message (FIPS 180 examples).
    #[test]
    fn rfc_3174_vectors() {
        assert_eq!(
            hex(digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let test4 = b"0123456701234567012345670123456701234567012345670123456701234567".repeat(10);
        assert_eq!(
            hex(digest(&test4)),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
        assert_eq!(hex(digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    #[cfg_attr(miri, ignore = "a million bytes: native only")]
    fn rfc_3174_test3_a_million_a() {
        let a = vec![b'a'; 1_000_000];
        assert_eq!(hex(digest(&a)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    /// Every length around the padding boundaries (55, 56, 63, 64, 119, 120
    /// bytes) against the digests of "a" repeated (Python's `hashlib.sha1`).
    #[test]
    fn padding_boundaries() {
        let cases: [(usize, &str); 6] = [
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (119, "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56"),
            (120, "f34c1488385346a55709ba056ddd08280dd4c6d6"),
        ];
        for (n, want) in cases {
            assert_eq!(hex(digest(&vec![b'a'; n])), want, "{n} bytes");
        }
    }
}
