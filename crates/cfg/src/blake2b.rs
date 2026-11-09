//! BLAKE2b-512 (RFC 7693), unkeyed, for the module hashes Limine checks
//! (`path: ...#<hash>`). The host tools and the browser use it, and since
//! LATER-6 the kernel's installer does too: it checks that a sealed
//! installation image pins the configuration it installs (`seal`, ADR-320).
//! Checked against RFC 7693's test vector and Python's
//! `hashlib.blake2b`.

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[u8; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Incremental BLAKE2b-512.
pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buf: [u8; 128],
    len: usize,
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::indexing_slicing)] // fixed-size arrays indexed by constants < 16
fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (w, c) in m.iter_mut().zip(block.as_chunks::<8>().0) {
        *w = u64::from_le_bytes(*c);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        };
        let w = |i: usize| m[usize::from(s[i])];
        g(&mut v, 0, 4, 8, 12, w(0), w(1));
        g(&mut v, 1, 5, 9, 13, w(2), w(3));
        g(&mut v, 2, 6, 10, 14, w(4), w(5));
        g(&mut v, 3, 7, 11, 15, w(6), w(7));
        g(&mut v, 0, 5, 10, 15, w(8), w(9));
        g(&mut v, 1, 6, 11, 12, w(10), w(11));
        g(&mut v, 2, 7, 8, 13, w(12), w(13));
        g(&mut v, 3, 4, 9, 14, w(14), w(15));
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

impl Blake2b {
    pub fn new() -> Self {
        let mut h = IV;
        // Digest length 64, no key, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ 64;
        Self {
            h,
            t: 0,
            buf: [0; 128],
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == 128 {
                self.t += 128;
                compress(&mut self.h, &self.buf, self.t, false);
                self.len = 0;
            }
            let n = (128 - self.len).min(data.len());
            let (head, tail) = data.split_at(n);
            if let Some(dst) = self.buf.get_mut(self.len..self.len + n) {
                dst.copy_from_slice(head);
            }
            self.len += n;
            data = tail;
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        self.t += self.len as u128;
        if let Some(rest) = self.buf.get_mut(self.len..) {
            rest.fill(0);
        }
        compress(&mut self.h, &self.buf, self.t, true);
        let mut out = [0u8; 64];
        for (o, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.h) {
            *o = w.to_le_bytes();
        }
        out
    }
}

/// BLAKE2b-512 of `data`.
pub fn hash(data: &[u8]) -> [u8; 64] {
    let mut h = Blake2b::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc7693_abc() {
        assert_eq!(
            hex(&hash(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn empty_and_block_boundaries() {
        // Values from Python's hashlib.blake2b (digest_size 64).
        assert_eq!(
            hex(&hash(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        // Incremental equals one-shot across the 128-byte boundary.
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        let mut h = Blake2b::new();
        for c in data.chunks(37) {
            h.update(c);
        }
        assert_eq!(h.finalize(), hash(&data));
    }
}
