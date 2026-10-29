//! SipHash-2-4 (Aumasson, Bernstein), keyed: the SYN-cookie MAC.

pub struct SipHasher {
    v: [u64; 4],
    tail: u64,
    ntail: usize,
    len: usize,
}

#[inline]
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

impl SipHasher {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k0 = [0u8; 8];
        let mut k1 = [0u8; 8];
        k0.copy_from_slice(&key[..8]);
        k1.copy_from_slice(&key[8..]);
        let (k0, k1) = (u64::from_le_bytes(k0), u64::from_le_bytes(k1));
        Self {
            v: [
                k0 ^ 0x736f_6d65_7073_6575,
                k1 ^ 0x646f_7261_6e64_6f6d,
                k0 ^ 0x6c79_6765_6e65_7261,
                k1 ^ 0x7465_6462_7974_6573,
            ],
            tail: 0,
            ntail: 0,
            len: 0,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.tail |= u64::from(b) << (8 * self.ntail);
            self.ntail += 1;
            self.len += 1;
            if self.ntail == 8 {
                let m = self.tail;
                self.v[3] ^= m;
                round(&mut self.v);
                round(&mut self.v);
                self.v[0] ^= m;
                self.tail = 0;
                self.ntail = 0;
            }
        }
    }

    pub fn finish(mut self) -> u64 {
        let b = ((self.len as u64 & 0xff) << 56) | self.tail;
        self.v[3] ^= b;
        round(&mut self.v);
        round(&mut self.v);
        self.v[0] ^= b;
        self.v[2] ^= 0xff;
        for _ in 0..4 {
            round(&mut self.v);
        }
        self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vectors from the SipHash paper's implementation
    /// (key 00..0f, messages 00..(n-1)).
    #[test]
    fn reference_vectors() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let msg: Vec<u8> = (0..64u8).collect();
        let want = [
            (0usize, 0x726f_db47_dd0e_0e31u64),
            (1, 0x74f8_39c5_93dc_67fd),
            (8, 0x93f5_f579_9a93_2462),
            (15, 0xa129_ca61_49be_45e5),
            (63, 0x958a_324c_eb06_4572),
        ];
        for (n, h) in want {
            let mut s = SipHasher::new(&key);
            s.write(&msg[..n]);
            assert_eq!(s.finish(), h, "len {n}");
        }
    }
}
