//! CRC-32C (Castagnoli), table driven, for on-disk metadata and log records.

const POLY: u32 = 0x82f6_3b78;

// Indexing is checked at compile time in a const block.
#[allow(clippy::indexing_slicing)]
const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    update(0, data)
}

/// Continues a CRC-32C computation (`crc` is a previous result, or 0).
pub fn update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        let i = ((c ^ u32::from(b)) & 0xff) as usize;
        c = TABLE.get(i).copied().unwrap_or(0) ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // RFC 3720 B.4 and the common "123456789" check value.
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62a8_ab43);
        assert_eq!(update(crc32c(b"1234"), b"56789"), 0xe306_9283);
    }
}
