//! CRC-32C (Castagnoli), for on-disk metadata and log records: table
//! driven, or a hardware backend chosen once at boot (X0b, ADR-041).

use core::sync::atomic::{AtomicUsize, Ordering};

const POLY: u32 = 0x82f6_3b78;

/// A CRC-32C implementation with [`update`]'s contract.
pub type Backend = fn(u32, &[u8]) -> u32;

/// The installed backend as a function address (0: the table).
static BACKEND: AtomicUsize = AtomicUsize::new(0);

/// Installs a faster implementation (the kernel's CPU dispatch, before the
/// store is opened). It must equal [`table_update`] for every input; the
/// kernel checks it against the known answers first.
pub fn set_backend(f: Backend) {
    // Release: a core that sees the pointer sees the function's code.
    BACKEND.store(f as usize, Ordering::Release);
}

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
    // Acquire: pairs with the Release in `set_backend`.
    match BACKEND.load(Ordering::Acquire) {
        0 => table_update(crc, data),
        f => {
            // SAFETY: only `set_backend` stores here, always a `Backend`
            // (function pointers round-trip through usize on every target).
            #[allow(unsafe_code)]
            let f: Backend = unsafe { core::mem::transmute::<usize, Backend>(f) };
            f(crc, data)
        }
    }
}

/// The portable table-driven implementation.
pub fn table_update(crc: u32, data: &[u8]) -> u32 {
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
