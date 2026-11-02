//! The disk key of `storage.encryption` (STORAGE-PLAN S7, ADR-240): two
//! AES-256 keys, 64 bytes. The rules are here so the packer, the kernel's
//! blob check, the disk tool and the builder agree.

/// Bytes of a disk key: the data key and the tweak key of XTS.
pub const KEY_BYTES: usize = 64;

/// What a key is refused for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Not [`KEY_BYTES`] long.
    Length,
    /// The two halves are equal (XTS forbids it) or the key is one repeated
    /// byte.
    Weak,
}

/// Checks key material: right length, halves different, not one repeated
/// byte.
pub fn check_key(key: &[u8]) -> Result<(), KeyError> {
    if key.len() != KEY_BYTES {
        return Err(KeyError::Length);
    }
    let (a, b) = key.split_at(KEY_BYTES / 2);
    let first = key.first().copied().unwrap_or(0);
    if a == b || key.iter().all(|&x| x == first) {
        return Err(KeyError::Weak);
    }
    Ok(())
}

/// Reads the contents of a key file: [`KEY_BYTES`] raw bytes, or 128 hex
/// digits (blanks and a final newline allowed). The key is checked.
pub fn parse_key_file(file: &[u8]) -> Result<[u8; KEY_BYTES], KeyError> {
    let mut out = [0u8; KEY_BYTES];
    let mut digits = file.iter().filter(|b| !b.is_ascii_whitespace());
    let n = digits.clone().count();
    if n == 2 * KEY_BYTES && digits.clone().all(u8::is_ascii_hexdigit) {
        let mut nib = || {
            (digits.next().copied().unwrap_or(b'0') as char)
                .to_digit(16)
                .unwrap_or(0) as u8
        };
        for o in out.iter_mut() {
            let hi = nib();
            let lo = nib();
            *o = hi << 4 | lo;
        }
    } else if file.len() == KEY_BYTES {
        out.copy_from_slice(file);
    } else {
        return Err(KeyError::Length);
    }
    check_key(&out)?;
    Ok(out)
}
