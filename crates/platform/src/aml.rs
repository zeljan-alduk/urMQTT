//! Minimal AML scanner for the `\_S5` sleep type (ACPI soft-off).
//!
//! Poweroff through ACPI needs `SLP_TYPa`/`SLP_TYPb` from the `_S5_` package
//! in the DSDT, which is AML bytecode. A real interpreter is far out of scope;
//! every PC firmware the broker targets (QEMU/KVM, SeaBIOS, OVMF, Contabo)
//! emits the package literally as `Name (_S5, Package () { a, b, ... })`, so
//! the scanner finds that exact encoding and nothing else:
//!
//! ```text
//! 08 [5C] 5F 53 35 5F 12 <PkgLength> <NumElements> <elem a> <elem b> ...
//! NameOp  \  _  S  5  _  PackageOp
//! ```
//!
//! Each element is ZeroOp, OneOp, or BytePrefix + byte (WordPrefix and
//! DWordPrefix are accepted too). Anything else, such as a method call or
//! a reference, is not understood and yields `None`, in which case the
//! caller falls back to reset. All reads are bounds-checked; hostile
//! bytecode can only make the scan return `None`.

/// `SLP_TYPa` and `SLP_TYPb` for sleep state S5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepType {
    pub a: u8,
    pub b: u8,
}

const NAME_OP: u8 = 0x08;
const ROOT_CHAR: u8 = 0x5c;
const PACKAGE_OP: u8 = 0x12;
const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;
/// `SLP_TYP` is a 3-bit field in PM1x_CNT.
const SLP_TYP_MAX: u32 = 7;

/// Finds the first well-formed `_S5_` package in `aml` (DSDT or SSDT body).
pub fn find_s5(aml: &[u8]) -> Option<SleepType> {
    let mut from = 0usize;
    loop {
        let rel = find_name(aml.get(from..)?)?;
        let at = from.checked_add(rel)?;
        if let Some(s) = s5_at(aml, at) {
            return Some(s);
        }
        from = at.checked_add(1)?;
    }
}

/// Offset of the next `_S5_` in `hay`.
fn find_name(hay: &[u8]) -> Option<usize> {
    hay.windows(4).position(|w| w == b"_S5_")
}

/// Parses the `Name (_S5_, Package ...)` whose name starts at `at`.
fn s5_at(aml: &[u8], at: usize) -> Option<SleepType> {
    let (&last, rest) = aml.get(..at)?.split_last()?;
    let named = last == NAME_OP || (last == ROOT_CHAR && rest.last() == Some(&NAME_OP));
    if !named {
        return None;
    }
    let mut p = at.checked_add(4)?;
    if *aml.get(p)? != PACKAGE_OP {
        return None;
    }
    p = p.checked_add(1)?;
    let (pkg_len, len_bytes) = pkg_length(aml.get(p..)?)?;
    // PkgLength counts its own encoding bytes.
    if pkg_len < len_bytes {
        return None;
    }
    let end = p.checked_add(pkg_len)?;
    let body = aml.get(p.checked_add(len_bytes)?..end)?;
    let (&count, mut elems) = body.split_first()?;
    if count < 2 {
        return None;
    }
    let a = element(&mut elems)?;
    let b = element(&mut elems)?;
    Some(SleepType { a, b })
}

/// Decodes an AML PkgLength: (length including its own bytes, bytes used).
fn pkg_length(b: &[u8]) -> Option<(usize, usize)> {
    let lead = *b.first()?;
    let extra = usize::from(lead >> 6);
    if extra == 0 {
        return Some((usize::from(lead & 0x3f), 1));
    }
    let mut len = usize::from(lead & 0x0f);
    for i in 0..extra {
        len |= usize::from(*b.get(i + 1)?) << (4 + 8 * i);
    }
    Some((len, extra + 1))
}

/// Reads one integer constant from `elems` and advances past it.
fn element(elems: &mut &[u8]) -> Option<u8> {
    let (&op, rest) = elems.split_first()?;
    let (value, used) = match op {
        ZERO_OP => (0u32, 0usize),
        ONE_OP => (1, 0),
        BYTE_PREFIX => (u32::from(*rest.first()?), 1),
        WORD_PREFIX => (
            u32::from(u16::from_le_bytes([*rest.first()?, *rest.get(1)?])),
            2,
        ),
        DWORD_PREFIX => (
            u32::from_le_bytes([*rest.first()?, *rest.get(1)?, *rest.get(2)?, *rest.get(3)?]),
            4,
        ),
        _ => return None,
    };
    if value > SLP_TYP_MAX {
        return None;
    }
    *elems = rest.get(used..)?;
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_encoding() {
        // Name (_S5, Package (0x04) { 0, 0, 0, 0 }) as emitted by QEMU.
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0, 0, 0, 0, 0x10,
        ];
        assert_eq!(find_s5(&aml), Some(SleepType { a: 0, b: 0 }));
    }

    #[test]
    fn byte_prefixed_with_root_char_and_junk_before() {
        let aml = [
            0xde, 0xad, 0x08, 0x5c, b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0a, 0x05, 0x0a,
            0x03, 0x01, 0x00,
        ];
        assert_eq!(find_s5(&aml), Some(SleepType { a: 5, b: 3 }));
    }

    #[test]
    fn wide_constants_and_multi_byte_pkg_length() {
        // PkgLength 0x4b 0x00 = 11 (two encoding bytes, nine of body).
        let mut aml = vec![0x08, b'_', b'S', b'5', b'_', 0x12, 0x4b, 0x00, 0x04];
        aml.extend_from_slice(&[0x0b, 0x07, 0x00, 0x0c, 0x01, 0, 0, 0]);
        assert_eq!(find_s5(&aml), Some(SleepType { a: 7, b: 1 }));
    }

    #[test]
    fn skips_false_positives_and_finds_later_real_one() {
        let mut aml = Vec::new();
        aml.extend_from_slice(b"xx_S5_yy"); // not a Name
        aml.extend_from_slice(&[0x08, b'_', b'S', b'5', b'_', 0x0a, 0x00]); // not a Package
        aml.extend_from_slice(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x02, 0x01, 0x01]);
        assert_eq!(find_s5(&aml), Some(SleepType { a: 1, b: 1 }));
    }

    #[test]
    fn rejects_malformed() {
        let name = [0x08, b'_', b'S', b'5', b'_'];
        let cases: &[&[u8]] = &[
            &[],
            &name,                                                   // truncated after name
            &[0x08, b'_', b'S', b'5', b'_', 0x12],                   // no length
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x40],             // length needs a 2nd byte
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x00, 0x04],       // length < its own size
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x3f, 0x04, 0, 0], // runs past the end
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x03, 0x01, 0x00], // one element only
            &[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x0a, 0x08, 0x00,
            ], // > 7
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x0a, 0x05], // second missing
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x5c, 0x00], // not a constant
            &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x0c, 1, 0], // dword cut short
        ];
        for c in cases {
            assert_eq!(find_s5(c), None, "{c:02x?}");
        }
    }

    #[test]
    fn name_at_buffer_start_does_not_panic() {
        assert_eq!(find_s5(b"_S5_"), None);
        assert_eq!(find_s5(b"_S5__S5_"), None);
    }
}
