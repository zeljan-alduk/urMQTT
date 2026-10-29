//! Sequence-number arithmetic modulo 2^32 (RFC 793 §3.3).

/// `a < b` in sequence space.
pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}

pub fn ge(a: u32, b: u32) -> bool {
    le(b, a)
}

/// `a` is in `[lo, lo + len)`.
pub fn in_window(a: u32, lo: u32, len: u32) -> bool {
    a.wrapping_sub(lo) < len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps() {
        assert!(lt(u32::MAX, 0));
        assert!(gt(5, u32::MAX - 5));
        assert!(le(7, 7) && ge(7, 7));
        assert!(in_window(2, u32::MAX - 1, 5));
        assert!(!in_window(3, u32::MAX - 1, 5));
    }
}
