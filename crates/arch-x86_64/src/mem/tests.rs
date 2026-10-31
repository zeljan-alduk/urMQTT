//! Differential tests of `copy` and `set` against plain Rust references: all
//! sizes up to 300, around every path boundary and well above, all source and
//! destination alignments, every overlap shift worth trying, with guard bytes
//! around the destination. Each runs with the `rep` path on and off.
//!
//! The assembly only runs on an x86_64 host (Linux, or macOS under Rosetta);
//! Miri cannot execute it (the reference is the Rust below, checked by the
//! ordinary tests).

use super::{copy, set, set_fast_rep};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.next() as u8;
        }
    }
}

const GUARD: usize = 48;
const PAD: u8 = 0xEE;

/// Sizes: every size to 300, then both sides of each boundary and some big ones.
fn sizes() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=300).collect();
    for b in [
        511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 2050, 2111, 2112, 2113, 4095, 4096,
        4097, 8191, 8192, 8193, 65_535, 65_536, 65_541, 1_000_003,
    ] {
        v.push(b);
    }
    v
}

fn offsets(n: usize) -> Vec<usize> {
    if n <= 300 {
        (0..32).collect()
    } else {
        vec![0, 1, 7, 8, 15, 16, 17, 31]
    }
}

fn run_copy_disjoint() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for n in sizes() {
        for so in offsets(n) {
            for d_o in offsets(n) {
                let mut src = vec![0u8; so + n + GUARD];
                rng.fill(&mut src);
                let mut dst = vec![PAD; GUARD + d_o + n + GUARD];
                let p = unsafe { copy(dst.as_mut_ptr().add(GUARD + d_o), src.as_ptr().add(so), n) };
                assert_eq!(
                    p as usize,
                    dst.as_ptr() as usize + GUARD + d_o,
                    "return value"
                );
                assert_eq!(
                    &dst[GUARD + d_o..GUARD + d_o + n],
                    &src[so..so + n],
                    "n={n} so={so} do={d_o}"
                );
                assert!(
                    dst[..GUARD + d_o].iter().all(|&b| b == PAD),
                    "head guard n={n} so={so} do={d_o}"
                );
                assert!(
                    dst[GUARD + d_o + n..].iter().all(|&b| b == PAD),
                    "tail guard n={n} so={so} do={d_o}"
                );
            }
        }
    }
}

fn shifts(n: usize) -> Vec<isize> {
    let n = n as isize;
    let mut v = vec![0isize];
    for s in [
        1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 130, 255, 256, 257,
    ] {
        v.push(s);
        v.push(-s);
    }
    for s in [n - 1, n, n + 1, n / 2, n / 2 + 1, n + 64, n + 200] {
        if s > 0 {
            v.push(s);
            v.push(-s);
        }
    }
    v
}

fn run_copy_overlap() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for n in sizes().into_iter().filter(|&n| n <= 4200 || n == 65_541) {
        let reps = if n <= 300 { 16 } else { 3 };
        for base in 0..reps {
            for sh in shifts(n) {
                // `dest = src + sh` inside one buffer with room on both sides.
                let room = GUARD + 600 + n.min(70_000);
                let total = room + n + room;
                let mut buf = vec![0u8; total];
                rng.fill(&mut buf);
                let src_at = (room + base) as isize;
                let dst_at = src_at + sh;
                if dst_at < GUARD as isize || dst_at as usize + n + GUARD > total {
                    continue;
                }
                let (src_at, dst_at) = (src_at as usize, dst_at as usize);
                let mut want = buf.clone();
                let tmp = buf[src_at..src_at + n].to_vec();
                want[dst_at..dst_at + n].copy_from_slice(&tmp);
                let p = buf.as_mut_ptr();
                let r = unsafe { copy(p.add(dst_at), p.add(src_at) as *const u8, n) };
                assert_eq!(r as usize, p as usize + dst_at);
                assert!(buf == want, "overlap n={n} base={base} shift={sh}");
            }
        }
    }
}

fn run_set() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for n in sizes() {
        for d_o in offsets(n) {
            for c in [0i32, 1, 0x5a, 0x80, 0xff, 0x1ff, -1] {
                let mut dst = vec![PAD; GUARD + d_o + n + GUARD];
                if rng.next() & 3 == 0 && n > 300 {
                    continue;
                }
                let p = unsafe { set(dst.as_mut_ptr().add(GUARD + d_o), c, n) };
                assert_eq!(p as usize, dst.as_ptr() as usize + GUARD + d_o);
                let b = c as u8;
                assert!(
                    dst[GUARD + d_o..GUARD + d_o + n].iter().all(|&x| x == b),
                    "set n={n} do={d_o} c={c}"
                );
                assert!(
                    dst[..GUARD + d_o].iter().all(|&x| x == PAD),
                    "head guard n={n}"
                );
                assert!(
                    dst[GUARD + d_o + n..].iter().all(|&x| x == PAD),
                    "tail guard n={n}"
                );
            }
        }
    }
}

#[test]
fn copy_matches_the_reference_without_overlap() {
    for fast in [false, true] {
        set_fast_rep(fast);
        run_copy_disjoint();
    }
    set_fast_rep(false);
}

#[test]
fn copy_matches_memmove_with_overlap() {
    for fast in [false, true] {
        set_fast_rep(fast);
        run_copy_overlap();
    }
    set_fast_rep(false);
}

#[test]
fn set_matches_the_reference() {
    for fast in [false, true] {
        set_fast_rep(fast);
        run_set();
    }
    set_fast_rep(false);
}
