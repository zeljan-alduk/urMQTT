//! The C string functions the SQLite amalgamation needs on bare metal (the
//! exact list comes from its undefined symbols; `mem*` come from
//! `compiler_builtins`). Host builds use the system libc instead.
//!
//! Each function takes NUL-terminated strings from SQLite and reads them
//! one byte at a time, never past the terminator (or `n`).

use core::ffi::{c_char, c_int};

/// # Safety
/// `s` must point to a NUL-terminated string.
unsafe fn at(s: *const c_char, i: usize) -> u8 {
    let p = s.cast::<u8>().wrapping_add(i);
    // SAFETY: the caller guarantees `s[..=len]` is readable and `i` never
    // goes past the terminator.
    unsafe { *p }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let mut n = 0;
    // SAFETY: `s` is NUL-terminated (C contract); stops at the terminator.
    while unsafe { at(s, n) } != 0 {
        n += 1;
    }
    n
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: both are NUL-terminated; comparison stops at the first NUL.
    unsafe { strncmp(a, b, usize::MAX) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    let mut i = 0;
    while i < n {
        // SAFETY: index `i` is at most the position of the first NUL in
        // either string (the loop returns there).
        let x = unsafe { at(a, i) };
        // SAFETY: as above, for `b`.
        let y = unsafe { at(b, i) };
        if x != y || x == 0 {
            return c_int::from(x) - c_int::from(y);
        }
        i += 1;
    }
    0
}

/// Whether byte `c` occurs in the NUL-terminated `set`.
///
/// # Safety
/// `set` must point to a NUL-terminated string.
unsafe fn contains(set: *const c_char, c: u8) -> bool {
    let mut i = 0;
    loop {
        // SAFETY: `set` is NUL-terminated; stops at the terminator.
        let x = unsafe { at(set, i) };
        if x == 0 {
            return false;
        }
        if x == c {
            return true;
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: `s` is NUL-terminated; stops at the terminator.
        let c = unsafe { at(s, n) };
        // SAFETY: `reject` is NUL-terminated.
        if c == 0 || unsafe { contains(reject, c) } {
            return n;
        }
        n += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: `s` is NUL-terminated; stops at the terminator.
        let c = unsafe { at(s, n) };
        // SAFETY: `accept` is NUL-terminated.
        if c == 0 || !unsafe { contains(accept, c) } {
            return n;
        }
        n += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let want = c as u8;
    let mut i = 0;
    loop {
        // SAFETY: `s` is NUL-terminated; stops at the terminator.
        let x = unsafe { at(s, i) };
        if x == want {
            return s.wrapping_add(i).cast_mut();
        }
        if x == 0 {
            return core::ptr::null_mut();
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    let want = c as u8;
    let mut found = core::ptr::null_mut();
    let mut i = 0;
    loop {
        // SAFETY: `s` is NUL-terminated; stops at the terminator.
        let x = unsafe { at(s, i) };
        if x == want {
            found = s.wrapping_add(i).cast_mut();
        }
        if x == 0 {
            return found;
        }
        i += 1;
    }
}
