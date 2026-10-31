//! Dev hooks of the H4 mitigations (`test=double-free`, `heap-uaf`,
//! `heap-overflow`, `keyslab-zero`, and those of the later H4 steps).
//!
//! Compiled only into images built with the `selftest` feature (dev
//! images); a production image contains none of this code or of its
//! strings, and its command line parser ignores the words anyway.

#![allow(unsafe_code)]

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::hint::black_box;

use urmqtt_log::{error, info, warn};
use urmqtt_mm::buddy::POISON;
use urmqtt_mm::keyslab::KeySlab;

use crate::cmdline::TestFault;

/// The kernel's key slab: 32-byte keys that outlive a request and must not
/// outlive their use. New long-lived secrets (S7's disk key) belong here.
pub static KEYS: KeySlab<32, 16> = KeySlab::new();

pub fn run(fault: TestFault) {
    match fault {
        TestFault::HeapDoubleFree => heap_double_free(),
        TestFault::HeapUaf => heap_uaf(),
        TestFault::HeapOverflow => heap_overflow(),
        TestFault::StackSmash => stack_smash(),
        TestFault::FaultSecrets | TestFault::FaultSecretsOpen => fault_with_secrets(),
        TestFault::PanicSecret => panic_with_secret(),
        TestFault::MteUaf => mte_uaf(),
        TestFault::MteOverflow => mte_overflow(),
        _ => warn!("test: {fault:?} is not implemented in this image"),
    }
}

/// A fresh block of `size` bytes the optimiser cannot reason about.
fn block(size: usize) -> (*mut u8, Layout) {
    let layout = Layout::from_size_align(size, 8).unwrap_or(Layout::new::<u64>());
    // SAFETY: a valid non-zero layout.
    let p = unsafe { alloc(layout) };
    (black_box(p), layout)
}

fn heap_double_free() {
    let (p, layout) = block(96);
    // SAFETY: the first free is legitimate; the second is the point.
    unsafe { dealloc(p, layout) };
    // SAFETY: deliberately wrong: the allocator must stop here.
    unsafe { dealloc(black_box(p), layout) };
    error!("test: the second free was NOT detected");
}

fn heap_uaf() {
    let (p, layout) = block(200);
    // SAFETY: the block is ours until the free.
    unsafe { dealloc(p, layout) };
    // SAFETY: deliberately wrong: a write to freed memory.
    unsafe { black_box(p).wrapping_add(77).write_volatile(0x41) };
    // The same CPU's cache hands the block out again.
    let (q, layout) = block(200);
    error!("test: the write after free was NOT detected");
    // SAFETY: the block came from `block`.
    unsafe { dealloc(q, layout) };
}

fn heap_overflow() {
    let (p, layout) = block(3000);
    // SAFETY: deliberately wrong: one byte past the allocation, into the
    // gap behind it (the block is 4096 bytes).
    unsafe { black_box(p).wrapping_add(3000).write_volatile(0x41) };
    // SAFETY: the block came from `block`.
    unsafe { dealloc(p, layout) };
    error!("test: the overflow was NOT detected");
}

/// `test=keyslab-zero`: the key slab wipes what it frees, stale handles are
/// refused, and the heap poisons what it frees.
pub fn keyslab_zero() {
    const N: usize = 8;
    let mut ok = true;
    // The pattern is a known test key: nothing else in the image holds it.
    let mut handles = alloc::vec::Vec::new();
    for i in 0..N {
        let key = [0xC0 + i as u8; 32];
        match KEYS.store(&key) {
            Ok(h) => handles.push(h),
            Err(_) => ok = false,
        }
    }
    let read_back = handles
        .iter()
        .enumerate()
        .all(|(i, h)| KEYS.with(h, |k| *k == [0xC0 + i as u8; 32]) == Ok(true));
    let live = KEYS.live();
    let mut stale = alloc::vec::Vec::new();
    for h in handles {
        stale.push(h.raw());
        ok &= KEYS.free(h).is_ok();
    }
    let zero = KEYS.free_slots_are_zero();
    let refused = stale.iter().all(|&(i, g)| {
        KEYS.free(urmqtt_mm::keyslab::KeyHandle::from_raw(i, g))
            .is_err()
            && KEYS
                .with(&urmqtt_mm::keyslab::KeyHandle::from_raw(i, g), |_| ())
                .is_err()
    });
    ok &= read_back && zero && refused && live == N && KEYS.live() == 0;
    info!(
        "keyslab-zero: {N} key(s) stored and read back in place ({read_back}), freed; \
         {} free slot(s) all zero ({zero}); stale handles refused ({refused}): {}",
        KEYS.free_slots(),
        if ok { "ok" } else { "FAILED" }
    );

    // The heap: a freed block holds poison, not what it held.
    let (p, layout) = block(1000);
    // SAFETY: the block is ours.
    unsafe { core::ptr::write_bytes(p, 0xA5, 1000) };
    // SAFETY: the block is ours until here.
    unsafe { dealloc(p, layout) };
    // SAFETY: the freed block stays mapped (heap memory is never unmapped);
    // reading it is the point of the check. Bytes 0..24 hold the cache link, tag and length.
    let seen = unsafe { core::slice::from_raw_parts(black_box(p).wrapping_add(24), 1000 - 24) };
    let poisoned = seen.iter().all(|&b| b == POISON);
    let leaked = seen.contains(&0xA5);
    info!(
        "keyslab-zero: a freed 1000-byte heap block reads back as poison {POISON:#04x} ({poisoned}), \
         no byte of the old contents left ({}): {}",
        !leaked,
        if poisoned && !leaked { "ok" } else { "FAILED" }
    );
}

/// A function with a 16-byte buffer that the loop below overruns by 48
/// bytes: the canary above the buffer is overwritten, and the check before
/// the return stops the machine. Kept out of line, and the writes volatile,
/// so the compiler can neither fold the loop nor drop the buffer.
#[inline(never)]
fn smash(n: usize) {
    let mut buf = [0u8; 16];
    // The pointer is recomputed from the frame on every write: held in a
    // spilled local it would sit above the buffer and be overwritten first.
    for i in 0..n {
        // SAFETY: deliberately wrong: writes `n - 16` bytes past the buffer.
        unsafe { buf.as_mut_ptr().wrapping_add(i).write_volatile(0x41) };
    }
    black_box(&buf);
}

fn stack_smash() {
    info!(
        "test: the stack canary is not the build-time constant: {}",
        !crate::hardening::stack_guard::is_default()
    );
    smash(black_box(64));
    error!("test: the stack smash was NOT detected");
}

/// A known test key: eight words that spell "SECRETKE" and friends, so a
/// grep for the hex or for the text finds them anywhere they leak.
pub const TEST_KEY: [u64; 6] = [
    0x5345_4352_4554_4b45, // "SECRETKE"
    0x595f_5445_5354_5f31, // "Y_TEST_1"
    0x5345_4352_4554_4b32, // "SECRETK2"
    0x595f_5445_5354_5f32, // "Y_TEST_2"
    0x5345_4352_4554_4b33, // "SECRETK3"
    0x595f_5445_5354_5f33, // "Y_TEST_3"
];

/// `test=fault-secrets`: the key is in registers and on the stack and the
/// heap when the CPU faults. Under the production policy (`redact`, or any
/// production image) the report must not show it; `fault-secrets-open`
/// prints the registers, which proves the check is able to see the bytes.
#[inline(never)]
fn fault_with_secrets() {
    let on_heap = alloc::boxed::Box::new(TEST_KEY);
    let on_stack = black_box(TEST_KEY);
    black_box(&on_heap);
    black_box(&on_stack);
    let unmapped = crate::memory::unmapped_mmio_probe();
    urmqtt_arch::trap::load_with_registers(unmapped, &TEST_KEY);
    error!("test: the fault with secrets did not happen");
}

/// `test=panic-secret`: a panic whose message is formatted from the key.
#[inline(never)]
fn panic_with_secret() {
    let key = black_box(TEST_KEY);
    #[allow(clippy::panic)]
    {
        panic!(
            "test panic carrying a key: {:02x?} {:#x}",
            key.as_slice(),
            key[0]
        );
    }
}

/// `test=mte-uaf`: a read through a pointer to a block that was freed. With
/// memory tagging the free set the block's tags to 0 and the stale pointer
/// carries a tag from 1 to 14: the read faults at once, before the
/// allocator's own check (which only runs when the block is reused) is
/// reached.
#[inline(never)]
fn mte_uaf() {
    if !crate::hardening::mte_active() {
        warn!("test: memory tagging is not active on this machine (no FEAT_MTE2), nothing to show");
        return;
    }
    let (p, layout) = block(100);
    // SAFETY: the block is ours until the free.
    unsafe { black_box(p).write_volatile(0x41) };
    // SAFETY: the block came from `block`.
    unsafe { dealloc(p, layout) };
    // SAFETY: deliberately wrong: a read through the stale pointer.
    let v = unsafe { black_box(p).read_volatile() };
    error!("test: the use after free was NOT detected (read {v:#x})");
}

/// `test=mte-overflow`: a write one granule (16 bytes) past the allocation,
/// into the next granule, which is not part of any allocation (tag 0).
#[inline(never)]
fn mte_overflow() {
    if !crate::hardening::mte_active() {
        warn!("test: memory tagging is not active on this machine (no FEAT_MTE2), nothing to show");
        return;
    }
    // 100 bytes are tagged as 112; byte 112 is the first one outside.
    let (p, layout) = block(100);
    // SAFETY: the last byte of the tagged part is inside the allocation's
    // granules.
    unsafe { black_box(p).wrapping_add(111).write_volatile(0x41) };
    info!("test: the write inside the last granule was accepted (granularity is 16 bytes)");
    // SAFETY: deliberately wrong: the first byte after the tagged granules.
    unsafe { black_box(p).wrapping_add(112).write_volatile(0x41) };
    error!("test: the overflow was NOT detected");
    // SAFETY: the block came from `block`.
    unsafe { dealloc(p, layout) };
}
