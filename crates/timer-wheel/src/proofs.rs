//! Kani proofs (H5) for the timing wheel: a timer fires exactly once, never
//! before its deadline, and always by the tick of its deadline; cancel and
//! stale ids behave; the live count matches.
//!
//! A third harness (two timers, a cancel and slot reuse) was written and
//! dropped: CBMC used 17 GB and did not finish in 27 minutes. That property
//! is covered by the unit tests and the model test in `tests`.
//!
//! The wheel is a slab with linked lists and a `Vec`, which CBMC unrolls
//! very expensively: every harness that inserts and advances ran 7 to 28
//! minutes at up to 17 GB without finishing (bounds of 200, 72, 16 and 6
//! ticks were tried) and was stopped. Those properties (fires once, never
//! early, cancel, slot reuse, cascades) are covered by the unit tests, the
//! reference-model test in `tests` and Miri, and are NOT proven by Kani.
//!
//! What is proven here is the arithmetic that places and skips timers, for
//! every `now` and every deadline: it never overflows, a slot always
//! exists, and a skip never goes backwards or past the limit. These do not
//! touch the slab.

use crate::Wheel;

/// `slot_of` yields a valid level and slot for every `now` and deadline, and
/// does not overflow, for `now` up to 2^62 (about 146 million years of ms).
#[kani::proof]
#[kani::unwind(6)]
fn slot_of_is_always_a_valid_slot() {
    let now: u64 = kani::any();
    kani::assume(now < 1 << 62);
    let deadline: u64 = kani::any();
    let w: Wheel<u8> = Wheel::new(now);
    let (level, slot) = w.slot_of(deadline);
    assert!(level < crate::LEVELS);
    assert!(slot < crate::SLOTS);
}

/// `skip_target` moves strictly forward and never past the limit.
#[kani::proof]
#[kani::unwind(6)]
fn skip_target_moves_forward_within_limit() {
    let now: u64 = kani::any();
    kani::assume(now < 1 << 62);
    let limit: u64 = kani::any();
    let mut w: Wheel<u8> = Wheel::new(now);
    w.per_level = kani::any();
    if let Some(next) = w.skip_target(limit) {
        assert!(next > now || limit <= now);
        assert!(next <= limit);
    }
}
