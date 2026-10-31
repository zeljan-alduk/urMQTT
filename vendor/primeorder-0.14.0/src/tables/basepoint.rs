//! Precomputed basepoint tables for accelerating fixed-base scalar multiplication.

#![allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]

use super::LookupTable;
use crate::{PrimeCurveParams, ProjectivePoint, Radix16Decomposition, Radix16Digits, Scalar};
use core::ops::Deref;
use elliptic_curve::{
    FieldBytesSize, array::typenum::Unsigned, ff::PrimeField, group::Group,
    subtle::ConditionallySelectable,
};

use lazy::Lazy as LazyLock;

/// urMQTT patch (ADR-110): a `no_std` once-cell built on atomics only, in place
/// of `std::sync::LazyLock` / `once_cell` + `critical-section`, so the table
/// works on bare metal with no further dependency. First use builds the
/// table; concurrent first users spin until it is ready (the build is about
/// a millisecond). The table is never dropped (it lives in a `static`).
mod lazy {
    use core::cell::UnsafeCell;
    use core::mem::MaybeUninit;
    use core::ops::Deref;
    use core::sync::atomic::{AtomicU8, Ordering};

    const EMPTY: u8 = 0;
    const BUILDING: u8 = 1;
    const READY: u8 = 2;

    pub struct Lazy<T> {
        state: AtomicU8,
        value: UnsafeCell<MaybeUninit<T>>,
        init: fn() -> T,
    }

    // SAFETY: `value` is written exactly once, by the thread that moved
    // `state` from EMPTY to BUILDING, and read only after a thread has
    // observed READY with Acquire (pairs with the Release store below).
    unsafe impl<T: Send + Sync> Sync for Lazy<T> {}

    impl<T> core::fmt::Debug for Lazy<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Lazy(..)")
        }
    }

    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Self {
                state: AtomicU8::new(EMPTY),
                value: UnsafeCell::new(MaybeUninit::uninit()),
                init,
            }
        }

        fn never() -> T {
            // A `ready` cell is never in the EMPTY state.
            unreachable!()
        }

        pub fn ready(value: T) -> Self {
            Self {
                state: AtomicU8::new(READY),
                value: UnsafeCell::new(MaybeUninit::new(value)),
                init: Self::never,
            }
        }
    }

    impl<T> Deref for Lazy<T> {
        type Target = T;

        fn deref(&self) -> &T {
            loop {
                match self.state.load(Ordering::Acquire) {
                    READY => break,
                    EMPTY => {
                        if self
                            .state
                            .compare_exchange(EMPTY, BUILDING, Ordering::Acquire, Ordering::Relaxed)
                            .is_ok()
                        {
                            let v = (self.init)();
                            // SAFETY: we hold BUILDING, so we are the only writer.
                            unsafe { (*self.value.get()).write(v) };
                            self.state.store(READY, Ordering::Release);
                            break;
                        }
                    }
                    _ => core::hint::spin_loop(),
                }
            }
            // SAFETY: READY was observed (or stored by us after the write).
            unsafe { (*self.value.get()).assume_init_ref() }
        }
    }
}

/// Precomputed lookup table of multiples of a base point, a.k.a. generator.
///
/// This type leverages lazy computation, and requires one of the following crate features to be
/// enabled in order to work:
/// - `std`: leverages `std::sync::LazyLock`
/// - `critical-section`: leverages `once_cell::sync::Lazy` via the `critical-section` crate,
///   enabling the feature to be used in `no_std` contexts.
#[derive(Debug)]
pub struct BasepointTable<Point, const WINDOW_SIZE: usize> {
    tables: LazyLock<[LookupTable<Point>; WINDOW_SIZE]>,
}

impl<Point, const WINDOW_SIZE: usize> BasepointTable<Point, WINDOW_SIZE>
where
    Point: ConditionallySelectable + Default + Group,
{
    /// Create a new [`BasepointTable`] which is lazily initialized on first use and can be bound
    /// to a constant.
    ///
    /// Computed using the `Point`'s [`Group::generator`] as the base point.
    pub const fn new() -> Self {
        /// Inner function to initialize the table.
        fn init_table<Point, const N: usize>() -> [LookupTable<Point>; N]
        where
            Point: ConditionallySelectable + Default + Group,
        {
            build_tables(Point::generator())
        }

        Self {
            tables: LazyLock::new(init_table),
        }
    }

    /// urMQTT patch (ADR-111): the table of an arbitrary, fixed point (for
    /// example a CA's public key), built now.
    pub fn from_point(point: Point) -> Self {
        Self {
            tables: LazyLock::ready(build_tables(point)),
        }
    }
}

fn build_tables<Point, const N: usize>(mut generator: Point) -> [LookupTable<Point>; N]
where
    Point: ConditionallySelectable + Default + Group,
{
    // Ensure basepoint table contains the expected number of entries for the scalar's size
    const {
        assert!(
            N as u32 == 1 + Point::Scalar::NUM_BITS.div_ceil(8),
            "incorrectly sized basepoint table"
        );
    }

    let mut res = [LookupTable::<Point>::default(); N];

    for i in 0..N {
        res[i] = LookupTable::new(generator);

        // We are storing tables spaced by two radix steps,
        // to decrease the size of the precomputed data.
        for _ in 0..8 {
            generator = generator.double();
        }
    }

    res
}

impl<C: PrimeCurveParams, const WINDOW_SIZE: usize>
    BasepointTable<ProjectivePoint<C>, WINDOW_SIZE>
{
    /// Multiply `Point::generator` by the given scalar in constant-time, using the precomputed
    /// basepoint table to accelerate the scalar multiplication.
    pub fn mul(&self, k: &Scalar<C>) -> ProjectivePoint<C> {
        let digits = Radix16Decomposition::<Radix16Digits<C>>::new(k);
        let len = FieldBytesSize::<C>::USIZE;
        let mut acc = self[len].select(digits[len * 2]);
        let mut acc2 = ProjectivePoint::<C>::IDENTITY;
        for i in (0..len).rev() {
            acc2 += &self[i].select(digits[i * 2 + 1]);
            acc += &self[i].select(digits[i * 2]);
        }

        // This is the price of halving the precomputed table size.
        for _ in 0..4 {
            acc2 = acc2.double();
        }

        acc + acc2
    }

    /// Multiply `Point::generator` by the given scalar in constant-time, using the precomputed
    /// basepoint table to accelerate the scalar multiplication.
    ///
    /// <div class = "warning">
    /// <b>Security Warning</b>
    ///
    /// Variable-time scalar multiplication can potentially leak secret values and should NOT be
    /// used with them.
    /// </div>
    pub fn mul_vartime(&self, k: &Scalar<C>) -> ProjectivePoint<C> {
        let digits = Radix16Decomposition::<Radix16Digits<C>>::new(k);
        let len = FieldBytesSize::<C>::USIZE;
        let mut acc = self[len].select_vartime(digits[len * 2]);
        let mut acc2 = ProjectivePoint::<C>::IDENTITY;
        for i in (0..len).rev() {
            acc2 += &self[i].select_vartime(digits[i * 2 + 1]);
            acc += &self[i].select_vartime(digits[i * 2]);
        }

        // This is the price of halving the precomputed table size.
        for _ in 0..4 {
            acc2 = acc2.double();
        }

        acc + acc2
    }
}

impl<Point, const WINDOW_SIZE: usize> Default for BasepointTable<Point, WINDOW_SIZE>
where
    Point: ConditionallySelectable + Default + Group,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Point, const WINDOW_SIZE: usize> Deref for BasepointTable<Point, WINDOW_SIZE> {
    type Target = [LookupTable<Point>; WINDOW_SIZE];

    #[inline]
    fn deref(&self) -> &[LookupTable<Point>; WINDOW_SIZE] {
        &self.tables
    }
}
