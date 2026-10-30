//! TSC frequency discovery and tick/nanosecond arithmetic (pure; D6).
//!
//! Every function here is plain integer maths so the edge cases (a zero
//! crystal in CPUID 0x15, overflow on long uptimes) run under host tests.

const NS_PER_S: u64 = 1_000_000_000;

/// Where the TSC frequency came from, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// CPUID 0x4000_0010 (hypervisor timing leaf, kHz).
    HypervisorLeaf,
    /// The KVM paravirtual clock's scale factors.
    Kvmclock,
    /// CPUID 0x15 (crystal clock ratio).
    Cpuid15,
    /// Measured against the HPET.
    Hpet,
    /// Measured against the ACPI PM timer.
    PmTimer,
    /// CPUID 0x16 (nominal base MHz; approximate).
    Cpuid16,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Self::HypervisorLeaf => "cpuid-0x40000010",
            Self::Kvmclock => "kvmclock",
            Self::Cpuid15 => "cpuid-0x15",
            Self::Hpet => "hpet",
            Self::PmTimer => "acpi-pm-timer",
            Self::Cpuid16 => "cpuid-0x16",
        }
    }
}

/// Nanoseconds in `ticks` at `hz`, rounded down, saturating. Splits into
/// whole seconds and a remainder so the common case needs no 128-bit
/// division and the result is exact.
pub const fn ticks_to_ns(ticks: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    let secs = ticks / hz;
    let rem = ticks % hz;
    let frac = if hz <= u64::MAX / NS_PER_S {
        // rem < hz, so rem * 1e9 fits.
        rem * NS_PER_S / hz
    } else {
        ((rem as u128 * NS_PER_S as u128) / hz as u128) as u64
    };
    match secs.checked_mul(NS_PER_S) {
        Some(s) => s.saturating_add(frac),
        None => u64::MAX,
    }
}

/// Ticks in `ns` nanoseconds at `hz`, rounded down, saturating.
pub const fn ns_to_ticks(ns: u64, hz: u64) -> u64 {
    let secs = ns / NS_PER_S;
    let rem = ns % NS_PER_S;
    let frac = ((rem as u128 * hz as u128) / NS_PER_S as u128) as u64;
    match secs.checked_mul(hz) {
        Some(s) => s.saturating_add(frac),
        None => u64::MAX,
    }
}

/// CPUID 0x15: TSC Hz = crystal Hz * ebx / eax. `None` when the leaf does
/// not describe the TSC (eax or ebx zero) and when the crystal (ecx) is
/// zero: the caller falls through to calibration rather than guessing a
/// crystal from the CPU model, where a wrong guess skews every timer.
pub const fn cpuid15_hz(eax: u32, ebx: u32, ecx: u32) -> Option<u64> {
    if eax == 0 || ebx == 0 || ecx == 0 {
        return None;
    }
    let hz = (ecx as u128 * ebx as u128) / eax as u128;
    if hz == 0 || hz > u64::MAX as u128 {
        None
    } else {
        Some(hz as u64)
    }
}

/// CPUID 0x16: processor base frequency in MHz (eax), as Hz. Approximate.
pub const fn cpuid16_hz(eax: u32) -> Option<u64> {
    let mhz = eax & 0xffff;
    if mhz == 0 {
        None
    } else {
        Some(mhz as u64 * 1_000_000)
    }
}

/// CPUID 0x4000_0010 EAX: TSC frequency in kHz.
pub const fn hypervisor_leaf_hz(eax: u32) -> Option<u64> {
    if eax == 0 {
        None
    } else {
        Some(eax as u64 * 1000)
    }
}

/// The TSC frequency implied by a pvclock record: the guest computes
/// `ns = ((tsc << shift) * mul) >> 32` (a negative `shift` shifts right),
/// so `hz = 1e9 * 2^32 / (mul * 2^shift)`.
pub const fn pvclock_hz(mul: u32, shift: i8) -> Option<u64> {
    if mul == 0 || shift > 31 || shift < -31 {
        return None;
    }
    let num: u128 = (NS_PER_S as u128) << 32;
    let hz = if shift >= 0 {
        num / ((mul as u128) << shift as u32)
    } else {
        (num << (-(shift as i32)) as u32) / mul as u128
    };
    if hz == 0 || hz > u64::MAX as u128 {
        None
    } else {
        Some(hz as u64)
    }
}

/// TSC Hz from a measurement: `tsc_delta` TSC ticks elapsed while a
/// reference counter at `ref_hz` advanced by `ref_delta`.
pub const fn calibrate_hz(tsc_delta: u64, ref_delta: u64, ref_hz: u64) -> Option<u64> {
    if ref_delta == 0 || tsc_delta == 0 {
        return None;
    }
    let hz = (tsc_delta as u128 * ref_hz as u128 + ref_delta as u128 / 2) / ref_delta as u128;
    if hz == 0 || hz > u64::MAX as u128 {
        None
    } else {
        Some(hz as u64)
    }
}

/// Plausible TSC frequencies: 10 MHz to 10 GHz. Anything else is a broken
/// source and the next one is tried.
pub const fn plausible(hz: u64) -> bool {
    hz >= 10_000_000 && hz <= 10_000_000_000
}

/// The median of three samples (one SMI or steal burst cannot skew it).
pub const fn median3(a: u64, b: u64, c: u64) -> u64 {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    if c < lo {
        lo
    } else if c > hi {
        hi
    } else {
        c
    }
}

/// Reference ticks of a counter at `ref_hz` covering `ms` milliseconds.
pub const fn ref_ticks_for_ms(ref_hz: u64, ms: u64) -> u64 {
    ref_hz / 1000 * ms
}

/// Difference of two reads of a free-running counter that is `bits` wide
/// (32 or 64), tolerating one wrap.
pub const fn counter_delta(start: u64, end: u64, bits: u32) -> u64 {
    if bits >= 64 {
        end.wrapping_sub(start)
    } else {
        end.wrapping_sub(start) & ((1u64 << bits) - 1)
    }
}

/// Local APIC timer initial count for a deadline `delta_tsc` TSC ticks
/// away, given the APIC timer's and the TSC's frequencies. At least 1 (a
/// count of 0 would stop the timer) and clamped to the 32-bit register.
pub const fn lapic_count_for(delta_tsc: u64, lapic_hz: u64, tsc_hz: u64) -> u32 {
    if tsc_hz == 0 {
        return 1;
    }
    let c = (delta_tsc as u128 * lapic_hz as u128) / tsc_hz as u128;
    if c == 0 {
        1
    } else if c > u32::MAX as u128 {
        u32::MAX
    } else {
        c as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_exact_and_monotonic() {
        let hz = 2_999_999_999;
        assert_eq!(ticks_to_ns(hz, hz), NS_PER_S);
        assert_eq!(ns_to_ticks(NS_PER_S, hz), hz);
        assert_eq!(ticks_to_ns(0, hz), 0);
        let mut last = 0;
        for t in (0..10_000_000u64).step_by(9973) {
            let n = ticks_to_ns(t, hz);
            assert!(n >= last);
            last = n;
        }
        assert_eq!(ticks_to_ns(30, 3_000_000_000), 10);
        assert_eq!(ns_to_ticks(10, 3_000_000_000), 30);
    }

    #[test]
    fn conversions_saturate_instead_of_wrapping() {
        assert_eq!(ticks_to_ns(u64::MAX, 1_000_000), u64::MAX);
        assert_eq!(ns_to_ticks(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(ticks_to_ns(5, 0), 0);
        // A 10-year uptime at 5 GHz is exact.
        let secs = 10 * 365 * 86_400u64;
        assert_eq!(
            ticks_to_ns(secs * 5_000_000_000, 5_000_000_000),
            secs * NS_PER_S
        );
        // Frequencies above the u64 fast path still convert.
        assert_eq!(ticks_to_ns(20_000_000_000, 20_000_000_000), NS_PER_S);
    }

    #[test]
    fn round_trip_loses_less_than_one_tick() {
        for hz in [10_000_000u64, 2_400_000_000, 3_579_545, 4_999_999_999] {
            for ns in [1u64, 999, 1_000_000_007, 123_456_789_012] {
                let back = ticks_to_ns(ns_to_ticks(ns, hz), hz);
                assert!(
                    back <= ns && ns - back <= NS_PER_S / hz + 1,
                    "{hz} {ns} {back}"
                );
            }
        }
    }

    #[test]
    fn cpuid15_edge_cases() {
        // 24 MHz crystal, ratio 125/1 -> 3 GHz.
        assert_eq!(cpuid15_hz(1, 125, 24_000_000), Some(3_000_000_000));
        assert_eq!(cpuid15_hz(2, 83, 24_000_000), Some(996_000_000));
        // crystal = 0 (Skylake-X, many VMs): do not guess.
        assert_eq!(cpuid15_hz(1, 125, 0), None);
        assert_eq!(cpuid15_hz(0, 125, 24_000_000), None);
        assert_eq!(cpuid15_hz(1, 0, 24_000_000), None);
        assert_eq!(cpuid15_hz(u32::MAX, 1, 1), None);
    }

    #[test]
    fn cpuid16_and_hypervisor_leaf() {
        assert_eq!(cpuid16_hz(2500), Some(2_500_000_000));
        assert_eq!(cpuid16_hz(0), None);
        assert_eq!(cpuid16_hz(0xffff_0000), None);
        assert_eq!(hypervisor_leaf_hz(2_900_000), Some(2_900_000_000));
        assert_eq!(hypervisor_leaf_hz(0), None);
    }

    #[test]
    fn pvclock_scale_matches_known_values() {
        // 2.5 GHz: 0.4 ns per tick -> mul = 0.4 * 2^32 with shift 0.
        let hz = pvclock_hz(1_717_986_918, 0).unwrap();
        assert!(hz.abs_diff(2_500_000_000) < 1000, "{hz}");
        // The same clock with a left shift of 1 and half the multiplier.
        let hz2 = pvclock_hz(858_993_459, 1).unwrap();
        assert!(hz2.abs_diff(hz) < 10, "{hz2} {hz}");
        // 10 GHz-ish TSCs need a right shift: 0.1 ns per tick.
        let hz3 = pvclock_hz(858_993_459, -1).unwrap();
        assert!(hz3.abs_diff(10_000_000_000) < 100, "{hz3}");
        // 100 MHz: 10 ns per tick = mul 10 * 2^32 / 2^4.
        let hz4 = pvclock_hz(2_684_354_560, 4).unwrap();
        assert!(hz4.abs_diff(100_000_000) < 10, "{hz4}");
        assert_eq!(pvclock_hz(0, 0), None);
        assert_eq!(pvclock_hz(1, 40), None);
    }

    #[test]
    fn calibration_math() {
        // HPET at 14.31818 MHz over 20 ms: 286_363 ticks; TSC at 2.5 GHz.
        let hz = calibrate_hz(50_000_000, 286_363, 14_318_180).unwrap();
        assert!(hz.abs_diff(2_500_000_000) < 20_000, "{hz}");
        assert_eq!(calibrate_hz(1, 0, 1), None);
        assert_eq!(calibrate_hz(0, 1, 1), None);
        assert_eq!(calibrate_hz(u64::MAX, 1, u64::MAX), None);
    }

    #[test]
    fn plausibility_and_median() {
        assert!(plausible(2_500_000_000));
        assert!(!plausible(0));
        assert!(!plausible(999));
        assert!(!plausible(u64::MAX));
        assert_eq!(median3(1, 2, 3), 2);
        assert_eq!(median3(3, 1, 2), 2);
        assert_eq!(median3(9, 9, 1), 9);
        assert_eq!(median3(1, 100, 2), 2);
    }

    #[test]
    fn counter_delta_wraps() {
        assert_eq!(counter_delta(10, 25, 32), 15);
        assert_eq!(counter_delta(0xffff_fff0, 0x10, 32), 0x20);
        assert_eq!(counter_delta(u64::MAX - 1, 3, 64), 5);
        assert_eq!(ref_ticks_for_ms(14_318_180, 20), 286_360);
    }

    #[test]
    fn lapic_count_clamps() {
        // TSC 2 GHz, APIC timer 1 GHz: half as many counts.
        assert_eq!(lapic_count_for(2000, 1_000_000_000, 2_000_000_000), 1000);
        assert_eq!(lapic_count_for(0, 1_000_000_000, 2_000_000_000), 1);
        assert_eq!(lapic_count_for(u64::MAX, 1_000_000_000, 1), u32::MAX);
        assert_eq!(lapic_count_for(5, 5, 0), 1);
    }
}
