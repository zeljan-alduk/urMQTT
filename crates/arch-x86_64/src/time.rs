//! Monotonic time and the per-CPU deadline timer: the TSC and the local
//! APIC timer (X4, ADR-045).
//!
//! `now()` is the raw TSC, like aarch64's raw counter; `uptime_ns()`
//! subtracts the TSC value taken at `init`. Deadlines are TSC values. The
//! timer is the local APIC's TSC-deadline mode when CPUID has it, else a
//! one-shot LAPIC timer re-armed from the deadline (its rate is measured
//! against the TSC once). `deadline()` returns the last value programmed on
//! this CPU, also after it fired, as the aarch64 compare register does: the
//! tick handler re-arms from it.

#![allow(unsafe_code)]

use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::apic::{self, TimerMode};
use crate::hpet::Hpet;
use crate::tsc::{self, Source};
use crate::{percpu, prim, vectors};

/// Why no time base could be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No source gave a plausible TSC frequency.
    NoTscFrequency,
}

/// The ACPI PM timer, as the FADT describes it (X6 supplies this).
#[derive(Debug, Clone, Copy)]
pub struct PmTimer {
    pub port: u16,
    /// True for a 32-bit counter, false for 24-bit.
    pub wide: bool,
}

/// What the platform can offer for calibration. Everything is optional;
/// CPUID-based sources need nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sources {
    /// Mapped (uncached) HPET register window.
    pub hpet_mmio: Option<usize>,
    pub pm_timer: Option<PmTimer>,
    /// Translates a kernel virtual address to its physical address; enables
    /// reading the TSC scale from KVM's paravirtual clock.
    pub virt_to_phys: Option<fn(usize) -> u64>,
}

/// What `init` found, for the boot log.
#[derive(Debug, Clone, Copy)]
pub struct Info {
    pub tsc_hz: u64,
    pub source: Source,
    /// CPUID.80000007H:EDX[8]. Without it the TSC may stop in deep C-states
    /// or scale with P-states; the kernel runs on it anyway (a hypervisor's
    /// virtual TSC is constant) and the log says so.
    pub invariant_tsc: bool,
    /// CPUID.1:ECX[24].
    pub tsc_deadline: bool,
}

static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_BASE: AtomicU64 = AtomicU64::new(0);
static LAPIC_HZ: AtomicU64 = AtomicU64::new(0);
static USE_DEADLINE: AtomicBool = AtomicBool::new(false);
static INVARIANT: AtomicBool = AtomicBool::new(false);
static SOURCE: AtomicU64 = AtomicU64::new(0);

const MAX_CPUS: usize = 64;
static DEADLINE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

const SOURCES: [Source; 6] = [
    Source::HypervisorLeaf,
    Source::Kvmclock,
    Source::Cpuid15,
    Source::Hpet,
    Source::PmTimer,
    Source::Cpuid16,
];

fn source_from(i: u64) -> Source {
    SOURCES.get(i as usize).copied().unwrap_or(Source::Cpuid16)
}

/// Finds the TSC frequency and starts the clock. Runs once on the boot CPU
/// before the local APIC timer is used. Order (D6, with one deliberate
/// change: a measured value beats CPUID 0x16, whose base MHz is only
/// nominal): hypervisor timing leaf, kvmclock, CPUID 0x15, HPET, ACPI PM
/// timer, CPUID 0x16.
pub fn init(src: &Sources) -> Result<Info, Error> {
    let (hz, source) = discover(src).ok_or(Error::NoTscFrequency)?;
    TSC_HZ.store(hz, Ordering::Relaxed);
    let idx = SOURCES.iter().position(|s| *s == source).unwrap_or(0);
    SOURCE.store(idx as u64, Ordering::Relaxed);
    TSC_BASE.store(prim::rdtsc_ordered(), Ordering::Release);

    let (max_ext, _, _, _) = prim::cpuid(0x8000_0000, 0);
    let invariant = max_ext >= 0x8000_0007 && prim::cpuid(0x8000_0007, 0).3 & (1 << 8) != 0;
    INVARIANT.store(invariant, Ordering::Relaxed);
    let deadline = prim::cpuid(1, 0).2 & (1 << 24) != 0;
    USE_DEADLINE.store(deadline, Ordering::Relaxed);
    Ok(info())
}

/// The current time base description (zeroed fields before `init`).
pub fn info() -> Info {
    Info {
        tsc_hz: TSC_HZ.load(Ordering::Relaxed),
        source: source_from(SOURCE.load(Ordering::Relaxed)),
        invariant_tsc: INVARIANT.load(Ordering::Relaxed),
        tsc_deadline: USE_DEADLINE.load(Ordering::Relaxed),
    }
}

/// True when the LAPIC timer runs in one-shot fallback mode.
pub fn timer_is_fallback() -> bool {
    !USE_DEADLINE.load(Ordering::Relaxed)
}

fn discover(src: &Sources) -> Option<(u64, Source)> {
    let plausible = |hz: Option<u64>| hz.filter(|h| tsc::plausible(*h));
    let hv_max = prim::hypervisor_max_leaf();
    if hv_max >= 0x4000_0010 {
        let hz = plausible(tsc::hypervisor_leaf_hz(prim::cpuid(0x4000_0010, 0).0));
        if let Some(hz) = hz {
            return Some((hz, Source::HypervisorLeaf));
        }
    }
    if let Some(hz) = plausible(kvmclock_hz(src)) {
        return Some((hz, Source::Kvmclock));
    }
    let max = prim::max_leaf();
    if max >= 0x15 {
        let (a, b, c, _) = prim::cpuid(0x15, 0);
        if let Some(hz) = plausible(tsc::cpuid15_hz(a, b, c)) {
            return Some((hz, Source::Cpuid15));
        }
    }
    if let Some(mmio) = src.hpet_mmio
        && let Some(h) = Hpet::start(mmio)
        && let Some(hz) = plausible(measure(h.hz, h.bits, || h.counter()))
    {
        return Some((hz, Source::Hpet));
    }
    if let Some(pm) = src.pm_timer {
        let bits = if pm.wide { 32 } else { 24 };
        let read = || {
            let v = prim::inl(pm.port);
            u64::from(if pm.wide { v } else { v & 0x00ff_ffff })
        };
        if let Some(hz) = plausible(measure(3_579_545, bits, read)) {
            return Some((hz, Source::PmTimer));
        }
    }
    if max >= 0x16
        && let Some(hz) = plausible(tsc::cpuid16_hz(prim::cpuid(0x16, 0).0))
    {
        return Some((hz, Source::Cpuid16));
    }
    None
}

/// Measures the TSC against a free-running counter: three 20 ms windows,
/// median. Gives up on a counter that does not advance.
fn measure(ref_hz: u64, bits: u32, read: impl Fn() -> u64) -> Option<u64> {
    let window = tsc::ref_ticks_for_ms(ref_hz, 20);
    let mut samples = [0u64; 3];
    for s in &mut samples {
        let r0 = read();
        let t0 = prim::rdtsc_ordered();
        let (t1, r1) = loop {
            let r = read();
            let t = prim::rdtsc_ordered();
            if tsc::counter_delta(r0, r, bits) >= window {
                break (t, r);
            }
            // 4e9 TSC ticks is 0.4 s at 10 GHz: the counter is not moving.
            if t.wrapping_sub(t0) > 4_000_000_000 {
                return None;
            }
            core::hint::spin_loop();
        };
        *s = tsc::calibrate_hz(
            t1.wrapping_sub(t0),
            tsc::counter_delta(r0, r1, bits),
            ref_hz,
        )?;
    }
    Some(tsc::median3(samples[0], samples[1], samples[2]))
}

// ---- KVM paravirtual clock (used for its TSC scale only) ----

const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3;

/// pvclock_vcpu_time_info.
#[repr(C, align(64))]
struct PvClock {
    version: u32,
    _pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    _pad1: [u8; 2],
}

struct PvPage(core::cell::UnsafeCell<PvClock>);

// SAFETY: the page is written by the hypervisor and read with volatile
// loads on the boot CPU during `init` only.
unsafe impl Sync for PvPage {}

static PVCLOCK: PvPage = PvPage(core::cell::UnsafeCell::new(PvClock {
    version: 0,
    _pad0: 0,
    tsc_timestamp: 0,
    system_time: 0,
    tsc_to_system_mul: 0,
    tsc_shift: 0,
    flags: 0,
    _pad1: [0; 2],
}));

/// Volatile read of one field of the pvclock page.
fn pv_read<T: Copy>(offset: usize) -> T {
    let p = PVCLOCK
        .0
        .get()
        .cast::<u8>()
        .wrapping_add(offset)
        .cast::<T>();
    // SAFETY: `p` points into the static page, which stays valid for the
    // program's lifetime; the host writes it, hence the volatile read.
    unsafe { core::ptr::read_volatile(p) }
}

/// Registers the pvclock page, reads the TSC scale the host computed for
/// this vCPU, and unregisters the page again.
fn kvmclock_hz(src: &Sources) -> Option<u64> {
    let v2p = src.virt_to_phys?;
    if prim::hypervisor_signature() != *b"KVMKVMKVM\0\0\0" {
        return None;
    }
    if prim::hypervisor_max_leaf() < 0x4000_0001
        || prim::cpuid(0x4000_0001, 0).0 & KVM_FEATURE_CLOCKSOURCE2 == 0
    {
        return None;
    }
    let va = PVCLOCK.0.get() as usize;
    prim::wrmsr(MSR_KVM_SYSTEM_TIME_NEW, v2p(va) | 1);
    let mut out = None;
    for _ in 0..16 {
        // The host updates the page concurrently: read the version before
        // and after the fields (odd = update in progress).
        let v1: u32 = pv_read(offset_of!(PvClock, version));
        let mul: u32 = pv_read(offset_of!(PvClock, tsc_to_system_mul));
        let shift: i8 = pv_read(offset_of!(PvClock, tsc_shift));
        let v2: u32 = pv_read(offset_of!(PvClock, version));
        if v1 == v2 && v1 & 1 == 0 && v1 != 0 {
            out = tsc::pvclock_hz(mul, shift);
            break;
        }
        core::hint::spin_loop();
    }
    prim::wrmsr(MSR_KVM_SYSTEM_TIME_NEW, 0);
    out
}

// ---- the facade ----

/// Counter frequency in Hz.
#[inline]
pub fn frequency() -> u64 {
    TSC_HZ.load(Ordering::Relaxed).max(1)
}

/// The TSC, ordered after earlier instructions.
#[inline]
pub fn now() -> u64 {
    prim::rdtsc_ordered()
}

pub fn ticks_to_ns(ticks: u64) -> u64 {
    tsc::ticks_to_ns(ticks, frequency())
}

pub fn ns_to_ticks(ns: u64) -> u64 {
    tsc::ns_to_ticks(ns, frequency())
}

/// Nanoseconds since `init`.
pub fn uptime_ns() -> u64 {
    ticks_to_ns(now().wrapping_sub(TSC_BASE.load(Ordering::Acquire)))
}

fn slot() -> &'static AtomicU64 {
    &DEADLINE[percpu::current().min(MAX_CPUS - 1)]
}

/// Arms this CPU's timer to fire when the TSC reaches `deadline` (at once
/// if it already has).
pub fn set_deadline(deadline: u64) {
    // A deadline of 0 means "disarmed" to the TSC-deadline MSR.
    let deadline = deadline.max(1);
    slot().store(deadline, Ordering::Relaxed);
    if USE_DEADLINE.load(Ordering::Relaxed) {
        prim::wrmsr(apic::MSR_TSC_DEADLINE, deadline);
    } else {
        let delta = deadline.saturating_sub(now());
        let count = tsc::lapic_count_for(delta, LAPIC_HZ.load(Ordering::Relaxed), frequency());
        apic::write(apic::REG_TIMER_INIT, count);
    }
}

/// The deadline last programmed on this CPU.
pub fn deadline() -> u64 {
    slot().load(Ordering::Relaxed)
}

/// Stops this CPU's timer.
pub fn disable() {
    if USE_DEADLINE.load(Ordering::Relaxed) {
        prim::wrmsr(apic::MSR_TSC_DEADLINE, 0);
    } else {
        apic::write(apic::REG_TIMER_INIT, 0);
    }
}

/// Programs and unmasks this CPU's LVT timer entry (vector `0x20`). In
/// fallback mode the first call measures the LAPIC timer against the TSC.
pub fn unmask_timer_lvt() {
    if USE_DEADLINE.load(Ordering::Relaxed) {
        apic::write(
            apic::REG_LVT_TIMER,
            apic::lvt_timer(vectors::TIMER, TimerMode::TscDeadline, false),
        );
        // Intel SDM 10.5.4.1: order the LVT write before the MSR write.
        prim::mfence();
        return;
    }
    apic::write(apic::REG_TIMER_DIV, apic::timer_divide(16));
    if LAPIC_HZ.load(Ordering::Relaxed) == 0 {
        calibrate_lapic_timer();
    }
    apic::write(
        apic::REG_LVT_TIMER,
        apic::lvt_timer(vectors::TIMER, TimerMode::OneShot, false),
    );
}

/// Measures the LAPIC timer's count rate (at divide-by-16) over ~10 ms of
/// TSC time, with the timer masked.
fn calibrate_lapic_timer() {
    apic::write(
        apic::REG_LVT_TIMER,
        apic::lvt_timer(vectors::TIMER, TimerMode::OneShot, true),
    );
    let span = tsc::ns_to_ticks(10_000_000, frequency());
    apic::write(apic::REG_TIMER_INIT, u32::MAX);
    let t0 = now();
    while now().wrapping_sub(t0) < span {
        core::hint::spin_loop();
    }
    let t1 = now();
    let left = apic::read(apic::REG_TIMER_CUR);
    apic::write(apic::REG_TIMER_INIT, 0);
    let counted = u64::from(u32::MAX - left);
    let hz = tsc::calibrate_hz(counted, t1.wrapping_sub(t0), frequency()).unwrap_or(1);
    LAPIC_HZ.store(hz, Ordering::Relaxed);
}

/// The finest-grained clock and its name (aarch64: the PMU cycle counter).
pub fn finest_clock() -> (fn() -> u64, &'static str) {
    (now, "tsc")
}
