//! Monotonic time and the per-CPU deadline timer: TSC and the local APIC
//! TSC-deadline timer (X4).

pub fn frequency() -> u64 {
    unimplemented_until!("X4 (time)")
}

pub fn now() -> u64 {
    unimplemented_until!("X4 (time)")
}

pub fn ticks_to_ns(_ticks: u64) -> u64 {
    unimplemented_until!("X4 (time)")
}

pub fn ns_to_ticks(_ns: u64) -> u64 {
    unimplemented_until!("X4 (time)")
}

pub fn uptime_ns() -> u64 {
    unimplemented_until!("X4 (time)")
}

pub fn set_deadline(_deadline: u64) {
    unimplemented_until!("X4 (time)")
}

pub fn deadline() -> u64 {
    unimplemented_until!("X4 (time)")
}

/// The finest-grained clock and its name (aarch64: the PMU cycle counter).
pub fn finest_clock() -> (fn() -> u64, &'static str) {
    (now, "tsc")
}
