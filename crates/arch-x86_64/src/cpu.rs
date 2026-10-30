//! The executing CPU (X2).

#![allow(unsafe_code)]

pub fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Waits for an interrupt (`hlt`; X2).
pub fn wait_for_interrupt() {
    unimplemented_until!("X2 (cpu)")
}

/// Enables interrupts (`sti`).
///
/// # Safety
/// The IDT and the interrupt controller must be ready.
pub unsafe fn enable_interrupts() {
    unimplemented_until!("X2 (cpu)")
}

/// Disables interrupts and returns the previous RFLAGS.
pub fn irq_save() -> u64 {
    unimplemented_until!("X2 (cpu)")
}

pub fn irq_restore(_flags: u64) {
    unimplemented_until!("X2 (cpu)")
}

/// The current privilege level (CS.RPL).
pub fn privilege_level() -> u8 {
    unimplemented_until!("X2 (cpu)")
}

/// Programs the return-address signing key (aarch64 PAC). x86 has none.
///
/// # Safety
/// Never called on x86.
pub unsafe fn set_return_address_key(_lo: u64, _hi: u64) {}

/// Where [`switch_to`] continues (a never-returning entry).
pub type Continuation = extern "C" fn(u64) -> !;

/// Switches to a fresh stack and calls `entry(arg)`.
///
/// # Safety
/// `stack_top` must be a valid, mapped stack.
pub unsafe fn switch_to(
    _stack_top: u64,
    _arg: u64,
    _unused: u64,
    _entry: Continuation,
    _pac: bool,
) -> ! {
    unimplemented_until!("X2 (cpu)")
}
