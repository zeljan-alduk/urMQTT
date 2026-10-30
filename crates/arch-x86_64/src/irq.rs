//! The interrupt controller: the local APIC and the I/O APIC (X4).

#![allow(unsafe_code)]

#[derive(Debug, Clone, Copy)]
pub enum Error {
    NoController,
}

/// The platform's interrupt controller.
#[derive(Clone, Copy)]
pub struct Controller(());

/// A CPU's handle on its local APIC.
#[derive(Debug, Clone, Copy)]
pub struct Local(());

/// Unused on x86; kept for the facade contract.
pub const GICV2_MAX_CPUS: usize = 8;

/// An acknowledged interrupt.
#[derive(Debug, Clone, Copy)]
pub struct Ack {
    pub intid: u32,
}

impl Ack {
    pub fn is_none(&self) -> bool {
        self.intid >= 256
    }

    pub fn is_spurious(&self) -> bool {
        self.intid == 0xff
    }
}

impl Controller {
    /// GICv3 and GICv2 do not exist on x86; kept so the kernel's interrupt
    /// setup compiles until X4/X6 give it an APIC path.
    ///
    /// # Safety
    /// Never called on x86.
    pub unsafe fn v3(_gicd: usize, _gicr: usize, _len: usize) -> Result<Self, Error> {
        Err(Error::NoController)
    }

    /// # Safety
    /// Never called on x86.
    pub unsafe fn v2(_gicd: usize, _gicc: usize) -> Self {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn is_v2(&self) -> bool {
        false
    }

    pub fn lines(&self) -> u32 {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn max_cpus(&self) -> usize {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn init_local(&self) -> Result<Local, Error> {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn enable_private(&self, _local: Option<&Local>, _intid: u32) {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn enable_spi(&self, _intid: u32, _hw_id: u64, _local: Option<&Local>) {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn send_ipi(&self, _intid: u32, _hw_id: u64, _local: Option<&Local>) {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn ack(&self) -> Ack {
        unimplemented_until!("X4 (APIC)")
    }

    pub fn eoi(&self, _ack: Ack) {
        unimplemented_until!("X4 (APIC)")
    }
}
