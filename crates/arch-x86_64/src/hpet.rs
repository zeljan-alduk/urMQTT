//! The HPET main counter as a calibration reference (X6 supplies the base
//! address from the ACPI HPET table).

#![allow(unsafe_code)]

#[cfg(target_os = "none")]
const REG_CAPS: usize = 0x00;
#[cfg(target_os = "none")]
const REG_CONFIG: usize = 0x10;
#[cfg(target_os = "none")]
const REG_COUNTER: usize = 0xf0;

/// Counter frequency from the capabilities register's period (bits 63:32,
/// femtoseconds per tick). The spec caps the period at 100 ns and forbids 0.
pub const fn frequency_from_caps(caps: u64) -> Option<u64> {
    let period_fs = caps >> 32;
    if period_fs == 0 || period_fs > 100_000_000 {
        None
    } else {
        Some(1_000_000_000_000_000 / period_fs)
    }
}

/// True if the counter is 64 bits wide (COUNT_SIZE_CAP, bit 13).
pub const fn is_64bit(caps: u64) -> bool {
    caps & (1 << 13) != 0
}

#[cfg(target_os = "none")]
pub use hw::*;

#[cfg(target_os = "none")]
mod hw {
    use super::*;
    use crate::prim;

    /// A mapped HPET.
    #[derive(Debug, Clone, Copy)]
    pub struct Hpet {
        mmio: usize,
        pub hz: u64,
        pub bits: u32,
    }

    impl Hpet {
        /// Starts the main counter and reads its parameters. `None` if the
        /// capabilities register is nonsense (all ones: no device there).
        pub fn start(mmio: usize) -> Option<Self> {
            let caps = prim::mmio_read64(mmio + REG_CAPS);
            let hz = frequency_from_caps(caps)?;
            let cfg = prim::mmio_read64(mmio + REG_CONFIG);
            prim::mmio_write64(mmio + REG_CONFIG, cfg | 1);
            Some(Self {
                mmio,
                hz,
                bits: if is_64bit(caps) { 64 } else { 32 },
            })
        }

        pub fn counter(&self) -> u64 {
            let v = prim::mmio_read64(self.mmio + REG_COUNTER);
            if self.bits == 64 { v } else { v & 0xffff_ffff }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_from_period() {
        // QEMU: 10 ns period (100 MHz).
        assert_eq!(frequency_from_caps(10_000_000u64 << 32), Some(100_000_000));
        // The common 69841279 fs = 14.31818 MHz.
        let hz = frequency_from_caps(69_841_279u64 << 32).unwrap();
        assert!(hz.abs_diff(14_318_180) < 5, "{hz}");
        assert_eq!(frequency_from_caps(0), None);
        assert_eq!(frequency_from_caps(u64::MAX), None);
    }

    #[test]
    fn counter_width() {
        assert!(is_64bit(1 << 13));
        assert!(!is_64bit(0));
    }
}
