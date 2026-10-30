//! The I/O APIC: redirection-entry encoding (pure, host-tested) and the
//! indirect register access on the kernel target.

#![allow(unsafe_code)]

/// Indirect registers.
pub const REG_ID: u32 = 0x00;
pub const REG_VERSION: u32 = 0x01;
/// Redirection table entry `n` occupies registers `0x10 + 2n` (low) and
/// `0x11 + 2n` (high).
pub const fn reg_redir_lo(pin: u32) -> u32 {
    0x10 + 2 * pin
}

pub const fn reg_redir_hi(pin: u32) -> u32 {
    0x11 + 2 * pin
}

/// Pin polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

/// Pin trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Edge,
    Level,
}

/// One redirection entry: fixed delivery, physical destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redirection {
    pub vector: u32,
    pub dest: u32,
    pub polarity: Polarity,
    pub trigger: Trigger,
    pub masked: bool,
}

impl Redirection {
    /// The 64-bit entry. Bits: vector 7:0, delivery mode 10:8 (fixed = 0),
    /// destination mode 11 (physical = 0), polarity 13 (1 = low), trigger 15
    /// (1 = level), mask 16, destination 63:56.
    pub const fn encode(&self) -> u64 {
        let mut v = (self.vector & 0xff) as u64;
        if matches!(self.polarity, Polarity::ActiveLow) {
            v |= 1 << 13;
        }
        if matches!(self.trigger, Trigger::Level) {
            v |= 1 << 15;
        }
        if self.masked {
            v |= 1 << 16;
        }
        v | ((self.dest as u64 & 0xff) << 56)
    }

    pub const fn decode(raw: u64) -> Self {
        Self {
            vector: (raw & 0xff) as u32,
            dest: (raw >> 56) as u32,
            polarity: if raw & (1 << 13) != 0 {
                Polarity::ActiveLow
            } else {
                Polarity::ActiveHigh
            },
            trigger: if raw & (1 << 15) != 0 {
                Trigger::Level
            } else {
                Trigger::Edge
            },
            masked: raw & (1 << 16) != 0,
        }
    }
}

/// The ISA default for a GSI with no interrupt source override: GSIs 0-15
/// are edge/active-high, PCI GSIs above are level/active-low.
pub const fn default_flags(gsi: u32) -> (Trigger, Polarity) {
    if gsi < 16 {
        (Trigger::Edge, Polarity::ActiveHigh)
    } else {
        (Trigger::Level, Polarity::ActiveLow)
    }
}

/// Number of redirection entries from the version register
/// (bits 23:16 hold the highest entry index).
pub const fn pin_count(version_reg: u32) -> u32 {
    ((version_reg >> 16) & 0xff) + 1
}

#[cfg(target_os = "none")]
pub use hw::*;

#[cfg(target_os = "none")]
mod hw {
    use super::*;
    use crate::prim;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// One mapped I/O APIC and the GSIs it serves.
    #[derive(Debug, Clone, Copy)]
    pub struct IoApic {
        /// Virtual address of its register window.
        pub mmio: usize,
        pub gsi_base: u32,
        pub pins: u32,
    }

    /// Serialises the select/window register pair across CPUs.
    static LOCK: AtomicBool = AtomicBool::new(false);

    fn with_lock<R>(f: impl FnOnce() -> R) -> R {
        let flags = prim::save_flags_cli();
        while LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let r = f();
        LOCK.store(false, Ordering::Release);
        prim::restore_flags(flags);
        r
    }

    impl IoApic {
        /// Reads the pin count from the chip at `mmio`.
        pub fn probe(mmio: usize, gsi_base: u32) -> Self {
            let mut io = Self {
                mmio,
                gsi_base,
                pins: 0,
            };
            io.pins = pin_count(io.read(REG_VERSION)).min(240);
            io
        }

        fn read(&self, reg: u32) -> u32 {
            with_lock(|| {
                prim::mmio_write32(self.mmio, reg);
                prim::mmio_read32(self.mmio + 0x10)
            })
        }

        fn write(&self, reg: u32, val: u32) {
            with_lock(|| {
                prim::mmio_write32(self.mmio, reg);
                prim::mmio_write32(self.mmio + 0x10, val);
            })
        }

        pub fn serves(&self, gsi: u32) -> bool {
            gsi >= self.gsi_base && gsi - self.gsi_base < self.pins
        }

        /// Writes the entry of the pin serving `gsi`. The high word goes
        /// first so a half-written entry never delivers to a stale
        /// destination.
        pub fn set(&self, gsi: u32, e: Redirection) {
            let pin = gsi - self.gsi_base;
            let raw = e.encode();
            self.write(reg_redir_hi(pin), (raw >> 32) as u32);
            self.write(reg_redir_lo(pin), raw as u32);
        }

        /// Masks every pin.
        pub fn mask_all(&self) {
            for pin in 0..self.pins {
                let lo = self.read(reg_redir_lo(pin));
                self.write(reg_redir_lo(pin), lo | (1 << 16));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers() {
        assert_eq!(reg_redir_lo(0), 0x10);
        assert_eq!(reg_redir_hi(0), 0x11);
        assert_eq!(reg_redir_lo(23), 0x3e);
        assert_eq!(reg_redir_hi(23), 0x3f);
        assert_eq!(pin_count(0x0017_0020), 24);
        assert_eq!(pin_count(0x00ff_0011), 256);
    }

    #[test]
    fn encodes_the_fields() {
        let e = Redirection {
            vector: 0x31,
            dest: 2,
            polarity: Polarity::ActiveHigh,
            trigger: Trigger::Edge,
            masked: false,
        };
        assert_eq!(e.encode(), (2u64 << 56) | 0x31);
        let lvl = Redirection {
            polarity: Polarity::ActiveLow,
            trigger: Trigger::Level,
            masked: true,
            ..e
        };
        assert_eq!(
            lvl.encode(),
            (2u64 << 56) | (1 << 16) | (1 << 15) | (1 << 13) | 0x31
        );
    }

    #[test]
    fn decode_is_the_inverse() {
        for (p, t, m) in [
            (Polarity::ActiveHigh, Trigger::Edge, false),
            (Polarity::ActiveLow, Trigger::Level, true),
            (Polarity::ActiveLow, Trigger::Edge, false),
            (Polarity::ActiveHigh, Trigger::Level, true),
        ] {
            let e = Redirection {
                vector: 0x3f,
                dest: 0xfe,
                polarity: p,
                trigger: t,
                masked: m,
            };
            assert_eq!(Redirection::decode(e.encode()), e);
        }
    }

    #[test]
    fn isa_and_pci_defaults() {
        assert_eq!(default_flags(1), (Trigger::Edge, Polarity::ActiveHigh));
        assert_eq!(default_flags(16), (Trigger::Level, Polarity::ActiveLow));
    }
}
