//! The interrupt vector map (pure; ADR-045).
//!
//! ```text
//! 0x00-0x1f  CPU exceptions
//! 0x20       local APIC timer
//! 0x21-0x3f  I/O APIC lines: vector = 0x21 + GSI (GSI 0..=30)
//! 0x40-0xdf  MSI / MSI-X, handed out by `msi::Frame`
//! 0xe0-0xef  the remapped 8259 PIC (kept masked; a spurious IRQ7/15 lands here)
//! 0xf1-0xf3  IPIs: ping, pong, wake (the facade's `ipi` constants)
//! 0xfe       local APIC error
//! 0xff       local APIC spurious
//! ```
//!
//! Vectors are per CPU: the same number on two CPUs is two interrupts, so
//! one global handler table indexed by vector works for all of them.

pub const TIMER: u32 = 0x20;
pub const IOAPIC_FIRST: u32 = 0x21;
pub const IOAPIC_LAST: u32 = 0x3f;
pub const MSI_FIRST: u32 = 0x40;
pub const MSI_LAST: u32 = 0xdf;
pub const PIC_MASTER_BASE: u32 = 0xe0;
pub const PIC_SLAVE_BASE: u32 = 0xe8;
pub const IPI_PING: u32 = 0xf1;
pub const IPI_PONG: u32 = 0xf2;
pub const IPI_WAKE: u32 = 0xf3;
pub const ERROR: u32 = 0xfe;
pub const SPURIOUS: u32 = 0xff;

/// The vector for I/O APIC global system interrupt `gsi`, if it fits the
/// range reserved for them.
pub const fn gsi_vector(gsi: u32) -> Option<u32> {
    if gsi > IOAPIC_LAST - IOAPIC_FIRST {
        None
    } else {
        Some(IOAPIC_FIRST + gsi)
    }
}

/// The GSI an I/O APIC vector stands for.
pub const fn vector_gsi(vector: u32) -> Option<u32> {
    if vector >= IOAPIC_FIRST && vector <= IOAPIC_LAST {
        Some(vector - IOAPIC_FIRST)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gsi_round_trip_and_bounds() {
        assert_eq!(gsi_vector(0), Some(0x21));
        assert_eq!(gsi_vector(30), Some(0x3f));
        assert_eq!(gsi_vector(31), None);
        assert_eq!(vector_gsi(0x21), Some(0));
        assert_eq!(vector_gsi(0x3f), Some(30));
        assert_eq!(vector_gsi(TIMER), None);
        assert_eq!(vector_gsi(0x40), None);
        for g in 0..=30 {
            assert_eq!(vector_gsi(gsi_vector(g).unwrap()), Some(g));
        }
    }

    #[test]
    fn ranges_do_not_overlap() {
        let r = [
            (TIMER, TIMER),
            (IOAPIC_FIRST, IOAPIC_LAST),
            (MSI_FIRST, MSI_LAST),
            (PIC_MASTER_BASE, PIC_SLAVE_BASE + 7),
            (IPI_PING, IPI_WAKE),
            (ERROR, ERROR),
            (SPURIOUS, SPURIOUS),
        ];
        for (i, a) in r.iter().enumerate() {
            assert!(a.0 >= 0x20 && a.0 <= a.1);
            for b in &r[i + 1..] {
                assert!(a.1 < b.0, "{a:x?} overlaps {b:x?}");
            }
        }
    }
}
