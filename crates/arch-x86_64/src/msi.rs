//! Message-signalled interrupts on x86 (pure logic): a message is a write
//! to the local APIC's address window with the vector as data.
//!
//! Address (Intel SDM vol. 3, 11.11.1): bits 31:20 = 0xFEE, destination ID
//! in 19:12, redirection hint (RH) bit 3, destination mode (DM) bit 2.
//! Data: vector 7:0, delivery mode 10:8, trigger mode bit 15 (0 = edge).
//! The message is composed for fixed delivery, physical destination mode,
//! no redirection hint, edge triggered: exactly one CPU, one pulse per
//! message. The destination field is 8 bits wide, so APIC IDs above 0xfe
//! are unreachable without interrupt remapping (see [`Frame::reachable`]).

/// MSI address window base.
const MSI_BASE: u64 = 0xfee0_0000;

/// First and last vector handed out to devices (see `vectors.rs`).
const FIRST_VECTOR: u32 = crate::vectors::MSI_FIRST;
const LAST_VECTOR: u32 = crate::vectors::MSI_LAST;

/// The vectors not yet handed out. The second argument of `from_typer` is
/// unused (it sizes a GIC frame on aarch64), and `compose` takes the vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    dest: u64,
    next: u32,
}

/// Unused on x86 (there is no frame to size); kept for the facade contract.
pub const TYPER: usize = 0;

/// The (address, data) pair for `vector` aimed at APIC ID `dest`. Only the
/// low 8 bits of `dest` are encoded.
pub const fn message(dest: u64, vector: u32) -> (u64, u32) {
    let addr = MSI_BASE | ((dest & 0xff) << 12); // RH = 0, DM = 0 (physical)
    let data = vector & 0xff; // fixed delivery (000), edge (bit 15 = 0)
    (addr, data)
}

impl Frame {
    pub const fn from_typer(dest_apic_id: u64, _typer: u32) -> Self {
        Self {
            dest: dest_apic_id,
            next: FIRST_VECTOR,
        }
    }

    /// The vectors this source can use, as `start..end`.
    pub const fn spis(&self) -> (u32, u32) {
        (FIRST_VECTOR, LAST_VECTOR + 1)
    }

    pub fn alloc(&mut self) -> Option<u32> {
        if self.next > LAST_VECTOR {
            return None;
        }
        let v = self.next;
        self.next += 1;
        Some(v)
    }

    /// The (address, data) pair a device writes to raise `vector`.
    pub const fn compose(&self, vector: u32) -> (u64, u32) {
        message(self.dest, vector)
    }

    /// True if the destination fits the 8-bit MSI destination field.
    pub const fn reachable(&self) -> bool {
        self.dest <= 0xfe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_address_and_vector() {
        let mut f = Frame::from_typer(3, 0);
        let v = f.alloc().unwrap();
        assert_eq!(v, 0x40);
        assert_eq!(f.compose(v), (0xfee0_3000, 0x40));
    }

    #[test]
    fn mode_bits_are_clear() {
        let (a, d) = message(0xfe, 0xdf);
        assert_eq!(a, 0xfeef_e000);
        assert_eq!(a & 0b1100, 0, "RH and DM must be clear");
        assert_eq!(d & !0xff, 0, "fixed delivery, edge");
        // A destination above 8 bits is truncated, never spilling into 31:20.
        assert_eq!(message(0x1ff, 0x40).0 >> 20, 0xfee);
        assert!(!Frame::from_typer(0x100, 0).reachable());
        assert!(Frame::from_typer(0xfe, 0).reachable());
    }

    #[test]
    fn allocation_stops_at_the_msi_range() {
        let mut f = Frame::from_typer(0, 0);
        let mut n = 0;
        let mut last = 0;
        while let Some(v) = f.alloc() {
            n += 1;
            last = v;
        }
        assert_eq!(last, 0xdf);
        assert_eq!(n, 0xdf - 0x40 + 1);
        assert_eq!(f.spis(), (0x40, 0xe0));
    }
}
