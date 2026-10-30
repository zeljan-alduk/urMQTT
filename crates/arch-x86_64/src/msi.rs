//! Message-signalled interrupts on x86 (pure logic): a message is a write
//! to the local APIC's address window (0xFEE0_0000 | dest << 12) with the
//! vector as data.

/// MSI address window base (Intel SDM vol. 3, 10.11).
const MSI_BASE: u64 = 0xfee0_0000;

/// First and last vector handed out to devices.
const FIRST_VECTOR: u32 = 0x40;
const LAST_VECTOR: u32 = 0xef;

/// The vectors not yet handed out. X1 keeps the aarch64 operations so the
/// kernel's call sites stay the same: the second argument of `from_typer`
/// is unused, and `compose` takes the vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    dest: u64,
    next: u32,
}

/// Unused on x86 (there is no frame to size); kept for the facade contract.
pub const TYPER: usize = 0;

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
        (MSI_BASE | (self.dest << 12), vector)
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
}
