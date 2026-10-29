//! Message-signalled interrupts through a GICv2m frame: an MSI is a write
//! of an SPI number to the frame's SETSPI_NS register (pure logic; the
//! kernel maps the frame and programs the device's MSI-X table).

/// Offset of MSI_TYPER in the frame.
pub const TYPER: usize = 0x008;
const SETSPI_NS: u64 = 0x040;

/// A GICv2m frame and the SPIs not yet handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pa: u64,
    next_spi: u32,
    end_spi: u32,
}

impl Frame {
    /// The frame at physical `pa` whose MSI_TYPER reads `typer`.
    pub const fn from_typer(pa: u64, typer: u32) -> Self {
        let base = (typer >> 16) & 0x3ff;
        let count = typer & 0x3ff;
        Self {
            pa,
            next_spi: base,
            end_spi: base + count,
        }
    }

    /// The SPIs this frame signals, as `start..end`.
    pub const fn spis(&self) -> (u32, u32) {
        (self.next_spi, self.end_spi)
    }

    /// Takes the next free SPI, or `None` when all are in use.
    pub fn alloc(&mut self) -> Option<u32> {
        if self.next_spi >= self.end_spi {
            return None;
        }
        let spi = self.next_spi;
        self.next_spi += 1;
        Some(spi)
    }

    /// The (address, data) pair a device writes to raise `spi`. Every SPI
    /// is routed by the distributor, so the target CPU is not encoded.
    pub const fn compose(&self, spi: u32) -> (u64, u32) {
        (self.pa + SETSPI_NS, spi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typer_range_and_allocation() {
        // QEMU virt: 64 SPIs from 80.
        let mut f = Frame::from_typer(0x0802_0000, (80 << 16) | 64);
        assert_eq!(f.spis(), (80, 144));
        assert_eq!(f.alloc(), Some(80));
        assert_eq!(f.alloc(), Some(81));
        assert_eq!(f.compose(81), (0x0802_0040, 81));
    }

    #[test]
    fn exhausted_frame_allocates_nothing() {
        let mut f = Frame::from_typer(0, (32 << 16) | 1);
        assert_eq!(f.alloc(), Some(32));
        assert_eq!(f.alloc(), None);
        assert_eq!(Frame::from_typer(0, 0).alloc(), None);
    }
}
