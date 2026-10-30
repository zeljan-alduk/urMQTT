//! ACPI PM1 control register encodings (pure, host-tested).

/// The S5 (soft-off) request for `PM1x_CNT`: `SLP_TYP` in bits 12:10 and
/// `SLP_EN` (bit 13). Only three bits of `slp_typ` exist.
pub const fn sleep_value(slp_typ: u8) -> u16 {
    ((slp_typ as u16 & 7) << 10) | (1 << 13)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s5_request_encoding() {
        // QEMU's \_S5 is 0/0: SLP_EN alone, the 0x2000 the QEMU fallback
        // writes to the same register.
        assert_eq!(sleep_value(0), 0x2000);
        assert_eq!(sleep_value(5), 0x3400);
        assert_eq!(sleep_value(7), 0x3c00);
        assert_eq!(sleep_value(8), 0x2000);
    }
}
