//! The example edition's configuration keys (NOW-18, ADR-337), shared by its
//! kernel image (`src/main.rs`) and its packer (`src/config.rs`).
//!
//! The keys live in the TOML table `[ext.example]` and in the reserved tag
//! range `0xF000..=0xFFFE`; the open kernel and the open `urmqtt-config`
//! refuse a configuration that sets one.

#![no_std]

use urmqtt_cfg::ext::field;
use urmqtt_cfg::fields::{Field, Kind};

/// The value the driver writes to the edu device's liveness register (the
/// device answers with its bitwise inverse).
pub const EDU_CHECK: Field = field(
    0xF000,
    "ext.example.edu_check",
    Kind::UInt {
        bytes: 4,
        min: 0,
        max: u32::MAX as u64,
        default: 0x5a5a_5a5a,
    },
    "The value the example driver writes to the edu device's liveness register.",
    2,
);

/// Whether the example driver binds the edu device.
pub const EDU_MODE: Field = field(
    0xF001,
    "ext.example.edu",
    Kind::Enum {
        variants: &["auto", "off"],
        default: 0,
    },
    "\"auto\": drive an edu device when there is one; \"off\": leave it alone.",
    2,
);

/// Every key of the edition, in tag order.
pub const FIELDS: &[Field] = &[EDU_CHECK, EDU_MODE];

const _: () = assert!(urmqtt_cfg::ext::check(FIELDS).is_ok());

#[cfg(test)]
mod tests {
    #[test]
    fn the_table_is_valid() {
        assert_eq!(urmqtt_cfg::ext::check(super::FIELDS), Ok(()));
    }
}
