//! Stateful broker fuzzing with ACL invariants (H5): the input is a
//! structured sequence of operations (connect, publish, subscribe, ack,
//! drop, tick, garbage) from several identities (two devices, the control
//! service, a plain service, bootstrap certificates), and an oracle written
//! apart from the broker's ACL code checks after every step that no device
//! receives another's topics, no publish is accepted outside its rights,
//! `$urmqtt/` is closed to everyone but the control identity, and the
//! retained and in-flight state stays within its limits. The model is
//! `crates/broker/tests/acl_oracle/`, which `cargo test -p urmqtt-broker`
//! also drives, so a crash here replays there.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/broker/tests/acl_oracle/mod.rs"]
mod acl_oracle;

fuzz_target!(|data: &[u8]| {
    acl_oracle::run(&acl_oracle::decode_ops(data));
});
