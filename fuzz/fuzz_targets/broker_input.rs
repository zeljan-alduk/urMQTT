//! The broker behind the codec (M9, M15, M16): sessions, subscriptions
//! (device-scoped and ordinary), retained messages, QoS 1 and 2 (ADR-271),
//! wills, takeovers, plaintext and WebSocket sessions (ADR-272) and limits,
//! driven by arbitrary bytes on several connections with time passing. It
//! must never panic, and output must stay bounded. The harness is
//! `crates/broker/tests/input_harness/`, which `cargo test -p urmqtt-broker`
//! also drives over the seeds.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/broker/tests/input_harness/mod.rs"]
mod input_harness;

fuzz_target!(|data: &[u8]| {
    input_harness::run(data);
});
