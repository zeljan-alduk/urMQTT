//! The seeds of the `broker_input` fuzz target replay as regression tests,
//! and the QoS 2 seeds (ADR-271) are known to reach the flows they were
//! written for, not only to pass.

mod input_harness;

fn seed(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds/broker_input")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn every_seed_replays() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/broker_input");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).expect("seed directory") {
        input_harness::run(&std::fs::read(e.expect("entry").path()).expect("seed"));
        n += 1;
    }
    assert!(n > 0, "no seeds in {}", dir.display());
}

#[test]
fn the_qos2_seeds_reach_their_flows() {
    let st = input_harness::run(&seed("qos2_inbound_duplicates")).stats();
    assert_eq!((st.qos2_received, st.qos2_duplicates), (2, 2), "{st:?}");
    assert_eq!(st.qos2_completed, 1, "{st:?}");
    let st = input_harness::run(&seed("qos2_resume_after_drop")).stats();
    assert!(st.qos2_received >= 5 && st.qos2_duplicates >= 1, "{st:?}");
    assert!(st.qos2_completed >= 2, "{st:?}");
    let st = input_harness::run(&seed("qos2_will_and_retained")).stats();
    assert_eq!((st.wills_published, st.qos2_received), (1, 1), "{st:?}");
    assert!(st.retained >= 1 && st.qos2_completed >= 1, "{st:?}");
}

/// The MQTT 5.0 seeds (ADR-274), written by hand with
/// `scripts/mqtt5-seeds.py`, reach what they are about.
#[test]
fn the_mqtt5_seeds_reach_their_flows() {
    let st = input_harness::run(&seed("mqtt5_session_expiry")).stats();
    assert_eq!((st.online_v5, st.sessions_expired), (2, 1), "{st:?}");
    assert!(st.delivered >= 1, "{st:?}");
    let st = input_harness::run(&seed("mqtt5_will_delay_alias")).stats();
    assert_eq!(st.published, 3, "{st:?}");
    assert_eq!(st.disconnects_sent[0x14], 1, "0x94 unknown alias: {st:?}");
    let st = input_harness::run(&seed("mqtt5_mixed_versions")).stats();
    assert_eq!((st.online, st.online_v5), (2, 1), "{st:?}");
    // Twice each: the harness routes a few messages back in as if from
    // another shard (ADR-269).
    assert!(st.delivered >= 2, "{st:?}");
    assert_eq!(st.disconnects_sent[0x02], 1, "AUTH: {st:?}");
    let st = input_harness::run(&seed("mqtt5_flow_control")).stats();
    assert_eq!((st.qos2_received, st.qos2_inbound_full), (32, 1), "{st:?}");
    assert_eq!(st.disconnects_sent[0x13], 1, "0x93: {st:?}");
}
