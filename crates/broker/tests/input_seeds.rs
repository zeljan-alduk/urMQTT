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
