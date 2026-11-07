//! H5: stateful ACL invariants over random operation sequences, checked by
//! the independent oracle in `acl_oracle/` (also driven by the cargo-fuzz
//! target `broker_acl`). Deterministic: a fixed seed, so `make check` does
//! the same work every run. The fuzz seeds are replayed as regressions.

mod acl_oracle;

use acl_oracle::{Op, decode_ops, run};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use urmqtt_mqtt::QoS;

proptest! {
    #![proptest_config(Config {
        cases: 300,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x4835_ac10_0001),
        failure_persistence: None,
        ..Config::default()
    })]

    /// Random bytes decode to operation sequences (curated and generated
    /// topics, spoofed ids, wills, takeovers, garbage).
    #[test]
    fn random_sequences(data in proptest::collection::vec(any::<u8>(), 0..1200)) {
        run(&decode_ops(&data));
    }

    /// The same, biased to what exercises the ACL: mostly connect,
    /// subscribe and publish, with the other operations mixed in.
    #[test]
    fn biased_sequences(
        ops in proptest::collection::vec(
            (
                prop_oneof![
                    3 => Just(0u8), 4 => Just(1u8), 4 => Just(2u8),
                    1 => Just(3u8), 1 => Just(4u8), 1 => Just(6u8), 1 => Just(5u8),
                ],
                any::<[u8; 5]>(),
            ),
            0..200,
        )
    ) {
        let data: Vec<u8> = ops
            .into_iter()
            .flat_map(|(o, rest)| std::iter::once(o).chain(rest))
            .collect();
        run(&decode_ops(&data));
    }
}

fn connect(slot: usize, who: usize, clean: bool) -> Op {
    Op::Connect {
        slot,
        who,
        claim: who,
        clean,
        will: None,
    }
}

fn publish(slot: usize, topic: &str, qos: QoS, retain: bool) -> Op {
    Op::Publish {
        slot,
        topic: topic.into(),
        qos,
        retain,
        empty: false,
        extra: 4,
    }
}

fn subscribe(slot: usize, filter: &str) -> Op {
    Op::Subscribe {
        slot,
        filters: vec![(filter.into(), QoS::AtLeastOnce)],
    }
}

/// Indices into `acl_oracle::WHO`.
const D1: usize = 0;
const D2: usize = 1;
const SVC: usize = 2;
const EXP: usize = 3;
const BOOT_D1: usize = 4;
const BOOT_SVC: usize = 5;

/// A directed scenario touching every rule once, so the oracle's own
/// checks are known to run (not only to pass).
#[test]
fn directed_attacks() {
    let q = QoS::AtLeastOnce;
    let ops = vec![
        connect(0, D1, true),
        connect(1, D2, true),
        connect(2, SVC, true),
        connect(3, EXP, true),
        subscribe(0, "devices/d1/cmd/#"),
        subscribe(0, "devices/+/cmd/#"),
        subscribe(0, "#"),
        subscribe(0, "$urmqtt/#"),
        subscribe(1, "devices/d1/cmd/#"),
        subscribe(1, "devices/d2/cmd/#"),
        subscribe(2, "devices/+/telemetry/#"),
        subscribe(3, "fleet/#"),
        // d1 publishes into d2's space and into the control namespace.
        publish(0, "devices/d2/cmd/reboot", q, true),
        publish(0, "$urmqtt/control", q, false),
        publish(0, "devices/d1/state", q, true),
        // The service commands both; exp (no control right) tries control.
        publish(2, "devices/d1/cmd/x", q, false),
        publish(2, "devices/d2/cmd/x", q, true),
        publish(3, "$urmqtt/control", q, false),
        publish(2, "$urmqtt/control", q, false),
        publish(2, "$urmqtt/other", q, false),
        // Later subscribers see retained messages only inside their rights.
        subscribe(1, "devices/d2/cmd/#"),
        Op::Ack { slot: 0 },
        Op::Ack { slot: 1 },
        Op::Drop { slot: 0 },
    ];
    let h = run(&ops);
    let st = h.b.stats();
    assert_eq!(st.dropped_acl, 1, "{st:?}");
    assert_eq!(st.control_received, 1, "{st:?}");
    assert!(st.dropped_control >= 2, "{st:?}");
}

#[test]
fn bootstrap_identities_get_no_operational_rights() {
    let q = QoS::AtLeastOnce;
    let ops = vec![
        connect(0, BOOT_SVC, true),
        connect(1, BOOT_D1, true),
        connect(2, D1, true),
        // A bootstrap certificate named like the control service.
        publish(0, "$urmqtt/control", q, false),
        publish(0, "devices/d1/cmd/x", q, false),
        subscribe(0, "devices/#"),
        subscribe(0, "provision/svc/#"),
        subscribe(1, "provision/d1/#"),
        subscribe(2, "devices/d1/cmd/#"),
        publish(0, "provision/svc/csr", q, true),
        publish(1, "provision/d1/csr", q, false),
        publish(1, "devices/d1/cmd/x", q, true),
        // Identity spoofing at CONNECT.
        Op::Connect {
            slot: 3,
            who: D2,
            claim: D1,
            clean: true,
            will: None,
        },
        // A will outside the owner's rights is refused.
        Op::Connect {
            slot: 3,
            who: D2,
            claim: D2,
            clean: true,
            will: Some(("devices/d1/state".into(), true, q)),
        },
        Op::Connect {
            slot: 3,
            who: D2,
            claim: D2,
            clean: true,
            will: Some(("$urmqtt/control".into(), false, q)),
        },
    ];
    let h = run(&ops);
    assert_eq!(h.b.stats().control_received, 0);
}

/// Every seed of the fuzz target is a regression test.
#[test]
fn fuzz_seeds_replay() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/broker_acl");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).expect("seed directory") {
        let data = std::fs::read(e.expect("entry").path()).expect("seed");
        run(&decode_ops(&data));
        n += 1;
    }
    assert!(n > 0, "no seeds in {}", dir.display());
}
