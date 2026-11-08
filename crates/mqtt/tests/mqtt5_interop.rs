//! MQTT 5.0 interop: byte streams captured from real clients and a real
//! broker (Mosquitto 2.x clients and broker, paho-mqtt 2.x; see
//! `tests/fixtures/v5/README.md` and `scripts/mqtt5-capture.sh`) must decode
//! completely with `urmqtt_mqtt::v5`, every packet must re-encode to bytes
//! that decode to the same packet, and the packets carry what the client
//! was asked to send. The fuzz seeds of `mqtt5_packet` are decoded too.

use std::path::{Path, PathBuf};

use urmqtt_mqtt::QoS;
use urmqtt_mqtt::v5::*;

const LIMITS: Limits = Limits {
    base: urmqtt_mqtt::Limits {
        max_packet_size: 65536,
        max_topic_len: 256,
        max_topic_levels: 16,
        max_client_id_len: 64,
        max_topics_per_packet: 8,
    },
    max_user_properties: 16,
    max_subscription_identifiers: 8,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v5")
}

/// Every packet of a captured stream, each checked to round-trip.
fn packets(bytes: &[u8]) -> Vec<Packet<'_>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (p, n) = decode(rest, &LIMITS).unwrap_or_else(|e| panic!("{e:?} at {rest:02x?}"));
        let mut buf = vec![0u8; encoded_len(&p).unwrap()];
        let m = encode(&p, &mut buf).unwrap();
        assert!(m <= n, "re-encoding grew");
        assert_eq!(decode(&buf[..m], &LIMITS).unwrap().0, p);
        out.push(p);
        rest = &rest[n..];
    }
    out
}

fn read(name: &str) -> Vec<u8> {
    let path = fixtures().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_fixture_decodes_completely() {
    let mut n = 0;
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "bin") {
            let bytes = std::fs::read(&path).unwrap();
            assert!(!bytes.is_empty(), "{}", path.display());
            let ps = packets(&bytes);
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with(".c2s.bin") {
                assert!(
                    matches!(ps.first(), Some(Packet::Connect(_))),
                    "{name} starts with CONNECT"
                );
                assert_eq!(connect_protocol_level(&bytes), Ok(5), "{name}");
            } else {
                assert!(
                    matches!(ps.first(), Some(Packet::ConnAck(_))),
                    "{name} starts with CONNACK"
                );
            }
            n += 1;
        }
    }
    assert!(n >= 20, "fixtures found: {n}");
}

#[test]
fn fuzz_seeds_decode_completely() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/mqtt5_packet");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!packets(&bytes).is_empty());
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn mosquitto_publish_properties() {
    let bytes = read("pub-qos1-props.c2s.bin");
    let ps = packets(&bytes);
    let Some(Packet::Publish(p)) = ps.iter().find(|p| matches!(p, Packet::Publish(_))) else {
        panic!("{ps:?}")
    };
    assert_eq!(p.qos, QoS::AtLeastOnce);
    let props: Vec<_> = p.properties.iter().collect();
    for want in [
        Property::UserProperty("k", "v"),
        Property::UserProperty("k", "v2"),
        Property::ContentType("text/plain"),
        Property::PayloadFormatIndicator(1),
        Property::MessageExpiryInterval(30),
        Property::ResponseTopic("r/t"),
        Property::CorrelationData(b"abc"),
    ] {
        assert!(props.contains(&want), "{want:?} in {props:?}");
    }
    // The broker's side: CONNACK, then PUBACK for the publish.
    let s2c = read("pub-qos1-props.s2c.bin");
    let back = packets(&s2c);
    assert!(
        back.iter()
            .any(|q| matches!(q, Packet::PubAck(a) if Some(a.packet_id) == p.packet_id))
    );
}

#[test]
fn mosquitto_connect_properties() {
    let bytes = read("pub-connect-props.c2s.bin");
    let ps = packets(&bytes);
    let Some(Packet::Connect(c)) = ps.first() else {
        panic!()
    };
    assert_eq!(c.properties.session_expiry_interval(), Some(60));
    assert_eq!(c.properties.receive_maximum(), Some(10));
    assert_eq!(c.properties.maximum_packet_size(), Some(2000));
    assert_eq!(c.properties.topic_alias_maximum(), Some(5));
    assert_eq!(
        c.properties.user_properties().collect::<Vec<_>>(),
        [("a", "b")]
    );
}

#[test]
fn mosquitto_will_and_credentials() {
    let bytes = read("pub-will.c2s.bin");
    let ps = packets(&bytes);
    let Some(Packet::Connect(c)) = ps.first() else {
        panic!()
    };
    let w = c.will.expect("will");
    assert_eq!(
        (w.topic, w.payload, w.qos, w.retain),
        ("w", &b"bye"[..], QoS::AtLeastOnce, true)
    );
    assert_eq!(w.properties.will_delay_interval(), Some(5));
    assert!(w.properties.iter().any(|p| p == Property::ContentType("x")));
    let bytes = read("pub-userpass.c2s.bin");
    let ps = packets(&bytes);
    let Some(Packet::Connect(c)) = ps.first() else {
        panic!()
    };
    assert_eq!((c.username, c.password), (Some("user"), Some(&b"pass"[..])));
}

#[test]
fn mosquitto_qos2_flow() {
    let c2s = read("pub-qos2.c2s.bin");
    let s2c = read("pub-qos2.s2c.bin");
    let out = packets(&c2s);
    let back = packets(&s2c);
    assert!(
        out.iter()
            .any(|p| matches!(p, Packet::Publish(p) if p.qos == QoS::ExactlyOnce))
    );
    assert!(out.iter().any(|p| matches!(p, Packet::PubRel(_))));
    assert!(back.iter().any(|p| matches!(p, Packet::PubRec(_))));
    assert!(back.iter().any(|p| matches!(p, Packet::PubComp(_))));
}

#[test]
fn subscribe_options_and_identifier() {
    let c2s = read("sub-props.c2s.bin");
    let ps = packets(&c2s);
    let Some(Packet::Subscribe(s)) = ps.iter().find(|p| matches!(p, Packet::Subscribe(_))) else {
        panic!("{ps:?}")
    };
    assert_eq!(
        s.properties.subscription_identifiers().collect::<Vec<_>>(),
        [7]
    );
    assert!(s.topics.iter().any(|(_, o)| o.qos == QoS::AtLeastOnce));
    // The broker's PUBLISH to this subscriber carries the identifier.
    let s2c = read("sub-props.s2c.bin");
    let back = packets(&s2c);
    assert!(back.iter().any(|p| matches!(p, Packet::SubAck(_))));
    assert!(back.iter().any(|p| matches!(
        p,
        Packet::Publish(pb) if pb.properties.subscription_identifiers().any(|i| i == 7)
    )));
}

#[test]
fn unsubscribe_round() {
    let c2s = read("sub-unsub.c2s.bin");
    let s2c = read("sub-unsub.s2c.bin");
    assert!(
        packets(&c2s)
            .iter()
            .any(|p| matches!(p, Packet::Unsubscribe(_)))
    );
    assert!(
        packets(&s2c)
            .iter()
            .any(|p| matches!(p, Packet::UnsubAck(_)))
    );
}

#[test]
fn paho_session() {
    let c2s = read("paho-session.c2s.bin");
    let ps = packets(&c2s);
    let Some(Packet::Connect(c)) = ps.first() else {
        panic!()
    };
    assert!(c.properties.session_expiry_interval().is_some());
    assert!(ps.iter().any(|p| matches!(
        p,
        Packet::Subscribe(s) if s.topics.iter().any(|(_, o)| o.no_local && o.retain_as_published
            && o.retain_handling == RetainHandling::SendIfNew)
    )));
    assert!(ps.iter().any(|p| matches!(
        p,
        Packet::Disconnect(d) if d.reason == ReasonCode::DisconnectWithWillMessage
    )));
    for q in [QoS::AtMostOnce, QoS::AtLeastOnce, QoS::ExactlyOnce] {
        assert!(
            ps.iter()
                .any(|p| matches!(p, Packet::Publish(pb) if pb.qos == q)),
            "{q:?}"
        );
    }
    let s2c = read("paho-session.s2c.bin");
    packets(&s2c);
}
