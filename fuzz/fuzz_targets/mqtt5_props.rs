//! An MQTT 5.0 property block for one of the 14 contexts (the first byte
//! picks it). Validation must never panic; an accepted block must be
//! consumed exactly (the properties' encoded lengths add up to the block),
//! and the same properties rebuilt as a list and encoded in a packet of
//! that context must decode back to the same properties (ADR-273).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_mqtt::QoS;
use urmqtt_mqtt::v5::{
    Ack, Auth, ConnAck, Connect, Disconnect, Limits, Packet, Properties, Property, PropertyContext,
    Publish, ReasonCode, SubAck, Subscribe, SubscribeTopics, SubscriptionOptions, UnsubAck,
    Unsubscribe, UnsubscribeTopics, Will, decode, encode, encoded_len, validate_properties,
};

const LIMITS: Limits = Limits {
    base: urmqtt_mqtt::Limits::PROTOCOL_MAX,
    max_user_properties: 16,
    max_subscription_identifiers: 8,
};

static TOPICS: [(&str, SubscriptionOptions); 1] =
    [("a", SubscriptionOptions::qos(QoS::AtMostOnce))];

fn packet<'a>(ctx: PropertyContext, p: Properties<'a>) -> Packet<'a> {
    let ack = Ack {
        packet_id: 1,
        reason: ReasonCode::Success,
        properties: p,
    };
    match ctx {
        PropertyContext::Connect | PropertyContext::Will => {
            let will = Will {
                properties: p,
                topic: "w",
                payload: b"",
                qos: QoS::AtMostOnce,
                retain: false,
            };
            let (props, will) = if ctx == PropertyContext::Will {
                (Properties::EMPTY, Some(will))
            } else {
                (p, None)
            };
            Packet::Connect(Connect {
                clean_start: true,
                keep_alive: 0,
                properties: props,
                client_id: "c",
                will,
                username: None,
                password: None,
            })
        }
        PropertyContext::ConnAck => Packet::ConnAck(ConnAck {
            session_present: false,
            reason: ReasonCode::Success,
            properties: p,
        }),
        PropertyContext::Publish => Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "t",
            packet_id: None,
            properties: p,
            payload: b"",
        }),
        PropertyContext::PubAck => Packet::PubAck(ack),
        PropertyContext::PubRec => Packet::PubRec(ack),
        PropertyContext::PubRel => Packet::PubRel(ack),
        PropertyContext::PubComp => Packet::PubComp(ack),
        PropertyContext::Subscribe => Packet::Subscribe(Subscribe {
            packet_id: 1,
            properties: p,
            topics: SubscribeTopics::List(&TOPICS),
        }),
        PropertyContext::SubAck => Packet::SubAck(SubAck {
            packet_id: 1,
            properties: p,
            reason_codes: &[0],
        }),
        PropertyContext::Unsubscribe => Packet::Unsubscribe(Unsubscribe {
            packet_id: 1,
            properties: p,
            topics: UnsubscribeTopics::List(&["a"]),
        }),
        PropertyContext::UnsubAck => Packet::UnsubAck(UnsubAck {
            packet_id: 1,
            properties: p,
            reason_codes: &[0],
        }),
        PropertyContext::Disconnect => Packet::Disconnect(Disconnect {
            reason: ReasonCode::Success,
            properties: p,
        }),
        PropertyContext::Auth => Packet::Auth(Auth {
            reason: ReasonCode::ContinueAuthentication,
            properties: p,
        }),
    }
}

fn props_of<'a>(ctx: PropertyContext, p: &Packet<'a>) -> Properties<'a> {
    match (ctx, p) {
        (PropertyContext::Will, Packet::Connect(c)) => c.will.map(|w| w.properties),
        (_, Packet::Connect(c)) => Some(c.properties),
        (_, Packet::ConnAck(a)) => Some(a.properties),
        (_, Packet::Publish(a)) => Some(a.properties),
        (_, Packet::PubAck(a) | Packet::PubRec(a) | Packet::PubRel(a) | Packet::PubComp(a)) => {
            Some(a.properties)
        }
        (_, Packet::Subscribe(a)) => Some(a.properties),
        (_, Packet::SubAck(a)) => Some(a.properties),
        (_, Packet::Unsubscribe(a)) => Some(a.properties),
        (_, Packet::UnsubAck(a)) => Some(a.properties),
        (_, Packet::Disconnect(a)) => Some(a.properties),
        (_, Packet::Auth(a)) => Some(a.properties),
        _ => None,
    }
    .expect("same packet type")
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, raw)) = data.split_first() else {
        return;
    };
    let ctx = PropertyContext::ALL[usize::from(sel) % PropertyContext::ALL.len()];
    if validate_properties(raw, ctx, &LIMITS).is_err() {
        return;
    }
    let block = Properties::Raw(raw);
    let list: Vec<Property<'_>> = block.iter().collect();
    assert_eq!(
        list.iter().map(Property::encoded_len).sum::<usize>(),
        raw.len()
    );
    assert_eq!(block.encoded_len(), raw.len());
    // An AUTH packet needs an Authentication Method; a block without one is
    // still a valid block for the context, just not a whole AUTH packet.
    if ctx == PropertyContext::Auth && block.authentication_method().is_none() {
        return;
    }
    for p in [packet(ctx, block), packet(ctx, Properties::List(&list))] {
        let mut out = vec![0u8; encoded_len(&p).expect("length")];
        let n = encode(&p, &mut out).expect("a valid block encodes");
        let (q, _) = decode(&out[..n], &LIMITS).expect("and decodes");
        assert_eq!(props_of(ctx, &q), block);
        // The list encodes to exactly the received bytes (one encoding per
        // property: minimal varints, no padding).
        let Properties::Raw(back) = props_of(ctx, &q) else {
            unreachable!()
        };
        assert_eq!(back, raw);
    }
});
