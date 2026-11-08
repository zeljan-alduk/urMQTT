//! Arbitrary bytes as an MQTT 5.0 byte stream (ADR-273). The decoder must
//! never panic; every packet it accepts must re-encode (in at most the
//! bytes it came in: the encoder writes the shortest form) to bytes that
//! decode to the same packet; every prefix of an accepted packet asks for
//! more; and a refusal depends only on the packet's own bytes (the same
//! error whatever follows it).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_mqtt::v5::{Error, Limits, decode, encode, encoded_len};

const LIMITS: Limits = Limits {
    base: urmqtt_mqtt::Limits {
        max_packet_size: 4096,
        max_topic_len: 256,
        max_topic_levels: 16,
        max_client_id_len: 128,
        max_topics_per_packet: 8,
    },
    max_user_properties: 8,
    max_subscription_identifiers: 4,
};

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    loop {
        match decode(rest, &LIMITS) {
            Ok((packet, used)) => {
                let len = encoded_len(&packet).expect("accepted packets have a length");
                assert!(len <= used, "re-encoding grew: {len} > {used}");
                let mut buf = vec![0u8; len];
                let n = encode(&packet, &mut buf).expect("accepted packets must encode");
                assert_eq!(n, len);
                let (again, used2) =
                    decode(&buf[..n], &LIMITS).expect("re-encoded packet must decode");
                assert_eq!(packet, again);
                assert_eq!(used2, n);
                assert!(matches!(
                    decode(&rest[..used - 1], &LIMITS),
                    Err(Error::Incomplete(k)) if k > used - 1
                ));
                rest = &rest[used..];
            }
            Err(Error::Incomplete(_)) => break,
            Err(e) => {
                let mut longer = rest.to_vec();
                longer.extend_from_slice(&[0xff; 8]);
                assert_eq!(decode(&longer, &LIMITS).map(|_| ()), Err(e));
                break;
            }
        }
    }
});
