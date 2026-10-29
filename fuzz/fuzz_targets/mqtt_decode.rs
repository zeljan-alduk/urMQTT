//! Arbitrary bytes as an MQTT byte stream. The decoder must never panic,
//! and every packet it accepts must re-encode to bytes that decode to the
//! same packet (no lossy or ambiguous parsing).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_mqtt::{Limits, decode, encode, encoded_len};

const LIMITS: Limits = Limits {
    max_packet_size: 4096,
    max_topic_len: 256,
    max_topic_levels: 16,
    max_client_id_len: 128,
    max_topics_per_packet: 8,
};

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while let Ok((packet, used)) = decode(rest, &LIMITS) {
        let mut buf = vec![0u8; encoded_len(&packet)];
        let n = encode(&packet, &mut buf).expect("accepted packets must encode");
        let (again, used2) = decode(&buf[..n], &LIMITS).expect("re-encoded packet must decode");
        assert_eq!(packet, again);
        assert_eq!(used2, n);
        rest = &rest[used..];
    }
});
