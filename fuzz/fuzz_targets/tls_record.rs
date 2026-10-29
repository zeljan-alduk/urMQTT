//! The in-house TLS 1.3 record layer (M10, M16) behind every established
//! connection. Arbitrary bytes as records must be rejected without a
//! panic, and records sealed by the peer must open to exactly what was sent
//! unless a byte was changed on the way, in which case they must fail.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_tls::record::{Opened, RecordLayer, Suite, record_len};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let suite = if first & 1 == 0 {
        Suite::Aes128Gcm
    } else {
        Suite::ChaCha20Poly1305
    };
    let (a, b) = ([0x11; 32], [0x22; 32]);
    let (Some(mut server), Some(mut client)) = (
        RecordLayer::new(suite, a, 0, b, 0),
        RecordLayer::new(suite, b, 0, a, 0),
    ) else {
        return;
    };
    let mut out = Vec::new();
    for chunk in rest.chunks(97) {
        let Some((&op, body)) = chunk.split_first() else {
            continue;
        };
        if op % 3 == 0 {
            // Raw bytes as a record from the network.
            let mut rec = body.to_vec();
            let _ = server.open(&mut rec, &mut out);
            continue;
        }
        if body.is_empty() {
            // Nothing to send makes no record.
            continue;
        }
        let mut sealed = Vec::new();
        if client.send(body, &mut sealed).is_err() {
            return;
        }
        let Some(len) = record_len(&sealed) else {
            panic!("sealed record without a header");
        };
        let mut rec = sealed.get(..len).unwrap_or(&[]).to_vec();
        let flip = op % 3 == 2 && !rec.is_empty();
        if flip {
            let at = usize::from(op) % rec.len();
            rec[at] ^= 0x01;
        }
        match server.open(&mut rec, &mut out) {
            Ok(Opened::Data(r)) => {
                assert!(!flip, "a modified record was accepted");
                assert_eq!(rec.get(r), Some(body), "record opened to other data");
            }
            Ok(other) => panic!("data record opened as {other:?}"),
            // The layer is unusable after an error: start over.
            Err(_) => {
                assert!(flip, "an intact record was rejected");
                return;
            }
        }
    }
});
