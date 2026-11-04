//! virtio-vsock packets (ADR-258): the stream stack of the Diagnostic
//! report service gets any packet sequence a host could send. Each step is
//! a selector byte and, for a packet, 44 header bytes (a selector bit makes
//! it address our CID and port, so connections really open). The stack
//! never panics, never holds more than MAX_CONNS connections, never sends a
//! payload outside the document or larger than the transmit buffer, and
//! never sends a connection more than the document.
#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::vsock::{
    DIAG_PORT, HDR_LEN, HOST_CID, Hdr, MAX_CONNS, OP_RESPONSE, OP_RW, Stack, TX_PAYLOAD,
};

const CID: u64 = 42;

fuzz_target!(|data: &[u8]| {
    let mut s = Stack::new(CID, DIAG_PORT);
    let doc: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    let mut now = 0u64;
    let mut sent: HashMap<u32, usize> = HashMap::new();
    let mut rest = data;
    while let Some((&sel, tail)) = rest.split_first() {
        rest = tail;
        if sel & 1 == 0 {
            let Some((raw, tail)) = rest.split_first_chunk::<HDR_LEN>() else {
                break;
            };
            rest = tail;
            if let Some(mut h) = Hdr::parse(raw) {
                if sel & 2 != 0 {
                    h.src_cid = HOST_CID;
                    h.dst_cid = CID;
                    h.dst_port = DIAG_PORT;
                    h.ty = 1;
                    h.op = 1 + u16::from(sel >> 4) % 7;
                    h.src_port %= 8;
                }
                s.on_packet(&h, h.len.min(4096), now);
            }
        } else {
            now = now.saturating_add(u64::from(sel) << 24);
            for _ in 0..64 {
                let Some((h, r)) = s.next_packet(&doc, TX_PAYLOAD, now) else {
                    break;
                };
                assert!(r.end <= doc.len() && r.len() <= TX_PAYLOAD);
                // From us; a reset answers on the port the packet was sent to.
                assert!(h.src_cid == CID && (h.src_port == DIAG_PORT || h.op != OP_RW));
                if h.op == OP_RW {
                    assert_eq!(h.len as usize, r.len());
                    let total = sent.entry(h.dst_port).or_insert(0);
                    *total += r.len();
                    assert!(*total <= doc.len());
                } else {
                    assert!(r.is_empty());
                    // A new connection (our RESPONSE) starts from zero.
                    if h.op == OP_RESPONSE {
                        sent.insert(h.dst_port, 0);
                    }
                }
            }
        }
        assert!(s.open() <= MAX_CONNS);
    }
});
