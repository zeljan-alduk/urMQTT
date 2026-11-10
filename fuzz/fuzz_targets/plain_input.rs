//! The plaintext listener's inputs (P1): the text parsers of the allow-list,
//! the account and the identity entries, the password-hash format, and a model
//! check of the per-source table under arbitrary sequences of operations.
//! Parsing must return `Ok`/`Err` and never panic; whatever parses must
//! round-trip; the table must keep exactly the connection counts the model
//! keeps and never forget a live connection. The allow-list takes IPv6
//! networks too (NEXT-1, ADR-334): an IPv6 network never admits an IPv4
//! address and the other way round.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_cfg::net::{Cidr, Net};
use urmqtt_cfg::passwd::PasswordHash;
use urmqtt_cfg::plain::{check_identity, parse_allow, parse_ip_identity, parse_user};
use urmqtt_plain::{AllowList, Limits, Open, Sources};

fuzz_target!(|data: &[u8]| {
    // Text parsers, on the data as lossy text and as exact text if it is UTF-8.
    let text = String::from_utf8_lossy(data);
    let _ = check_identity(&text);
    if let Ok(c) = parse_allow(&text) {
        // What parses prints back to a text of the same value and is a member
        // of itself.
        assert_eq!(Net::parse(&c.to_string()), Ok(c));
        match c {
            Net::V4(n) => assert!(c.contains_v4(n.octets())),
            Net::V6(n) => assert!(c.contains_v6(&n.addr) && !c.contains_v4([0; 4])),
        }
    }
    let _ = Cidr::parse(&text);
    if let Ok((_, hash)) = parse_user(&text) {
        // A cheap check only: a parsed hash may ask for 200000 iterations.
        if hash.iterations() <= 16 {
            let _ = hash.verify(b"password");
        }
    }
    let _ = parse_ip_identity(&text);
    if let Ok(h) = PasswordHash::parse(&text) {
        assert!(h.salt().len() >= 16 && h.salt().len() <= 32);
    }

    // The allow-list: any list of valid networks, any address.
    let nets: Vec<Net> = text
        .lines()
        .filter_map(|l| Net::parse(l.trim()).ok())
        .take(16)
        .collect();
    let list = AllowList::new(&nets, false);
    for chunk in data.chunks_exact(4).take(32) {
        let ip = [chunk[0], chunk[1], chunk[2], chunk[3]];
        let want = nets
            .iter()
            .any(|n| matches!(n, Net::V4(c) if c.contains_octets(ip)));
        assert_eq!(list.allows(ip), want);
        assert!(AllowList::new(&nets, true).allows(ip));
    }
    for chunk in data.chunks_exact(16).take(8) {
        let ip: [u8; 16] = chunk.try_into().unwrap();
        let want = nets
            .iter()
            .any(|n| matches!(n, Net::V6(c) if c.contains(&ip)));
        assert_eq!(list.allows6(&ip), want);
    }

    // The per-source table against a model, over a small set of addresses so
    // that they collide, in a table small enough to fill up.
    let limits = Limits {
        max_per_ip: 1 + u32::from(data.first().copied().unwrap_or(0) % 4),
        max_failures: 1 + u32::from(data.get(1).copied().unwrap_or(0) % 5),
        lockout_s: 1 + u32::from(data.get(2).copied().unwrap_or(0)),
    };
    let key = u64::from(data.get(3).copied().unwrap_or(0)) * 0x0101_0101;
    let mut table = Sources::new(8, key, limits);
    let mut held = [0u32; 16];
    let mut now = 1000u32;
    for op in data.iter().skip(4) {
        let which = usize::from(op >> 4) & 0x0f;
        let ip = [10, 0, 0, which as u8 + 1];
        match op & 0x0f {
            0..=5 => {
                if table.open(ip, now) == Open::Ok {
                    held[which] += 1;
                }
            }
            6..=8 => {
                if held[which] > 0 {
                    table.close(ip, now);
                    held[which] -= 1;
                }
            }
            9..=10 => {
                let _ = table.failed(ip, now);
            }
            11 => table.succeeded(ip),
            12 => now = now.saturating_add(1),
            13 => now = now.saturating_add(u32::from(*op)),
            _ => {
                let _ = table.syn(ip, now);
                let _ = table.locked_out(ip, now);
            }
        }
        assert!(table.connections(ip) >= held[which].min(limits.max_per_ip));
        assert!(held[which] <= limits.max_per_ip);
    }
    for (which, h) in held.iter().enumerate() {
        // A live connection is never forgotten.
        assert_eq!(table.connections([10, 0, 0, which as u8 + 1]), *h);
    }
});
