//! Password-account control messages (NOW-15, ADR-285): the item of a
//! `set-account` message and the bodies of the two account commands reach the
//! decoder on the DB core after the signature check. Nothing may panic; an
//! item that parses re-encodes to the same bytes and names a valid identity
//! and a bounded PBKDF2 hash; a body that decodes has at most
//! `MAX_ACCOUNT_ITEMS` items with distinct ids and re-encodes exactly; the
//! policy refuses account commands when the image has no accounts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_cfg::passwd::{self, PasswordHash};
use urmqtt_cfg::plain::check_identity;
use urmqtt_control::{
    AccountClass, Command, MAX_ACCOUNT_ITEMS, MAX_ACCOUNT_ITERATIONS, Message, Policy, Reject,
    decode_body, encode_account, encode_body, parse_account,
};

fn check_item(item: &[u8]) {
    if let Ok(a) = parse_account(item) {
        assert_eq!(
            encode_account(a.class, a.id, a.hash).as_deref(),
            Some(item),
            "an item that parses re-encodes to itself"
        );
        assert!(check_identity(a.id).is_ok());
        let h = PasswordHash::parse(a.hash).expect("the hash parsed once");
        assert!(h.iterations() <= MAX_ACCOUNT_ITERATIONS);
        assert!(item.len() <= 255, "an item fits a length byte");
    }
}

fn check_body(body: &[u8]) {
    let Ok(m) = decode_body(body) else { return };
    assert_eq!(encode_body(&m).as_deref(), Some(body));
    if m.command.on_accounts() {
        assert!(m.items.len() <= MAX_ACCOUNT_ITEMS);
        let ids: Vec<Vec<u8>> = m
            .items
            .iter()
            .map(|i| {
                if m.command == Command::SetAccount {
                    parse_account(i).expect("decoded").id.as_bytes().to_vec()
                } else {
                    check_identity(std::str::from_utf8(i).expect("an identity is ASCII"))
                        .expect("an identity");
                    i.clone()
                }
            })
            .collect();
        for (n, id) in ids.iter().enumerate() {
            assert!(!ids[..n].contains(id), "one id once per message");
        }
        let off = Policy {
            max_message_age_s: 600,
            allow_unrevoke: true,
            allowlist_mode: true,
            accounts: false,
        };
        assert_eq!(
            urmqtt_control::check(&m, Some(m.not_before), 0, &off),
            if m.not_after - m.not_before > 600 {
                Err(Reject::WindowTooLong)
            } else {
                Err(Reject::AccountsDisabled)
            }
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        // A raw item.
        0 => check_item(rest),
        // A raw body, any command.
        1 => check_body(rest),
        // A structured message: the id, class and password come from the
        // input, so a good part of the inputs encode and reach the checks.
        _ => {
            if rest.len() < 3 {
                return;
            }
            let class = AccountClass::from_byte(rest[0] % 4);
            let n = usize::from(rest[1]) % 10;
            let remove = rest[2] & 1 == 1;
            let tail = &rest[3..];
            let mut items = Vec::new();
            for (i, chunk) in tail
                .chunks((tail.len() / n.max(1)).max(1))
                .take(n)
                .enumerate()
            {
                let id: String = chunk
                    .iter()
                    .take(8)
                    .map(|b| char::from(b'a' + (b % 26)))
                    .chain(std::iter::once(char::from(b'0' + (i as u8 % 10))))
                    .collect();
                if remove {
                    items.push(id.into_bytes());
                } else if let Some(c) = class {
                    let salt = [chunk.first().copied().unwrap_or(7); 16];
                    let iterations = 1000 + u32::from(rest[2] % 8) * 100;
                    let Ok(hash) = passwd::encode(chunk, &salt, iterations) else {
                        continue;
                    };
                    if let Some(item) = encode_account(c, &id, &hash) {
                        items.push(item);
                    }
                }
            }
            let m = Message {
                seq: 1,
                not_before: 10,
                not_after: 20,
                command: if remove {
                    Command::RemoveAccount
                } else {
                    Command::SetAccount
                },
                items,
            };
            if let Some(body) = encode_body(&m) {
                assert_eq!(decode_body(&body).as_ref(), Ok(&m));
                check_body(&body);
                // One byte flipped: never a panic, and if it still decodes it
                // is again a message of the same shape.
                let mut flipped = body.clone();
                let at = usize::from(rest[1]) % flipped.len();
                flipped[at] ^= 1 << (rest[0] % 8);
                check_body(&flipped);
            }
        }
    }
});
