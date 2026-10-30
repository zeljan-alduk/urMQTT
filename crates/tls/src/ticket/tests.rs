use super::*;

const IV: u64 = 100;

fn keys() -> TicketKeys {
    TicketKeys::new(IV, || 0)
}

/// A deterministic "CSPRNG" for the tests: a counter stream.
fn rng() -> impl FnMut(&mut [u8]) -> bool {
    let mut n = 1u8;
    move |b: &mut [u8]| {
        for x in b {
            *x = n;
            n = n.wrapping_mul(31).wrapping_add(7);
        }
        true
    }
}

fn seal(k: &TicketKeys, now: u64, plain: &[u8]) -> Vec<u8> {
    k.seal_at(now, &mut rng(), plain).unwrap()
}

#[test]
fn round_trip_and_format() {
    let k = keys();
    let t = seal(&k, 0, b"session state");
    assert_eq!(t.len(), ID_LEN + NONCE_LEN + 13 + TAG_LEN);
    assert_eq!(k.open_at(1, &t).unwrap(), b"session state");
    assert_eq!(k.stats().issued, 1);
    assert_eq!(k.stats().opened, 1);
}

#[test]
fn rotation_boundaries() {
    let k = keys();
    // The first key is born with the first ticket, at 0. This one is
    // issued at the very end of its current interval.
    seal(&k, 0, b"first");
    let late = seal(&k, IV - 1, b"a");
    assert_eq!(k.live_keys_at(IV - 1), 1);
    // The next ticket comes from a new key; the first one is previous now.
    let next = seal(&k, IV, b"b");
    assert_ne!(late.get(..ID_LEN), next.get(..ID_LEN));
    assert_eq!(k.live_keys_at(IV), 2);
    // The previous key opens until two intervals after its birth (the
    // late ticket's full lifetime of IV seconds) ...
    assert_eq!(k.open_at(2 * IV - 1, &late).unwrap(), b"a");
    // ... and not one second longer.
    assert_eq!(k.open_at(2 * IV, &late), Err(Refused::Expired));
    assert_eq!(k.open_at(2 * IV, &next).unwrap(), b"b");
    assert_eq!(k.open_at(3 * IV, &next), Err(Refused::Expired));
    let s = k.stats();
    assert_eq!(s.refused[Refused::Expired.index()], 2);
}

#[test]
fn every_ticket_lives_its_lifetime_and_no_longer() {
    // For tickets issued at every second over four intervals: they open
    // for the whole lifetime (`interval`), and the key is gone by
    // 2 intervals after it was born, so never later than 2 lifetimes.
    for t in 0..4 * IV {
        // A key born at 0, so `t` falls anywhere in some key's interval.
        let k = keys();
        seal(&k, 0, b"first");
        let tk = seal(&k, t, &t.to_le_bytes());
        assert_eq!(
            k.open_at(t + IV - 1, &tk).unwrap(),
            t.to_le_bytes(),
            "issued {t}"
        );
        assert!(k.open_at(t + 2 * IV, &tk).is_err(), "issued {t}");
    }
}

#[test]
fn long_sleep_drops_both_keys_and_starts_fresh() {
    let k = keys();
    let old = seal(&k, 0, b"x");
    seal(&k, IV, b"y");
    assert_eq!(k.live_keys_at(10 * IV), 0);
    assert_eq!(k.open_at(10 * IV, &old), Err(Refused::Expired));
    // A fresh key is born now, not back-dated: its ticket lasts a full IV.
    let fresh = seal(&k, 10 * IV, b"z");
    assert_eq!(k.open_at(11 * IV - 1, &fresh).unwrap(), b"z");
}

#[test]
fn opening_alone_still_expires_keys() {
    // No ticket is issued after the first: the key must still age out.
    let k = keys();
    let t = seal(&k, 0, b"x");
    assert_eq!(k.open_at(IV + 1, &t).unwrap(), b"x");
    assert_eq!(k.open_at(2 * IV, &t), Err(Refused::Expired));
    assert_eq!(k.live_keys_at(2 * IV), 0);
}

#[test]
fn forged_tickets_are_refused() {
    let k = keys();
    let t = seal(&k, 0, b"identity: device-001");
    // Every single flipped bit, in the id, the nonce, the body or the tag.
    for i in 0..t.len() * 8 {
        let mut f = t.clone();
        if let Some(b) = f.get_mut(i / 8) {
            *b ^= 1 << (i % 8);
        }
        let r = k.open_at(1, &f);
        let want = if i < ID_LEN * 8 {
            Refused::UnknownKey
        } else {
            Refused::Invalid
        };
        assert_eq!(r, Err(want), "bit {i}");
    }
    // Another instance's keys (another boot or replica): unknown id.
    let other = TicketKeys::new(IV, || 0);
    let mut r2 = {
        let mut n = 200u8;
        move |b: &mut [u8]| {
            for x in b {
                *x = n;
                n = n.wrapping_mul(17).wrapping_add(3);
            }
            true
        }
    };
    let foreign = other.seal_at(0, &mut r2, b"x").unwrap();
    assert_eq!(k.open_at(1, &foreign), Err(Refused::UnknownKey));
    // Truncated and empty.
    assert_eq!(
        k.open_at(1, &t[..ID_LEN + NONCE_LEN]),
        Err(Refused::Malformed)
    );
    assert_eq!(k.open_at(1, &[]), Err(Refused::Malformed));
    // The current id with a body sealed under a different key.
    let mut spliced = foreign.clone();
    spliced[..ID_LEN].copy_from_slice(&t[..ID_LEN]);
    assert_eq!(k.open_at(1, &spliced), Err(Refused::Invalid));
}

#[test]
fn image_derived_tickets_are_refused() {
    // The pre-H2 format: nonce || ChaCha20-Poly1305 under a key derived
    // from the server key. Whatever key an attacker derives, the ticket
    // names no key id here.
    let k = keys();
    seal(&k, 0, b"x");
    let derived = [7u8; 32];
    let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived).unwrap();
    let nonce = [1u8; 12];
    let mut body = b"forged session".to_vec();
    aead.encrypt_in_place((&nonce).into(), b"urmqtt ticket", &mut body)
        .unwrap();
    let mut old = nonce.to_vec();
    old.extend_from_slice(&body);
    assert_eq!(k.open_at(1, &old), Err(Refused::UnknownKey));
}

#[test]
fn retired_keys_are_zeroised_in_place() {
    let k = keys();
    seal(&k, 0, b"x");
    seal(&k, IV, b"y");
    let live = k.slot_bytes();
    assert!(live.iter().all(|(l, b)| *l && b.iter().any(|&x| x != 0)));
    // The first key retires at 2 IV, the second at 3 IV.
    assert_eq!(k.live_keys_at(2 * IV), 1);
    let s = k.slot_bytes();
    assert_eq!(s.iter().filter(|(l, _)| !l).count(), 1);
    for (l, b) in s {
        if !l {
            assert_eq!(b, [0; 32], "a retired slot keeps key bytes");
        }
    }
    assert_eq!(k.live_keys_at(3 * IV), 0);
    assert!(k.slot_bytes().iter().all(|(l, b)| !l && *b == [0; 32]));
}

#[test]
fn rng_failure_issues_no_ticket() {
    let k = keys();
    assert!(k.seal_at(0, &mut |_| false, b"x").is_none());
    assert_eq!(k.live_keys_at(0), 0);
    assert!(k.slot_bytes().iter().all(|(l, b)| !l && *b == [0; 32]));
    assert_eq!(k.stats().not_issued, 1);
    // A key exists, but the nonce fails: still nothing.
    seal(&k, 0, b"x");
    let mut fail_nonce = |b: &mut [u8]| {
        b.fill(9);
        false
    };
    assert!(k.seal_at(1, &mut fail_nonce, b"x").is_none());
    assert_eq!(k.stats().not_issued, 2);
}

#[test]
fn nonces_differ_per_ticket() {
    let k = keys();
    let mut r = rng();
    let a = k.seal_at(0, &mut r, b"same").unwrap();
    let b = k.seal_at(0, &mut r, b"same").unwrap();
    assert_eq!(a[..ID_LEN], b[..ID_LEN]);
    assert_ne!(a[ID_LEN..ID_LEN + NONCE_LEN], b[ID_LEN..ID_LEN + NONCE_LEN]);
    assert_ne!(a, b);
}

#[test]
fn debug_never_prints_keys() {
    let k = keys();
    seal(&k, 0, b"x");
    let d = alloc::format!("{k:?}");
    assert!(d.contains("interval") && !d.contains("key:"), "{d}");
}
