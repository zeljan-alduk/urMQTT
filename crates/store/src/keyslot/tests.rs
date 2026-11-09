use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn blocks(b: &[u8]) -> Vec<[u8; 8]> {
    b.as_chunks::<8>().0.to_vec()
}

fn kek() -> [u8; 32] {
    hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        .try_into()
        .unwrap()
}

/// RFC 3394 section 4.3 and 4.6 (a 256-bit KEK over 128 and 256 bits of
/// key data), both ways, and a flipped bit refused.
#[test]
fn rfc_3394_vectors() {
    for (data, want) in [
        (
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
        ),
        (
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        ),
    ] {
        let mut r = blocks(&hex(data));
        let a = wrap_blocks(&kek(), &mut r);
        let mut got = a.to_vec();
        r.iter().for_each(|b| got.extend_from_slice(b));
        assert_eq!(got, hex(want));
        assert!(unwrap_blocks(&kek(), a, &mut r));
        assert_eq!(r.concat(), hex(data));
        // One bit of the ciphertext flipped: refused.
        let w = hex(want);
        for bit in [0usize, 70, w.len() * 8 - 1] {
            let mut c = w.clone();
            c[bit / 8] ^= 1 << (bit % 8);
            let mut r = blocks(&c[8..]);
            assert!(!unwrap_blocks(&kek(), c[..8].try_into().unwrap(), &mut r));
        }
    }
}

fn disk_key(seed: u8) -> [u8; KEY_BYTES] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
}

#[test]
fn the_64_byte_wrap_round_trips_and_a_wrong_kek_fails() {
    let k = disk_key(3);
    let w = wrap(&kek(), &k);
    assert_eq!(*unwrap(&kek(), &w).unwrap(), k);
    let mut other = kek();
    other[31] ^= 1;
    assert!(unwrap(&other, &w).is_none());
}

const UUID: [u8; 16] = [0x42; 16];

#[test]
fn a_slot_opens_with_its_passphrase_only() {
    let k = disk_key(9);
    let s = KeySlot::seal(&k, b"correct horse battery", &UUID, [5; 32], MIN_ITERATIONS);
    assert_eq!(s.iterations, MIN_ITERATIONS);
    assert_eq!(*s.open(b"correct horse battery", &UUID).unwrap(), k);
    assert!(s.open(b"correct horse batterz", &UUID).is_none());
    assert!(s.open(b"", &UUID).is_none());
    // Bound to the disk: the same slot on another UUID does not open.
    assert!(s.open(b"correct horse battery", &[0x43; 16]).is_none());
    // Another salt, another wrap.
    let t = KeySlot::seal(&k, b"correct horse battery", &UUID, [6; 32], MIN_ITERATIONS);
    assert_ne!(s.wrapped, t.wrapped);
    // The cost is clamped into the format's bounds.
    let low = KeySlot::seal(&k, b"correct horse battery", &UUID, [5; 32], 1);
    assert_eq!(low.iterations, MIN_ITERATIONS);
    // Debug shows the cost, never the salt or the wrapped key.
    assert_eq!(format!("{s:?}"), "KeySlot(passphrase, 10000 iterations)");
}

#[test]
fn slots_encode_and_decode() {
    let s = KeySlot::seal(&disk_key(1), b"twelve chars!", &UUID, [7; 32], 20_000);
    let mut b = [0u8; SLOTS * SLOT_BYTES];
    encode_all(&[None, Some(s)], &mut b);
    assert!(b[..SLOT_BYTES].iter().all(|&x| x == 0));
    assert_eq!(
        &b[SLOT_BYTES..SLOT_BYTES + 4],
        &KIND_PASSPHRASE.to_le_bytes()
    );
    assert_eq!(&b[SLOT_BYTES + 4..SLOT_BYTES + 8], &20_000u32.to_le_bytes());
    assert_eq!(decode_all(&b).unwrap(), [None, Some(s)]);
    // Damage that the decoder refuses: an unknown kind, a cost out of
    // bounds either way, reserved bytes, an empty slot with bytes.
    let one = |f: &dyn Fn(&mut [u8])| {
        let mut c = b;
        f(&mut c[SLOT_BYTES..]);
        decode_all(&c)
    };
    assert_eq!(one(&|c| c[0] = 2), Err(SlotError::UnknownKind));
    assert_eq!(
        one(&|c| c[4..8].copy_from_slice(&(MIN_ITERATIONS - 1).to_le_bytes())),
        Err(SlotError::Iterations)
    );
    assert_eq!(
        one(&|c| c[4..8].copy_from_slice(&(MAX_ITERATIONS + 1).to_le_bytes())),
        Err(SlotError::Iterations)
    );
    assert_eq!(one(&|c| c[127] = 1), Err(SlotError::Reserved));
    let mut c = b;
    c[5] = 1;
    assert_eq!(decode_all(&c), Err(SlotError::Reserved));
}

#[test]
fn passphrase_rules() {
    assert_eq!(check_passphrase(b"short"), Err(PassphraseError::TooShort));
    assert_eq!(check_passphrase(b"exactly 12 c"), Ok(()));
    assert_eq!(
        check_passphrase(&[b'a'; MAX_PASSPHRASE + 1]),
        Err(PassphraseError::TooLong)
    );
    assert_eq!(check_passphrase(&[b'a'; MAX_PASSPHRASE]), Ok(()));
    assert_eq!(
        check_passphrase("pässphrase long".as_bytes()),
        Err(PassphraseError::NotPrintable)
    );
    assert_eq!(
        check_passphrase(b"tab\tinside xx"),
        Err(PassphraseError::NotPrintable)
    );
}

fn typed(e: &mut LineEditor, bytes: &[u8]) -> Vec<LineEvent> {
    bytes.iter().map(|&b| e.feed(b)).collect()
}

#[test]
fn the_line_editor() {
    let mut e = LineEditor::new();
    let ev = typed(&mut e, b"abc\x7fd\x08x\r");
    assert_eq!(ev.last(), Some(&LineEvent::Done));
    assert_eq!(e.line(), b"abx");
    e.clear();
    // CR LF ends the line once; the LF is swallowed.
    assert_eq!(typed(&mut e, b"\n"), [LineEvent::None]);
    assert_eq!(e.line(), b"");
    // A lone LF ends a line too.
    assert_eq!(typed(&mut e, b"q\n").last(), Some(&LineEvent::Done));
    assert_eq!(e.line(), b"q");
    e.clear();
    // Arrow keys (CSI and SS3) and other controls are ignored.
    typed(&mut e, b"a\x1b[A\x1b[1;5Cb\x1bOBc\x01\x00\x09d");
    assert_eq!(e.line(), b"abcd");
    // Ctrl-U clears, Ctrl-C too.
    assert_eq!(typed(&mut e, b"\x15"), [LineEvent::Cleared]);
    assert_eq!(e.line(), b"");
    typed(&mut e, b"zz\x03");
    assert_eq!(e.line(), b"");
    // Backspace on an empty line does nothing.
    typed(&mut e, b"\x08\x08y");
    assert_eq!(e.line(), b"y");
    e.clear();
    // Too long: dropped whole, reported at Enter, then a fresh line.
    for _ in 0..MAX_PASSPHRASE {
        assert_eq!(e.feed(b'a'), LineEvent::None);
    }
    assert_eq!(e.line().len(), MAX_PASSPHRASE);
    e.feed(b'b');
    assert_eq!(e.line(), b"");
    assert_eq!(
        typed(&mut e, b"cc\x08\r"),
        [LineEvent::None; 3]
            .iter()
            .copied()
            .chain([LineEvent::Overflow])
            .collect::<Vec<_>>()
    );
    assert_eq!(typed(&mut e, b"ok\r").last(), Some(&LineEvent::Done));
    assert_eq!(e.line(), b"ok");
    // Non-ASCII bytes are not taken.
    e.clear();
    typed(&mut e, "é1".as_bytes());
    assert_eq!(e.line(), b"1");
}
