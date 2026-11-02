use super::*;
use crate::disk::MemDisk;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// IEEE 1619-2007, vector 1 for AES-256 (data unit 0, all zero keys cannot
/// be used by `check_key`, but the primitive must still match).
#[test]
fn ieee_1619_vector_10_style_sector() {
    // Vector 10 of IEEE 1619: AES-256, data unit 0xff, plaintext 00..ff
    // twice (512 bytes). Keys are the digits of e and pi.
    let k1 = hex("2718281828459045235360287471352662497757247093699959574966967627");
    let k2 = hex("3141592653589793238462643383279502884197169399375105820974944592");
    let mut key = [0u8; KEY_BYTES];
    key[..32].copy_from_slice(&k1);
    key[32..].copy_from_slice(&k2);
    let dk = DiskKey::new(&key);
    let mut buf: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
    dk.sector(0xff, &mut buf, true);
    assert_eq!(&buf[..16], &hex("1c3b3a102f770386e4836c99e370cf9b")[..]);
    dk.sector(0xff, &mut buf, false);
    let plain: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
    assert_eq!(buf, plain);
}

#[test]
fn key_checks() {
    assert_eq!(check_key(&[1; 10]), Err(KeyError::Length));
    assert_eq!(check_key(&[7; 64]), Err(KeyError::Weak));
    let mut k = [0u8; 64];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    assert!(check_key(&k).is_ok());
    let mut same = [0u8; 64];
    let (a, b) = same.split_at_mut(32);
    a.copy_from_slice(&k[..32]);
    b.copy_from_slice(&k[..32]);
    assert_eq!(check_key(&same), Err(KeyError::Weak));
}

fn key(seed: u8) -> [u8; KEY_BYTES] {
    let mut k = [0u8; KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(seed);
    }
    k
}

#[test]
fn key_check_depends_on_key_and_uuid() {
    let a = DiskKey::new(&key(1));
    let b = DiskKey::new(&key(2));
    let c = a.key_check(&[9; 16]);
    assert!(a.matches(&[9; 16], &c));
    assert!(!b.matches(&[9; 16], &c));
    assert!(!a.matches(&[8; 16], &c));
}

#[test]
fn sectors_differ_by_position_and_roundtrip() {
    let dk = DiskKey::new(&key(1));
    let mut x = [0x55u8; 512];
    let mut y = [0x55u8; 512];
    dk.sector(10, &mut x, true);
    dk.sector(11, &mut y, true);
    assert_ne!(x, y);
    assert_ne!(x, [0x55u8; 512]);
    dk.sector(10, &mut x, false);
    assert_eq!(x, [0x55u8; 512]);
}

#[test]
fn wrapper_encrypts_all_but_the_superblock_and_keeps_holes_zero() {
    let raw = MemDisk::new(1 << 20);
    let probe = raw.clone();
    let mut d = CryptDev::new(Box::new(raw), DiskKey::new(&key(3)));
    let data = [0xabu8; 4096];
    d.write(0, &data).unwrap(); // slot A: plain
    d.write(8, &data).unwrap(); // size table: encrypted
    let mut seen = [0u8; 4096];
    let mut p = probe.clone();
    p.read(0, &mut seen).unwrap();
    assert_eq!(seen, data);
    p.read(8, &mut seen).unwrap();
    assert_ne!(seen, data);
    let mut back = [0u8; 4096];
    d.read(8, &mut back).unwrap();
    assert_eq!(back, data);
    // A hole reads as zeros.
    d.read(100, &mut back).unwrap();
    assert_eq!(back, [0u8; 4096]);
    // Written zeros come back as zeros but are not zero on the medium.
    d.write(200, &[0u8; 4096]).unwrap();
    p.read(200, &mut seen).unwrap();
    assert_ne!(seen, [0u8; 4096]);
    d.read(200, &mut back).unwrap();
    assert_eq!(back, [0u8; 4096]);
}

/// `cargo test -p urmqtt-store --release --lib crypt::tests::xts_throughput -- --ignored --nocapture`
/// (S7 measurement; host CPU, the `aes` crate's best backend for it).
#[test]
#[ignore]
fn xts_throughput() {
    let dk = DiskKey::new(&key(9));
    let mut buf = vec![0x5au8; 1 << 20];
    for enc in [true, false] {
        let rounds = 400;
        let t = std::time::Instant::now();
        for r in 0..rounds {
            for (i, s) in buf.chunks_exact_mut(512).enumerate() {
                dk.sector((r * 2048 + i) as u64, s, enc);
            }
        }
        let secs = t.elapsed().as_secs_f64();
        println!(
            "xts {}: {:.0} MB/s (hardware_aes={})",
            if enc { "encrypt" } else { "decrypt" },
            rounds as f64 / secs * 1.048576,
            hardware_aes()
        );
    }
}
