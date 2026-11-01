//! Arbitrary bytes into the kernel's configuration blob decoder (C1):
//! parsing must return `Ok`/`Err` and never panic, anything it accepts must
//! survive every typed accessor and the cross-field checks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_cfg::blob::{
    Blob, FORMAT_VERSION, MAGIC, SlotKind, find_slots, fingerprint_of, slot_blob,
};
use urmqtt_cfg::check::check;
use urmqtt_cfg::fields::{FIELDS, Kind};

/// Wraps `payload` in a header with the right fingerprint, so the fuzzer
/// explores the record grammar instead of stalling on the hash.
fn assemble(payload: &[u8]) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    let fp = fingerprint_of(&v);
    v.extend_from_slice(&fp);
    v.push(0);
    v
}

fuzz_target!(|data: &[u8]| {
    let wrapped = assemble(data);
    // As a bare blob, a well-fingerprinted payload, and the content of a slot.
    for bytes in [
        data,
        &wrapped[..],
        slot_blob(data, SlotKind::Boot).unwrap_or(&[]),
    ] {
        let Ok(b) = Blob::parse(bytes) else {
            continue;
        };
        for f in FIELDS {
            match f.kind {
                Kind::Bool(_) => {
                    let _ = b.bool(f.tag);
                }
                Kind::UInt { .. } => {
                    let _ = b.uint(f.tag);
                }
                Kind::Enum { .. } => {
                    let _ = b.variant(f.tag);
                }
                Kind::Str { .. } => {
                    let _ = b.str(f.tag);
                }
                Kind::Strs { .. } => {
                    let _ = b.strs(f.tag).count();
                }
                Kind::Bin { .. } => {
                    let _ = b.bin(f.tag);
                }
                Kind::BinList { .. } => {
                    let _ = b.bins(f.tag).count();
                }
                Kind::Ipv4 => {
                    let _ = b.ipv4(f.tag);
                }
                Kind::Cidr => {
                    let _ = b.cidr(f.tag);
                }
                Kind::Rate { .. } => {
                    let _ = b.rate(f.tag);
                }
                Kind::Addr => {
                    let _ = b.addr(f.tag);
                }
                Kind::Addrs { .. } => {
                    let _ = b.addrs(f.tag).count();
                }
                Kind::Key32 => {
                    let _ = b.key32(f.tag);
                }
            }
        }
        for dev in [false, true] {
            let _ = check(&b, dev);
        }
    }
    let _ = find_slots(data, SlotKind::Boot);
});
