//! Telemetry log recovery (M12, M16): the log region of the data disk is
//! read back at every boot from a device the kernel does not trust blindly.
//! A valid log with records in every partition is damaged at fuzz-chosen
//! places; opening and scanning it must never panic, and nothing may come
//! back that is larger than the region.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use urmqtt_store::disk::{Disk, MemDisk};
use urmqtt_store::layout::{RegionKind, SECTOR};
use urmqtt_store::telemetry::TelemetryLog;

const SIZE: usize = 16 << 20;
const NOW: u64 = 1_761_696_000;

/// A disk image with a valid log, and the log region's byte range.
fn base() -> &'static (Vec<u8>, u64, u64) {
    static BASE: OnceLock<(Vec<u8>, u64, u64)> = OnceLock::new();
    BASE.get_or_init(|| {
        let m = MemDisk::new(SIZE);
        let (mut d, _) = Disk::open(m.device(), || [1; 16]).unwrap();
        let (mut log, _) = TelemetryLog::open(&mut d, NOW, u64::MAX).unwrap();
        for i in 0..2000u64 {
            let p = (i % 8) as usize;
            log.append(
                &mut d,
                p,
                NOW * 1000 + i,
                "devices/d/telemetry/t",
                &i.to_le_bytes(),
            )
            .unwrap();
            if i % 300 == 0 {
                log.flush(&mut d).unwrap();
            }
        }
        log.flush(&mut d).unwrap();
        let r = d.region(RegionKind::Telemetry).unwrap();
        drop(d);
        (m.raw(0, SIZE), r.start * SECTOR, r.bytes())
    })
}

fuzz_target!(|data: &[u8]| {
    let (image, start, len) = base();
    let mut img = image.clone();
    // Patches: 4-byte offset into the region, 1-byte length, bytes.
    let mut rest = data;
    while let Some((head, tail)) = rest.split_first_chunk::<5>() {
        let off = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as u64 % len;
        let n = usize::from(head[4]).min(tail.len());
        let at = (start + off) as usize;
        for (k, b) in tail[..n].iter().enumerate() {
            if let Some(x) = img.get_mut(at + k) {
                *x = *b;
            }
        }
        rest = &tail[n..];
    }
    let m = MemDisk::from_image(img);
    let Ok((mut d, _)) = Disk::open(m.device(), || [1; 16]) else {
        return;
    };
    let Ok((log, rec)) = TelemetryLog::open(&mut d, NOW, u64::MAX) else {
        return;
    };
    let mut bytes = 0u64;
    for p in 0..8 {
        let _ = log.scan(&mut d, p, u64::MAX, |r| {
            bytes += (r.topic.len() + r.payload.len()) as u64;
        });
    }
    assert!(bytes <= *len, "recovered more than the region holds");
    let _ = rec;
});
