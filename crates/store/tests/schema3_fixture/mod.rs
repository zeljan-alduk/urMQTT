//! What the schema 3 golden tests share (ADR-271): the disk helpers and
//! the QoS 2 state the golden file holds.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::layout::SECTOR;
use urmqtt_store::{Disk, MemDisk, Platform, Qos2Id, Queued, SessionRecord};

pub const DISK_BYTES: usize = 16 << 20;
pub const UUID: [u8; 16] = *b"urmqtt-golden-v2";
pub const NOW: u64 = 1_761_696_000;

pub fn platform() -> Platform {
    Platform {
        random: |b| {
            b.iter_mut()
                .enumerate()
                .for_each(|(i, x)| *x = (i * 31 + 7) as u8)
        },
        now_unix_ms: || Some(NOW * 1000),
        delay_us: |_| {},
        log: |_, _| {},
    }
}

pub fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub fn heap() -> &'static mut [u8] {
    Box::leak(vec![0u8; 32 << 20].into_boxed_slice())
}

pub fn path(name: &str) -> PathBuf {
    [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "golden",
        &format!("{name}.txt"),
    ]
    .iter()
    .collect()
}

pub fn sparse(m: &MemDisk) -> String {
    let mut out = String::from(
        "# urMQTT data disk, layout v2.0, database schema 3 (QoS 2): every non-zero 512-byte sector as `lba hex`\n",
    );
    let _ = writeln!(out, "size {DISK_BYTES}");
    let sector = SECTOR as usize;
    for lba in 0..DISK_BYTES / sector {
        let s = m.raw(lba * sector, sector);
        if s.iter().any(|&b| b != 0) {
            let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(out, "{lba} {hex}");
        }
    }
    out
}

pub fn load(name: &str) -> MemDisk {
    let text = std::fs::read_to_string(path(name)).unwrap();
    let mut img = vec![0u8; DISK_BYTES];
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("size"))
    {
        let (lba, hex) = line.split_once(' ').unwrap();
        let at = lba.parse::<usize>().unwrap() * SECTOR as usize;
        for (i, b) in img[at..at + SECTOR as usize].iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    MemDisk::from_image(img)
}

/// Installs `m` as the store's disk.
pub fn mount(m: &MemDisk) {
    let (disk, _) = Disk::open(m.device(), || UUID).unwrap();
    urmqtt_store::init(heap(), disk, platform()).unwrap();
}

/// The QoS 2 state the golden file holds.
pub fn write_qos2_state(s: &mut urmqtt_store::Store) {
    s.begin().unwrap();
    s.retain("fleet/fw", b"2.0", 2).unwrap();
    s.session_upsert("device-002", NOW as i64).unwrap();
    s.subscribe("device-002", "devices/device-002/cmd/#", 2)
        .unwrap();
    s.queue_push_sent("device-002", "devices/device-002/cmd/a", b"a", 2, 7)
        .unwrap();
    s.queue_push_sent("device-002", "devices/device-002/cmd/b", b"b", 1, 8)
        .unwrap();
    s.queue_push("device-002", "devices/device-002/cmd/c", b"c", 2)
        .unwrap();
    for id in [
        Qos2Id {
            released: true,
            pid: 6,
        },
        Qos2Id {
            released: false,
            pid: 41,
        },
        Qos2Id {
            released: false,
            pid: 40,
        },
        // Recorded twice (a snapshot after another): one row.
        Qos2Id {
            released: false,
            pid: 40,
        },
        // Not an id: not stored.
        Qos2Id {
            released: false,
            pid: 0,
        },
    ] {
        s.qos2_id("device-002", id).unwrap();
    }
    s.commit().unwrap();
}

pub fn want_qos2_session() -> SessionRecord {
    let q = |t: &str, p: &[u8], qos, pid| Queued {
        topic: t.into(),
        payload: p.into(),
        qos,
        pid,
    };
    SessionRecord {
        client_id: "device-002".into(),
        subscriptions: vec![("devices/device-002/cmd/#".into(), 2)],
        queued: vec![
            q("devices/device-002/cmd/a", b"a", 2, 7),
            q("devices/device-002/cmd/b", b"b", 1, 8),
            q("devices/device-002/cmd/c", b"c", 2, 0),
        ],
        qos2_ids: vec![
            Qos2Id {
                released: false,
                pid: 40,
            },
            Qos2Id {
                released: false,
                pid: 41,
            },
            Qos2Id {
                released: true,
                pid: 6,
            },
        ],
    }
}
