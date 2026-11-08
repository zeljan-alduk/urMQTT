//! What the schema 3 and 4 golden tests share (ADR-271, ADR-274): the disk
//! helpers, the QoS 2 state of `schema3-qos2` and the MQTT 5.0 state of
//! `schema4-mqtt5`.

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
    sparse_titled(m, "database schema 3 (QoS 2)")
}

pub fn sparse_titled(m: &MemDisk, what: &str) -> String {
    let mut out = format!(
        "# urMQTT data disk, layout v2.0, {what}: every non-zero 512-byte sector as `lba hex`\n"
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
        ..Queued::default()
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
        ..SessionRecord::default()
    }
}

/// The MQTT 5.0 state of `schema4-mqtt5` (ADR-274): a session with its
/// Session Expiry Interval, offline since a known time, a subscription with
/// options, queued and retained messages with properties and expiry.
pub fn write_mqtt5_state(s: &mut urmqtt_store::Store) {
    s.begin().unwrap();
    s.retain_v5(
        "fleet/notice",
        b"maintenance",
        1,
        Some(&PROPS),
        Some(NOW as i64 + 3600),
    )
    .unwrap();
    s.session_upsert_expiry("device-005", NOW as i64, Some(86_400))
        .unwrap();
    // QoS 1, No Local, Retain As Published, Retain Handling 1.
    s.subscribe_options("device-005", "devices/device-005/cmd/#", 0x1d)
        .unwrap();
    s.queue_push_v5("device-005", mqtt5_queued().as_ref())
        .unwrap();
    s.queue_push("device-005", "devices/device-005/cmd/plain", b"p", 1)
        .unwrap();
    s.session_offline("device-005", NOW as i64 + 60).unwrap();
    s.commit().unwrap();
}

/// A property block: Content Type "text/plain", User Property k=v.
pub const PROPS: [u8; 20] = [
    0x03, 0, 10, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n', 0x26, 0, 1, b'k', 0,
    1, b'v',
];

fn mqtt5_queued() -> Queued {
    Queued {
        topic: "devices/device-005/cmd/fw".into(),
        payload: b"fw".to_vec(),
        qos: 2,
        pid: 0,
        props: Some(PROPS.to_vec()),
        expires_at: Some(NOW as i64 + 600),
    }
}

pub fn want_mqtt5_session() -> SessionRecord {
    SessionRecord {
        client_id: "device-005".into(),
        subscriptions: vec![("devices/device-005/cmd/#".into(), 0x1d)],
        queued: vec![
            mqtt5_queued(),
            Queued {
                topic: "devices/device-005/cmd/plain".into(),
                payload: b"p".to_vec(),
                qos: 1,
                ..Queued::default()
            },
        ],
        qos2_ids: vec![],
        sub_ids: vec![],
        expiry_s: Some(86_400),
        offline_since: Some(NOW as i64 + 60),
    }
}

/// The MQTT 5.0 part 3 state of `schema5-shared` (ADR-275): a service's
/// session with a shared subscription and Subscription Identifiers.
pub fn write_shared_state(s: &mut urmqtt_store::Store) {
    s.begin().unwrap();
    s.session_upsert_expiry("backend", NOW as i64, Some(3_600))
        .unwrap();
    s.subscribe_v5("backend", "$share/workers/devices/+/telemetry", 1, 42)
        .unwrap();
    s.subscribe_v5("backend", "fleet/#", 2, 268_435_455)
        .unwrap();
    s.subscribe_v5("backend", "devices/+/status", 0, 0).unwrap();
    s.commit().unwrap();
}

pub fn want_shared_session() -> SessionRecord {
    SessionRecord {
        client_id: "backend".into(),
        subscriptions: vec![
            ("$share/workers/devices/+/telemetry".into(), 1),
            ("devices/+/status".into(), 0),
            ("fleet/#".into(), 2),
        ],
        sub_ids: vec![
            ("$share/workers/devices/+/telemetry".into(), 42),
            ("fleet/#".into(), 268_435_455),
        ],
        expiry_s: Some(3_600),
        ..SessionRecord::default()
    }
}
