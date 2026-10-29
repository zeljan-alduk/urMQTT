//! `urmqtt-disk`: offline work on a urMQTT boot disk (STORAGE-PLAN S1):
//! an image file or a block device, on macOS or Linux, with the VM stopped.
//!
//! ```text
//! urmqtt-disk info DISK                          GPT, data partition, layout, file sizes
//! urmqtt-disk verify DISK                        every check; non-zero exit on any error
//! urmqtt-disk export-db DISK OUT.sqlite          the database with its WAL applied
//! urmqtt-disk export-telemetry DISK [--format csv|jsonl] [--since MS] [--until MS] [--topic FILTER]
//! urmqtt-disk import-devices DISK FILE [--allowlist] --write
//!                                                device ids, one per line, into the registry
//!                                                (and the allowlist)
//! urmqtt-disk create OUT --esp ESP [--size BYTES[K|M|G]]
//!                                                a boot image (byte for byte mkraw.py), optionally
//!                                                on a larger disk; the first boot formats the data
//! urmqtt-disk update-boot DISK --esp ESP --write replace the kernel (ESP), keep the data
//! ```
//!
//! Everything is read-only unless `--write` is given. Commands that only
//! read but need SQLite or the telemetry recovery to run (`verify`,
//! `export-*`) work on an in-memory copy-on-write overlay, so the disk is
//! never changed.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use urmqtt_store::gpt::{self, DataPartition, Table};
use urmqtt_store::layout::{FileKind, Layout, RegionKind, SECTOR};
use urmqtt_store::part::Partition;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{BlockDevice, Disk, IoError, Opened, Platform};

const S: usize = SECTOR as usize;

// --- block devices ---------------------------------------------------------

/// An image file or block device. Writes need `--write`.
struct FileDisk {
    f: Arc<Mutex<File>>,
    sectors: u64,
    writable: bool,
}

impl FileDisk {
    fn open(path: &str, writable: bool) -> Result<Self, String> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)
            .map_err(|e| format!("{path}: {e}"))?;
        let bytes = f
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("{path}: {e}"))?;
        if bytes == 0 || bytes % SECTOR != 0 {
            return Err(format!(
                "{path}: {bytes} bytes is not a whole number of 512-byte sectors (on macOS use /dev/rdiskN)"
            ));
        }
        Ok(Self {
            f: Arc::new(Mutex::new(f)),
            sectors: bytes / SECTOR,
            writable,
        })
    }
}

impl BlockDevice for FileDisk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        if lba + (buf.len() / S) as u64 > self.sectors {
            return Err(IoError::OutOfRange);
        }
        let mut f = self.f.lock().map_err(|_| IoError::Device)?;
        f.seek(SeekFrom::Start(lba * SECTOR))
            .and_then(|_| f.read_exact(buf))
            .map_err(|_| IoError::Device)
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        if !self.writable {
            return Err(IoError::Device);
        }
        if lba + (buf.len() / S) as u64 > self.sectors {
            return Err(IoError::OutOfRange);
        }
        let mut f = self.f.lock().map_err(|_| IoError::Device)?;
        f.seek(SeekFrom::Start(lba * SECTOR))
            .and_then(|_| f.write_all(buf))
            .map_err(|_| IoError::Device)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if !self.writable {
            return Ok(());
        }
        self.f
            .lock()
            .map_err(|_| IoError::Device)?
            .sync_all()
            .map_err(|_| IoError::Device)
    }
}

/// Copy-on-write over a read-only device: writes stay in memory.
struct Overlay {
    base: FileDisk,
    dirty: Arc<Mutex<BTreeMap<u64, Box<[u8; S]>>>>,
}

impl BlockDevice for Overlay {
    fn sectors(&self) -> u64 {
        self.base.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.base.read(lba, buf)?;
        let d = self.dirty.lock().map_err(|_| IoError::Device)?;
        for (i, chunk) in buf.chunks_mut(S).enumerate() {
            if let Some(s) = d.get(&(lba + i as u64)) {
                chunk.copy_from_slice(&s[..]);
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        if lba + (buf.len() / S) as u64 > self.base.sectors {
            return Err(IoError::OutOfRange);
        }
        let mut d = self.dirty.lock().map_err(|_| IoError::Device)?;
        for (i, chunk) in buf.chunks(S).enumerate() {
            let mut s = Box::new([0u8; S]);
            s.copy_from_slice(chunk);
            d.insert(lba + i as u64, s);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

// --- the disk's structure ----------------------------------------------------

struct Found {
    primary: Option<Table>,
    backup: Option<Table>,
    data: Option<DataPartition>,
}

fn inspect(dev: &mut dyn BlockDevice) -> Result<Found, String> {
    let io = |e: IoError| format!("read failed: {e:?}");
    let primary = gpt::read_table(dev, 1).map_err(io)?;
    let backup_lba = primary
        .as_ref()
        .map_or(dev.sectors() - 1, |t| t.header.backup_lba);
    let backup = gpt::read_table(dev, backup_lba).map_err(io)?;
    let data = primary
        .as_ref()
        .or(backup.as_ref())
        .and_then(Table::data_partition)
        .map(|e| DataPartition {
            first_lba: e.first_lba,
            last_lba: e.last_lba,
            unique_guid: e.unique_guid,
        });
    Ok(Found {
        primary,
        backup,
        data,
    })
}

fn mib(sectors: u64) -> u64 {
    (sectors * SECTOR) >> 20
}

fn name(e: &gpt::Entry) -> String {
    let u: Vec<u16> = e
        .name
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&x| x != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

fn open_layout(part: Partition) -> Result<Disk, String> {
    match Disk::open(Box::new(part), || [0; 16]) {
        Ok((d, Opened::Existing)) => Ok(d),
        Ok((_, Opened::Formatted)) => Err("the data partition is blank (never booted)".into()),
        Err(e) => Err(format!("data partition layout: {e:?}")),
    }
}

fn data_part(path: &str, dev: Box<dyn BlockDevice>, f: &Found) -> Result<Partition, String> {
    let d = f.data.ok_or_else(|| {
        format!("{path}: no urMQTT data partition (the image has not been booted yet)")
    })?;
    Partition::new(dev, d.first_lba, d.sectors())
        .ok_or_else(|| format!("{path}: data partition beyond the end of the disk"))
}

fn overlay(path: &str) -> Result<(Overlay, Found), String> {
    let mut base = FileDisk::open(path, false)?;
    let found = inspect(&mut base)?;
    Ok((
        Overlay {
            base,
            dirty: Arc::default(),
        },
        found,
    ))
}

// --- SQLite on the host --------------------------------------------------------

fn platform() -> Platform {
    Platform {
        random: |b| {
            if let Ok(mut f) = File::open("/dev/urandom") {
                let _ = f.read_exact(b);
            }
        },
        now_unix_ms: || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64)
        },
        delay_us: |us| std::thread::sleep(std::time::Duration::from_micros(u64::from(us))),
        log: |code, msg| {
            if code & 0xff != 27 && code & 0xff != 28 {
                eprintln!("sqlite ({code}): {msg}");
            }
        },
    }
}

fn open_store(disk: Disk) -> Result<urmqtt_store::Store, String> {
    let heap: &'static mut [u8] = Box::leak(vec![0u8; 256 << 20].into_boxed_slice());
    urmqtt_store::init(heap, disk, platform()).map_err(|e| e.to_string())?;
    urmqtt_store::open()
        .map(|(s, _)| s)
        .map_err(|e| e.to_string())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// --- commands ------------------------------------------------------------------

fn info(path: &str) -> Result<(), String> {
    let (mut dev, f) = overlay(path)?;
    let total = dev.sectors();
    println!("disk: {path}, {} MiB ({total} sectors)", mib(total));
    let Some(t) = f.primary.as_ref().or(f.backup.as_ref()) else {
        println!("gpt: none (not a urMQTT boot disk)");
        return Ok(());
    };
    println!(
        "gpt: disk GUID {}, primary {}, backup {} at LBA {}",
        t.header.disk_guid,
        if f.primary.is_some() {
            "valid"
        } else {
            "INVALID"
        },
        if f.backup.is_some() {
            "valid"
        } else {
            "INVALID"
        },
        t.header.backup_lba
    );
    for (i, e) in t.entries.iter().enumerate() {
        let kind = if e.type_guid == gpt::ESP_TYPE {
            "EFI system partition"
        } else if e.type_guid == gpt::DATA_TYPE {
            "urMQTT data"
        } else {
            "other"
        };
        println!(
            "  {}: {kind} \"{}\" LBA {}..{} ({} MiB), GUID {}",
            i + 1,
            name(e),
            e.first_lba,
            e.last_lba,
            mib(e.sectors()),
            e.unique_guid
        );
    }
    let Some(d) = f.data else {
        println!("data: no data partition yet (created on the first boot)");
        return Ok(());
    };
    let part = data_part(path, Box::new(dev.clone_ro()?), &f)?;
    match open_layout(part) {
        Ok(disk) => {
            let l: &Layout = disk.layout();
            println!(
                "data: layout v{} uuid {}, formatted {} sectors",
                urmqtt_store::layout::VERSION,
                l.uuid
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                l.total_sectors
            );
            for r in &l.regions {
                println!(
                    "  region {:?}: LBA {}..{} of the partition ({} MiB)",
                    r.kind,
                    r.start,
                    r.start + r.sectors - 1,
                    mib(r.sectors)
                );
            }
            for k in [FileKind::Db, FileKind::Wal, FileKind::Journal] {
                println!("  file {k:?}: {} bytes", disk.file_size(k));
            }
        }
        Err(e) => println!("data: partition at LBA {}: {e}", d.first_lba),
    }
    let _ = &mut dev;
    Ok(())
}

impl Overlay {
    /// A second read-only view of the same file (for a partition window).
    fn clone_ro(&self) -> Result<Overlay, String> {
        Ok(Overlay {
            base: FileDisk {
                f: self.base.f.clone(),
                sectors: self.base.sectors,
                writable: false,
            },
            dirty: self.dirty.clone(),
        })
    }
}

fn verify(path: &str) -> Result<(), String> {
    let (dev, f) = overlay(path)?;
    let mut problems = Vec::new();
    match (&f.primary, &f.backup) {
        (Some(p), Some(b)) => {
            if p.entries != b.entries || p.header.disk_guid != b.header.disk_guid {
                problems.push("gpt: primary and backup disagree".to_string());
            }
        }
        (None, Some(_)) => problems.push("gpt: primary invalid (the next boot repairs it)".into()),
        (Some(_), None) => problems.push("gpt: backup invalid".into()),
        (None, None) => return Err("gpt: no valid table: not a urMQTT boot disk".into()),
    }
    println!("gpt: ok");
    let part = data_part(path, Box::new(dev.clone_ro()?), &f)?;
    let mut disk = open_layout(part)?;
    println!("layout: ok ({} regions)", disk.layout().regions.len());
    let retention_ms = u64::MAX / 4;
    match TelemetryLog::open(&mut disk, now_unix(), retention_ms) {
        Ok((_, rec)) => {
            println!(
                "telemetry: ok, {} record(s) in {} segment(s), {} torn tail(s)",
                rec.records, rec.segments, rec.torn_tails
            );
            if rec.torn_tails > 0 {
                problems.push(format!(
                    "telemetry: {} torn tail(s) (the next boot truncates them)",
                    rec.torn_tails
                ));
            }
        }
        Err(e) => problems.push(format!("telemetry: {e:?}")),
    }
    let store = open_store(disk)?;
    let qc = store
        .db()
        .query_text("PRAGMA integrity_check")
        .map_err(|e| e.to_string())?;
    if qc == "ok" {
        println!("sqlite: integrity_check ok");
    } else {
        problems.push(format!("sqlite: integrity_check: {qc}"));
    }
    if problems.is_empty() {
        println!("verify: ok");
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn export_db(path: &str, out: &str) -> Result<(), String> {
    let (dev, f) = overlay(path)?;
    let part = data_part(path, Box::new(dev.clone_ro()?), &f)?;
    let store = open_store(open_layout(part)?)?;
    store
        .db()
        .exec("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|e| e.to_string())?;
    let bytes = urmqtt_store::vfs::with_disk(|d| {
        let n = d.file_size(FileKind::Db);
        let mut buf = vec![0u8; n as usize];
        d.read_at(RegionKind::Db, 0, &mut buf).map(|()| buf)
    })
    .ok_or("store not installed")?
    .map_err(|e| format!("reading the database: {e:?}"))?;
    drop(store);
    std::fs::write(out, &bytes).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "export-db: {out}: {} bytes, WAL applied (in memory; {path} unchanged)",
        bytes.len()
    );
    Ok(())
}

fn matches(filter: &str, topic: &str) -> bool {
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn export_telemetry(path: &str, args: &[String]) -> Result<(), String> {
    let (mut format, mut since, mut until, mut topic) = ("csv".to_string(), 0u64, u64::MAX, None);
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let mut v = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{k} needs a value"))
        };
        match k.as_str() {
            "--format" => format = v()?,
            "--since" => since = v()?.parse().map_err(|e| format!("--since: {e}"))?,
            "--until" => until = v()?.parse().map_err(|e| format!("--until: {e}"))?,
            "--topic" => topic = Some(v()?),
            _ => return Err(format!("unknown option {k}")),
        }
    }
    if format != "csv" && format != "jsonl" {
        return Err("--format csv|jsonl".into());
    }
    let (dev, f) = overlay(path)?;
    let part = data_part(path, Box::new(dev.clone_ro()?), &f)?;
    let mut disk = open_layout(part)?;
    let retention = u64::MAX / 4;
    let (log, _) = TelemetryLog::open(&mut disk, now_unix(), retention)
        .map_err(|e| format!("telemetry: {e:?}"))?;
    let mut rows: Vec<(u64, usize, String, Vec<u8>)> = Vec::new();
    for p in 0..urmqtt_store::telemetry::PARTITIONS {
        log.scan(&mut disk, p, retention, |r| {
            let keep = r.ts_ms >= since
                && r.ts_ms < until
                && topic.as_deref().is_none_or(|t| matches(t, r.topic));
            if keep {
                rows.push((r.ts_ms, p, r.topic.to_string(), r.payload.to_vec()));
            }
        })
        .map_err(|e| format!("telemetry partition {p}: {e:?}"))?;
    }
    rows.sort_by_key(|r| r.0);
    let mut out = std::io::stdout().lock();
    if format == "csv" {
        let _ = writeln!(out, "ts_ms,partition,topic,payload");
    }
    for (ts, p, t, payload) in &rows {
        let text = String::from_utf8_lossy(payload);
        let _ = if format == "csv" {
            writeln!(out, "{ts},{p},{},{}", csv_field(t), csv_field(&text))
        } else {
            writeln!(
                out,
                "{{\"ts_ms\":{ts},\"partition\":{p},\"topic\":{},\"payload\":{}}}",
                json_str(t),
                json_str(&text)
            )
        };
    }
    eprintln!("export-telemetry: {} record(s)", rows.len());
    Ok(())
}

fn import_devices(path: &str, file: &str, allowlist: bool, write: bool) -> Result<(), String> {
    if !write {
        return Err("import-devices changes the disk: add --write (with the VM stopped)".into());
    }
    let ids: Vec<String> =
        std::io::BufReader::new(File::open(file).map_err(|e| format!("{file}: {e}"))?)
            .lines()
            .map_while(Result::ok)
            .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
    for id in &ids {
        if id.is_empty()
            || id.contains(['/', '+', '#', '\0'])
            || id.starts_with('$')
            || id.len() > 128
        {
            return Err(format!("{file}: {id:?} is not a valid device id"));
        }
    }
    let mut dev = FileDisk::open(path, true)?;
    let f = inspect(&mut dev)?;
    let part = data_part(path, Box::new(dev), &f)?;
    let mut store = open_store(open_layout(part)?)?;
    let now = now_unix() as i64;
    store.begin().map_err(|e| e.to_string())?;
    for id in &ids {
        store.device_seen(id, now).map_err(|e| e.to_string())?;
        if allowlist {
            store.allow(id, 0, now).map_err(|e| e.to_string())?;
        }
    }
    store.commit().map_err(|e| e.to_string())?;
    store
        .db()
        .exec("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|e| e.to_string())?;
    urmqtt_store::vfs::with_disk(|d| d.sync())
        .ok_or("store not installed")?
        .map_err(|e| format!("{e:?}"))?;
    eprintln!(
        "import-devices: {} device(s) imported{}",
        ids.len(),
        if allowlist { " and allowlisted" } else { "" }
    );
    Ok(())
}

fn parse_size(s: &str) -> Result<u64, String> {
    let (n, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&s[..s.len() - 1], 1 << 20),
        Some('G' | 'g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    n.parse::<u64>()
        .map(|v| v * mult)
        .map_err(|e| format!("size {s:?}: {e}"))
}

fn create(out: &str, esp: &str, size: Option<u64>) -> Result<(), String> {
    let esp = std::fs::read(esp).map_err(|e| format!("{esp}: {e}"))?;
    let img = gpt::raw_image(&esp).ok_or("the ESP must be a non-empty multiple of 512 bytes")?;
    if size.is_some_and(|s| s < img.len() as u64) {
        return Err(format!("--size is below the image's {} bytes", img.len()));
    }
    let mut f = File::create(out).map_err(|e| format!("{out}: {e}"))?;
    f.write_all(&img).map_err(|e| format!("{out}: {e}"))?;
    if let Some(s) = size {
        f.set_len(s).map_err(|e| format!("{out}: {e}"))?;
    }
    eprintln!(
        "create: {out}: {} bytes ({} MiB of image, mkraw.py-identical){}",
        size.unwrap_or(img.len() as u64),
        img.len() >> 20,
        if size.is_some() {
            "; the first boot creates the data partition"
        } else {
            ""
        }
    );
    Ok(())
}

fn update_boot(path: &str, esp: &str, write: bool) -> Result<(), String> {
    let esp = std::fs::read(esp).map_err(|e| format!("{esp}: {e}"))?;
    let mut dev = FileDisk::open(path, write)?;
    let f = inspect(&mut dev)?;
    let t = f.primary.as_ref().ok_or("no valid primary GPT")?;
    let e = t
        .entries
        .iter()
        .find(|e| e.type_guid == gpt::ESP_TYPE)
        .ok_or("no EFI system partition")?;
    let room = e.sectors() * SECTOR;
    if esp.is_empty() || esp.len() % S != 0 || esp.len() as u64 > room {
        return Err(format!(
            "the new ESP ({} bytes) must be whole sectors and fit the old one ({room} bytes)",
            esp.len()
        ));
    }
    if !write {
        println!(
            "update-boot: would write {} bytes at LBA {} (dry run; add --write)",
            esp.len(),
            e.first_lba
        );
        return Ok(());
    }
    dev.write(e.first_lba, &esp)
        .map_err(|e| format!("write: {e:?}"))?;
    dev.flush().map_err(|e| format!("flush: {e:?}"))?;
    eprintln!("update-boot: {path}: ESP replaced, data partition kept");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let opt = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let pos: Vec<&String> = {
        let mut v = Vec::new();
        let mut skip = false;
        for a in args {
            if skip {
                skip = false;
                continue;
            }
            if a.starts_with("--") {
                skip = !matches!(a.as_str(), "--write" | "--allowlist");
                continue;
            }
            v.push(a);
        }
        v
    };
    let arg = |i: usize, what: &str| {
        pos.get(i)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("missing {what}"))
    };
    match pos.first().map(|s| s.as_str()) {
        Some("info") => info(arg(1, "DISK")?),
        Some("verify") => verify(arg(1, "DISK")?),
        Some("export-db") => export_db(arg(1, "DISK")?, arg(2, "OUT")?),
        Some("export-telemetry") => {
            let i = args
                .iter()
                .position(|a| a.starts_with("--"))
                .unwrap_or(args.len());
            export_telemetry(arg(1, "DISK")?, &args[i..])
        }
        Some("import-devices") => import_devices(
            arg(1, "DISK")?,
            arg(2, "FILE")?,
            flag("--allowlist"),
            flag("--write"),
        ),
        Some("create") => create(
            arg(1, "OUT")?,
            &opt("--esp").ok_or("--esp ESP is required")?,
            opt("--size").map(|s| parse_size(&s)).transpose()?,
        ),
        Some("update-boot") => update_boot(
            arg(1, "DISK")?,
            &opt("--esp").ok_or("--esp ESP is required")?,
            flag("--write"),
        ),
        _ => {
            print!(
                "{}",
                include_str!("main.rs")
                    .lines()
                    .take_while(|l| l.starts_with("//!"))
                    .map(|l| format!(
                        "{}\n",
                        l.trim_start_matches("//!").strip_prefix(' ').unwrap_or("")
                    ))
                    .collect::<String>()
            );
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("urmqtt-disk: {e}");
            ExitCode::FAILURE
        }
    }
}
