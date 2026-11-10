//! `urmqtt-disk`: offline work on a urMQTT boot disk (STORAGE-PLAN S1, S2,
//! S3): an image file or a block device, on macOS or Linux, with the VM
//! stopped.
//!
//! ```text
//! urmqtt-disk info DISK                          GPT, data partition, layout, file sizes, migration record
//! urmqtt-disk verify DISK                        every check; non-zero exit on any error
//! urmqtt-disk export-db DISK OUT.sqlite          the database with its WAL applied
//! urmqtt-disk export-telemetry DISK [--format csv|jsonl] [--since MS] [--until MS] [--topic FILTER]
//! urmqtt-disk import-devices DISK FILE [--allowlist] --write
//!                                                device ids, one per line, into the registry
//!                                                (and the allowlist)
//! urmqtt-disk create OUT --esp ESP [--size BYTES[K|M|G]] [--config BLOB|SLOT]
//!                                                a boot image (byte for byte mkraw.py), optionally
//!                                                on a larger disk, optionally configured; the first
//!                                                boot formats the data
//! urmqtt-disk update-boot DISK --esp ESP --write [--config BLOB|SLOT | --keep-config | --replace-config]
//!                    [--allow-unsealed]
//!                                                replace the kernel (ESP), keep the data. The disk's
//!                                                configuration slot (C1c) is kept whenever it holds a
//!                                                real configuration (the default, whatever the new ESP
//!                                                carries); --config sets one, --replace-config takes
//!                                                the new ESP's own
//! urmqtt-disk slots status DISK                  the two boot slots of an A/B disk (v0.6.0, NEXT-11):
//!                                                region, release, state, the disk GUID the control
//!                                                messages name
//! urmqtt-disk slots stage DISK (--image RELEASE.img --sums SHA256SUMS --sig SHA256SUMS.minisig
//!                    --pubkey minisign.pub [--pubkey ...] | --esp ESP --unsigned | --image IMG --unsigned)
//!                    [--config BLOB|SLOT | --keep-config | --replace-config] [--allow-downgrade]
//!                    [--allow-unsealed] --write
//!                                                write the standby slot (the configuration is carried
//!                                                over as update-boot does); the data is not touched.
//!                                                A disk sealed for Secure Boot (ADR-320) takes only a
//!                                                sealed ESP unless --allow-unsealed
//! urmqtt-disk slots activate DISK [--tries N] [--one-way] [--retry] [--allow-downgrade] --write
//!                                                make the staged slot the boot entry, on trial: it must
//!                                                confirm itself (or an operator confirms it) within
//!                                                N boots (default 3), else the previous slot returns
//! urmqtt-disk slots confirm DISK --write          confirm the slot on trial
//! urmqtt-disk slots rollback DISK --write         go back to the previous slot (the slot left is marked bad)
//!                                                Without --write every slots command rehearses on an
//!                                                in-memory overlay and changes nothing
//! urmqtt-disk migrate DISK [--write] [--resume | --rollback [--force]]
//!                    [--rollback-file FILE] [--align-mib N]
//!                                                layout v1 -> v2. Without --write: the plan and the
//!                                                preconditions, nothing is changed. --resume finishes
//!                                                an interrupted run, --rollback returns to v1
//! urmqtt-disk grow DISK [--ratio PERCENT] [--write]
//!                                                use the space a larger disk offers (the kernel does
//!                                                the same at boot): partition table, then layout.
//!                                                Without --write: what would change
//! urmqtt-disk backup DISK [--write]              take an in-disk backup now (S5), adding the backup
//!                                                region first if the layout has none. Without --write
//!                                                the whole run happens on an in-memory overlay
//! urmqtt-disk backup-extract DISK OUT [--slot N] write the newest intact snapshot (or slot N) as an
//!                                                SQLite file; the disk is not changed
//! urmqtt-disk scrub DISK                         one scrub pass (S6) over the database, the backups and
//!                                                the telemetry ring, as the broker's idle scrubber does
//!                                                it; non-zero exit if it finds damage. Read-only
//! urmqtt-disk backup-restore DISK --write        replace the database by the newest intact snapshot
//!                                                (the kernel does the same at boot when the database
//!                                                is corrupt and storage.auto_restore is on)
//! urmqtt-disk encrypt DISK --key-new FILE --write [--resume] [--journal FILE]
//! urmqtt-disk decrypt DISK --key FILE --write [--resume] [--journal FILE]
//! urmqtt-disk rekey DISK --key FILE --key-new FILE --write [--resume] [--journal FILE]
//!                                                encryption at rest (S7): AES-256-XTS over the whole
//!                                                data partition, offline. The VM must be stopped. The
//!                                                disk is refused by the kernel until a run that was cut
//!                                                is resumed (--resume, same keys); the journal (default
//!                                                DISK.convert-journal) must be kept until then. Without
//!                                                --write the run happens on an in-memory overlay. A
//!                                                conversion empties the key slots (they wrap the old key)
//! urmqtt-disk keys DISK                          the key slots (LATER-7): the disk key wrapped under
//!                                                passphrases, not in the image; no key needed
//! urmqtt-disk keys DISK add (--key FILE | --passphrase-file FILE) --new-passphrase-file FILE
//!                    [--slot N] [--iterations N] --write
//!                                                wrap the key under a new passphrase (an image-key disk
//!                                                becomes one for storage.disk_key_source = "console")
//! urmqtt-disk keys DISK change (--key FILE | --passphrase-file FILE) --new-passphrase-file FILE
//!                    [--slot N] [--iterations N] --write
//!                                                a new passphrase for a slot (the one the old one opens)
//! urmqtt-disk keys DISK remove --slot N (--key FILE | --passphrase-file FILE) --write
//!                                                empty a slot (never the last)
//! urmqtt-disk keys DISK unwrap (--key FILE | --passphrase-file FILE --key-out FILE) --write
//!                                                empty every slot: the key must come from the image
//!                                                again (storage.disk_key; the way back to v0.5)
//!                                                Key changes rewrite the superblock only (two writes,
//!                                                each flushed); without --write on an overlay
//! ```
//!
//! `--key FILE` goes with every other command that reads an encrypted disk
//! (`info`, `verify`, `export-*`, `scrub`, `backup*`, `grow`, `import-devices`):
//! 64 raw bytes or 128 hex digits. `--passphrase-file FILE` instead opens a
//! disk whose key is in its key slots (LATER-7): the file's bytes without
//! one final newline.
//!
//! Test hooks (images only): `fixture-v1 DISK [--populate] --write` builds a
//! layout-v1 data partition (the kernel only reads v2), and `--fault SPEC`
//! on a writing command stops the device after the N-th write
//! (`stop-after-write=N`, `tear-write=N:K`, see `urmqtt_store::fault`).
//!
//! Everything is read-only unless `--write` is given. Commands that only
//! read but need SQLite or the telemetry recovery to run (`verify`,
//! `export-*`) work on an in-memory copy-on-write overlay, so the disk is
//! never changed.

use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use urmqtt_disk::config;
use urmqtt_disk::convert::{self, FileJournal, Key, MemJournal};
use urmqtt_disk::dev::{FileDisk, Overlay, S, Shared};
use urmqtt_disk::host::{self, mib, now_unix, open_store};
use urmqtt_disk::keys;
use urmqtt_disk::migrate;
use urmqtt_disk::slots as ab;
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::gpt::{self, DataPartition, Table};
use urmqtt_store::layout::{FileKind, Layout, LayoutError, RegionKind, SECTOR, v1};
use urmqtt_store::part::Partition;
use urmqtt_store::slots;
use urmqtt_store::telemetry::TelemetryLog;
use urmqtt_store::{BlockDevice, Disk, DiskError, IoError, Opened};

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

fn name(e: &gpt::Entry) -> String {
    let u: Vec<u16> = e
        .name
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&x| x != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

const V1_HINT: &str = "the data partition is layout v1; this tool and the kernel need v2: run `urmqtt-disk migrate DISK` (docs/DEPLOY.md)";

/// The disk key given with `--key FILE`, for every command that opens the
/// data partition.
static KEY: std::sync::OnceLock<Key> = std::sync::OnceLock::new();

fn key_error(e: DiskError) -> Option<String> {
    Some(match e {
        DiskError::KeyRequired => {
            "the data partition is encrypted: give its key with --key FILE".into()
        }
        DiskError::WrongKey => "the key does not match this disk (--key FILE)".into(),
        DiskError::NotEncrypted => {
            "the data partition is not encrypted: leave out --key".into()
        }
        DiskError::ConversionPending => "an encrypt, decrypt or rekey run was interrupted: run it again with --resume and the same keys".into(),
        _ => return None,
    })
}

fn load_key(path: &str) -> Result<Key, String> {
    let b = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    urmqtt_store::crypt::parse_key(&b).map_err(|e| {
        format!("{path}: not a usable disk key ({e:?}): 64 raw bytes or 128 hex digits, two different halves")
    })
}

fn open_layout(part: Partition) -> Result<Disk, String> {
    match Disk::open_keyed(Box::new(part), || [0; 16], 8, KEY.get()) {
        Ok((d, Opened::Existing)) => Ok(d),
        Ok((_, Opened::Formatted)) => Err("the data partition is blank (never booted)".into()),
        Err(DiskError::Layout(LayoutError::OldVersion(_))) => Err(V1_HINT.into()),
        Err(e) => Err(key_error(e).unwrap_or_else(|| format!("data partition layout: {e:?}"))),
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
    Ok((Overlay::new(Box::new(base)), found))
}

/// A device for a writing command: the file or block device, wrapped in the
/// fault injector when `--fault` is given.
fn writable(path: &str, fault: Option<&str>) -> Result<Box<dyn BlockDevice>, String> {
    let f = FileDisk::open(path, true)?;
    match fault {
        None => Ok(Box::new(f)),
        Some(spec) => {
            let spec =
                FaultSpec::parse(spec).ok_or("--fault: see urmqtt_store::fault::FaultSpec")?;
            eprintln!("urmqtt-disk: injecting {spec:?} (test hook)");
            Ok(Box::new(FaultDevice::new(Box::new(f), spec)))
        }
    }
}

fn random() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b
}

// --- commands ------------------------------------------------------------------

fn print_regions(l: &Layout) {
    for r in &l.regions {
        println!(
            "  region {:?}: LBA {}..{} of the partition ({} MiB)",
            r.kind,
            r.start,
            r.start + r.sectors - 1,
            mib(r.sectors)
        );
    }
}

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
    if let Some(e) = t.entries.iter().find(|e| e.type_guid == gpt::ESP_TYPE) {
        match read_esp(&mut dev, e) {
            Ok(esp) => println!(
                "{}\n{}",
                config::describe(&config::read(&esp)),
                config::describe_seal(&esp)
            ),
            Err(m) => println!("config: unreadable ({m})"),
        }
    }
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
    let mut part = data_part(path, Box::new(dev.view()), &f)?;
    match migrate::classify(&mut part) {
        Ok(migrate::Found::V1) => {
            let sb = migrate::read_block(&mut part, 0)?;
            match v1::decode(&sb, part.sectors()) {
                Ok(Some(l)) => {
                    println!(
                        "data: layout v1 (the kernel refuses it; run `urmqtt-disk migrate`), uuid {}, formatted {} sectors",
                        hex(&l.uuid),
                        l.total_sectors
                    );
                    print_regions(&l);
                }
                other => println!("data: layout v1, unreadable: {other:?}"),
            }
        }
        _ => match open_layout(data_part(path, Box::new(dev.view()), &f)?) {
            Ok(disk) => {
                let l: &Layout = disk.layout();
                println!(
                    "data: layout v{} generation {} (superblock slot {}), uuid {}, formatted {} sectors of {} in the partition",
                    urmqtt_store::layout::VERSION,
                    l.generation,
                    if disk.sb_slot() == 0 { "A" } else { "B" },
                    hex(&l.uuid),
                    l.total_sectors,
                    d.sectors()
                );
                println!(
                    "  {} telemetry partition(s), regions aligned to {} KiB{}",
                    l.partitions,
                    l.align_sectors / 2,
                    if l.legacy_telemetry() {
                        " (the telemetry ring is a migrated v1 ring: 4 KiB aligned)"
                    } else {
                        ""
                    }
                );
                print_regions(l);
                for k in [FileKind::Db, FileKind::Wal, FileKind::Journal] {
                    println!("  file {k:?}: {} bytes", disk.file_size(k));
                }
                if disk.spare_sectors() >= 2048 {
                    println!(
                        "  {} MiB of the partition are not in the layout (the next boot, or `grow`, adds them)",
                        mib(disk.spare_sectors())
                    );
                }
                let mut disk = disk;
                for line in backup_report(&mut disk).0 {
                    println!("  {line}");
                }
                if let Ok((log, _)) = TelemetryLog::open(&mut disk, now_unix(), u64::MAX / 4) {
                    let seg = log.segment_bytes();
                    println!(
                        "  telemetry ring: {} partition(s) of {} segment(s) of {} KiB each (the ring's first byte is 4 KiB into the telemetry region)",
                        log.partitions(),
                        log.capacity_bytes() / seg.saturating_sub(512).max(1),
                        seg >> 10
                    );
                }
            }
            Err(e) => println!("data: partition at LBA {}: {e}", d.first_lba),
        },
    }
    if let Ok(Some(r)) = migrate::read_record(&mut part) {
        println!("migration record: state {} (seq {})", r.state, r.seq);
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
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
    let mut raw = data_part(path, Box::new(dev.view()), &f)?;
    let mut disk = match migrate::classify(&mut raw)? {
        migrate::Found::V1 => {
            // Checked as far as the old layout allows, but the kernel
            // refuses it: that is a problem too.
            problems.push(V1_HINT.to_string());
            let part = data_part(path, Box::new(dev.view()), &f)?;
            Disk::open_v1(Box::new(part)).map_err(|e| format!("layout v1: {e:?}"))?
        }
        _ => open_layout(data_part(path, Box::new(dev.view()), &f)?)?,
    };
    println!(
        "layout: ok ({} regions, generation {})",
        disk.layout().regions.len(),
        disk.layout().generation
    );
    match host::telemetry_digest(&mut disk) {
        Ok(t) => {
            println!(
                "telemetry: ok, {} record(s) in {} segment(s), {} torn tail(s)",
                t.records, t.segments, t.torn_tails
            );
            if t.torn_tails > 0 {
                problems.push(format!(
                    "telemetry: {} torn tail(s) (the next boot truncates them)",
                    t.torn_tails
                ));
            }
        }
        Err(e) => problems.push(e),
    }
    let (lines, bad) = backup_report(&mut disk);
    for l in lines {
        println!("{l}");
    }
    problems.extend(bad);
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
    let part = data_part(path, Box::new(dev.view()), &f)?;
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
    write_private(out, &bytes)?;
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
    let part = data_part(path, Box::new(dev.view()), &f)?;
    let mut disk = open_layout(part)?;
    let retention = u64::MAX / 4;
    let (log, _) = TelemetryLog::open(&mut disk, now_unix(), retention)
        .map_err(|e| format!("telemetry: {e:?}"))?;
    let mut rows: Vec<(u64, usize, String, Vec<u8>)> = Vec::new();
    for p in 0..log.partitions() {
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

fn create(out: &str, esp: &str, size: Option<u64>, config: Option<&str>) -> Result<(), String> {
    let esp = std::fs::read(esp).map_err(|e| format!("{esp}: {e}"))?;
    let esp = match config {
        None => esp,
        Some(c) => {
            let slot = config::slot_from_file(&std::fs::read(c).map_err(|e| format!("{c}: {e}"))?)?;
            // A fresh image has nothing to keep: the new ESP's slot is replaced.
            let (esp, what) = config::carry_over(&[], esp, &config::Policy::Set(slot))?;
            eprintln!("create: {what}");
            esp
        }
    };
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

/// The whole EFI system partition `e` of `dev`.
fn read_esp(dev: &mut dyn BlockDevice, e: &gpt::Entry) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; (e.sectors() * SECTOR) as usize];
    let chunk = 2048 * S; // 1 MiB
    for (i, c) in buf.chunks_mut(chunk).enumerate() {
        dev.read(e.first_lba + (i * 2048) as u64, c)
            .map_err(|err| format!("read failed: {err:?}"))?;
    }
    Ok(buf)
}

fn update_boot(
    path: &str,
    esp: &str,
    write: bool,
    in_place: bool,
    allow_unsealed: bool,
    policy: &config::Policy,
) -> Result<(), String> {
    let esp = std::fs::read(esp).map_err(|e| format!("{esp}: {e}"))?;
    let mut dev = FileDisk::open(path, write)?;
    // An A/B disk (ADR-299): the running slot would be overwritten in place,
    // with no way back if the new kernel fails.
    let ab = matches!(slots::read(&mut dev), Ok(Some(_)));
    if let Ok(Some(s)) = slots::read(&mut dev) {
        if !in_place {
            return Err(format!(
                "this disk has two boot slots: update it with `urmqtt-disk slots stage` and `slots activate` (the old kernel stays as the way back); --in-place overwrites the running slot {} anyway",
                s.letter(&s.active())
            ));
        }
        if s.active().state.trial {
            return Err(ab::slot_error(&slots::SlotError::TrialPending));
        }
    }
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
    // The configuration slot (C1c): carried over from the disk's current ESP
    // unless the new ESP is configured itself (or the caller says otherwise).
    let old = read_esp(&mut dev, e)?;
    let (esp, what) = config::carry_over(&old, esp, policy)?;
    if let Some(w) = config::keep_sealed(&old, &esp, allow_unsealed)? {
        eprintln!("update-boot: {w}");
    }
    println!(
        "update-boot: {}\nupdate-boot: before: {}\nupdate-boot: after:  {}\nupdate-boot: {}",
        what,
        config::describe(&config::read(&old)),
        config::describe(&config::read(&esp)),
        config::describe_seal(&esp),
    );
    if !write {
        println!(
            "update-boot: would write {} bytes at LBA {} (dry run; add --write)",
            esp.len(),
            e.first_lba
        );
        return Ok(());
    }
    let note = slots::find_notes(&esp).into_iter().next();
    dev.write(e.first_lba, &esp)
        .map_err(|e| format!("write: {e:?}"))?;
    dev.flush().map_err(|e| format!("flush: {e:?}"))?;
    eprintln!("update-boot: {path}: ESP replaced, data partition kept");
    if ab {
        // The slot's label, schema and commitment follow its new bytes
        // (ADR-299): a stale commitment would make it unusable as the way
        // back after the next activation.
        let label = note.as_ref().map_or("in-place", |n| n.version.as_str());
        let schema = note
            .as_ref()
            .and_then(|n| u8::try_from(n.schema).ok())
            .unwrap_or(0);
        slots::reseal_active(&mut dev, label, schema).map_err(|e| ab::slot_error(&e))?;
        eprintln!(
            "update-boot: the active slot now records {label} and a commitment to its new bytes"
        );
    }
    Ok(())
}

// --- A/B boot slots (NEXT-11) ---------------------------------------------------------

/// The options of `urmqtt-disk slots`.
struct SlotArgs {
    write: bool,
    fault: Option<String>,
    image: Option<String>,
    esp: Option<String>,
    sums: Option<String>,
    sig: Option<String>,
    pubkeys: Vec<String>,
    unsigned: bool,
    allow_downgrade: bool,
    /// Stage an unsealed ESP onto a disk whose active slot is sealed (ADR-320).
    allow_unsealed: bool,
    tries: u8,
    one_way: bool,
    retry: bool,
    policy: config::Policy,
}

/// The device for a slots command: the disk (through the fault injector)
/// with `--write`, an in-memory overlay otherwise.
fn slot_device(path: &str, a: &SlotArgs) -> Result<Box<dyn BlockDevice>, String> {
    if a.write {
        writable(path, a.fault.as_deref())
    } else {
        Ok(Box::new(Overlay::new(Box::new(FileDisk::open(
            path, false,
        )?))))
    }
}

fn read_slots(dev: &mut dyn BlockDevice) -> Result<slots::Slots, String> {
    // A table write that was cut leaves the two copies different: the next
    // boot repairs that from the primary (in force); so does this, first.
    if matches!(slots::read(dev), Err(slots::SlotError::NeedsRepair)) {
        gpt::prepare(dev, random).map_err(|e| format!("partition table: {e:?}"))?;
        println!(
            "slots: the partition table's copies differed: repaired from the primary (what the next boot does)"
        );
    }
    slots::read(dev)
        .map_err(|e| ab::slot_error(&e))?
        .ok_or_else(|| ab::slot_error(&slots::SlotError::NotAb))
}

/// The store schema on the disk, read on an overlay (opening migrates).
fn disk_store_schema(path: &str) -> Option<u32> {
    let (dev, f) = overlay(path).ok()?;
    let part = data_part(path, Box::new(dev.view()), &f).ok()?;
    let disk = open_layout(part).ok()?;
    host::store_schema(disk).ok()
}

fn slots_status(path: &str) -> Result<(), String> {
    // On an overlay: a table a cut left torn is repaired in memory only.
    let mut dev = Overlay::new(Box::new(FileDisk::open(path, false)?));
    let s = read_slots(&mut dev)?;
    let disk_guid = s.table.header.disk_guid;
    println!(
        "disk GUID {disk_guid} (the --disk-guid of urmqtt-control boot-confirm/boot-rollback)"
    );
    for x in [s.active(), s.standby_slot()] {
        println!("{}", ab::describe(&s, &x));
    }
    let a = s.active();
    if a.state.trial {
        println!(
            "next: the kernel confirms the trial itself (update.confirm = auto) or an operator sends boot-confirm; offline: `urmqtt-disk slots confirm {path} --write` or `slots rollback {path} --write`"
        );
    } else if s.standby_slot().state.sealed && !s.standby_slot().state.bad {
        println!(
            "the standby holds {}: `urmqtt-disk slots activate {path} --write` boots it on trial",
            s.standby_slot().label
        );
    }
    Ok(())
}

fn slots_stage(path: &str, a: &SlotArgs) -> Result<(), String> {
    // 1. The image and what vouches for it.
    let (esp, origin) = match (&a.image, &a.esp) {
        (Some(img), None) => {
            let bytes = std::fs::read(img).map_err(|e| format!("{img}: {e}"))?;
            let origin = if a.unsigned {
                "UNSIGNED image (--unsigned): nothing vouches for it".to_string()
            } else {
                let (Some(sums), Some(sig)) = (&a.sums, &a.sig) else {
                    return Err("--image needs --sums SHA256SUMS --sig SHA256SUMS.minisig --pubkey minisign.pub (or --unsigned for an image you built)".into());
                };
                if a.pubkeys.is_empty() {
                    return Err(
                        "--pubkey minisign.pub is required to check the release signature".into(),
                    );
                }
                let keys = a
                    .pubkeys
                    .iter()
                    .map(|k| std::fs::read_to_string(k).map_err(|e| format!("{k}: {e}")))
                    .collect::<Result<Vec<_>, _>>()?;
                let sums = std::fs::read(sums).map_err(|e| format!("{sums}: {e}"))?;
                let sig = std::fs::read_to_string(sig).map_err(|e| format!("{sig}: {e}"))?;
                let name = std::path::Path::new(img)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("the image path has no file name")?;
                ab::verify_release(name, &bytes, &sums, &sig, &keys)?
            };
            (ab::esp_of_image(&bytes)?, origin)
        }
        (None, Some(e)) => {
            if !a.unsigned {
                return Err("--esp stages an ESP image you built: no release signature covers it; say so with --unsigned (or stage the release's .img with --sums, --sig and --pubkey)".into());
            }
            (
                std::fs::read(e).map_err(|x| format!("{e}: {x}"))?,
                "UNSIGNED ESP image (--esp --unsigned): nothing vouches for it".to_string(),
            )
        }
        _ => return Err("give one of --image IMG or --esp ESP".into()),
    };
    println!("stage: {origin}");
    // 2. What its kernels are.
    let note = ab::note_of(&esp)?;
    println!(
        "stage: kernel {} (A/B protocol {}, store schema {}, configuration formats up to {})",
        note.version, note.ab_protocol, note.schema, note.cfg_format
    );
    // 3. The disk, the configuration to carry over, the rules.
    let db_schema = disk_store_schema(path);
    let mut dev = slot_device(path, a)?;
    let s = read_slots(dev.as_mut())?;
    let active = s.active();
    let old = ab::read_region(dev.as_mut(), active.first_lba, active.sectors())?;
    let (esp, what) = config::carry_over(&old, esp, &a.policy)?;
    if let Some(w) = config::keep_sealed(&old, &esp, a.allow_unsealed)? {
        eprintln!("stage: {w}");
    }
    println!(
        "stage: {what}; the configuration: {}\nstage: {}",
        config::describe(&config::read(&esp)),
        config::describe_seal(&esp)
    );
    if let Some(f) = ab::config_format(&esp)
        && f > note.cfg_format
    {
        return Err(format!(
            "the configuration is format {f}, this kernel reads formats up to {}: it would refuse it at boot",
            note.cfg_format
        ));
    }
    for w in ab::rules(&note, &active, db_schema, a.allow_downgrade)? {
        println!("stage: warning: {w}");
    }
    let schema = u8::try_from(note.schema).map_err(|_| "store schema out of range")?;
    // 4. The write.
    let st =
        slots::stage(dev.as_mut(), &esp, &note.version, schema).map_err(|e| ab::slot_error(&e))?;
    println!(
        "stage: slot {} holds {} now, SHA-256 of the slot {}{}",
        st.slot,
        note.version,
        ab::hex(&st.sha256),
        if a.write {
            format!("; next: `urmqtt-disk slots activate {path} --write`")
        } else {
            " (dry run on an overlay: nothing was written; add --write with the VM stopped)".into()
        }
    );
    Ok(())
}

fn slots_activate(path: &str, a: &SlotArgs) -> Result<(), String> {
    let db_schema = disk_store_schema(path);
    let mut dev = slot_device(path, a)?;
    let s = read_slots(dev.as_mut())?;
    let (active, standby) = (s.active(), s.standby_slot());
    if standby.state.empty || !standby.state.sealed {
        return Err(
            "the standby slot holds nothing staged: `urmqtt-disk slots stage` first".into(),
        );
    }
    let note = slots::Note {
        ab_protocol: slots::AB_PROTOCOL,
        schema: u32::from(standby.state.schema),
        cfg_format: 0,
        version: standby.label.clone(),
    };
    for w in ab::rules(&note, &active, db_schema, a.allow_downgrade)? {
        println!("activate: warning: {w}");
    }
    let needs_one_way = standby.state.schema > active.state.schema;
    if needs_one_way && !a.one_way {
        return Err(format!(
            "{} writes store schema {}, the running {} reads up to {}: once the new kernel has migrated the store there is no way back to the old one. Activate with --one-way to accept that (the automatic return still works until the migration ran)",
            standby.label, standby.state.schema, active.label, active.state.schema
        ));
    }
    let (from, to) = slots::activate(
        dev.as_mut(),
        slots::Activation {
            tries: a.tries,
            one_way: needs_one_way,
            retry: a.retry,
        },
    )
    .map_err(|e| ab::slot_error(&e))?;
    println!(
        "activate: slot {to} ({}) is the boot entry, on trial for {} boot(s); slot {from} ({}) is the way back{}",
        standby.label,
        a.tries.clamp(1, slots::MAX_TRIES),
        active.label,
        if a.write {
            ""
        } else {
            " (dry run on an overlay: nothing was written; add --write with the VM stopped)"
        }
    );
    Ok(())
}

fn slots_confirm(path: &str, a: &SlotArgs) -> Result<(), String> {
    let mut dev = slot_device(path, a)?;
    match slots::confirm(dev.as_mut()).map_err(|e| ab::slot_error(&e))? {
        true => println!(
            "confirm: the active slot is confirmed{}",
            if a.write {
                ""
            } else {
                " (dry run: nothing was written)"
            }
        ),
        false => println!("confirm: the active slot was not on trial: nothing to do"),
    }
    Ok(())
}

fn slots_rollback(path: &str, a: &SlotArgs) -> Result<(), String> {
    let db_schema = disk_store_schema(path);
    let mut dev = slot_device(path, a)?;
    // The way back must read the store as it is now (the kernel marks such a
    // slot bad when it opens the store; this covers a store migrated by a
    // kernel that never got to that point).
    let s = read_slots(dev.as_mut())?;
    let standby = s.standby_slot();
    if let Some(db) = db_schema
        && !standby.state.empty
        && u32::from(standby.state.schema) < db
    {
        return Err(format!(
            "the previous slot's kernel ({}) writes store schema {}, the store on the disk is schema {db}: it would refuse the store (a store migration is one-way). Never allowed",
            standby.label, standby.state.schema
        ));
    }
    let (from, to) = slots::rollback(dev.as_mut()).map_err(|e| ab::slot_error(&e))?;
    println!(
        "rollback: slot {to} is the boot entry again, slot {from} is marked bad{}",
        if a.write {
            ""
        } else {
            " (dry run: nothing was written)"
        }
    );
    Ok(())
}

// --- migrate (S2) ------------------------------------------------------------------

struct MigrateArgs {
    write: bool,
    resume: bool,
    rollback: bool,
    force: bool,
    rollback_file: Option<PathBuf>,
    align_mib: u32,
    fault: Option<String>,
}

fn migrate_cmd(path: &str, a: &MigrateArgs) -> Result<(), String> {
    let opts = migrate::Options {
        align_sectors: a.align_mib * 2048,
        check_db: true,
        force: a.force,
    };
    if !a.write {
        // The plan and the preconditions, on a read-only view.
        if a.resume || a.rollback {
            return Err("--resume and --rollback change the disk: add --write".into());
        }
        let (dev, f) = overlay(path)?;
        let mut raw = data_part(path, Box::new(dev.view()), &f)?;
        match migrate::classify(&mut raw)? {
            migrate::Found::V1 => {}
            migrate::Found::V2 { .. } => {
                return Err("the data partition is layout v2 already".into());
            }
            other => return Err(format!("not a layout-v1 data partition: {other:?}")),
        }
        if let Some(r) = migrate::read_record(&mut raw)? {
            return Err(format!(
                "an earlier migration was interrupted (state {}): use --resume --write or --rollback --write",
                r.state
            ));
        }
        let sb = migrate::read_block(&mut raw, 0)?;
        let plan = migrate::plan(&mut raw, &sb, &opts)?;
        print!("{}", plan.describe());
        let shared = Shared::new(Box::new(data_part(path, Box::new(dev.view()), &f)?));
        for n in migrate::preconditions(&shared, &plan, &opts)? {
            println!("precondition: {n}");
        }
        println!("dry run: nothing was written. Stop the VM, then add --write to migrate.");
        return Ok(());
    }
    let mut dev = writable(path, a.fault.as_deref())?;
    let f = inspect(dev.as_mut())?;
    let d = f.data.ok_or("no urMQTT data partition")?;
    let part =
        Partition::new(dev, d.first_lba, d.sectors()).ok_or("data partition beyond the end")?;
    let shared = Shared::new(Box::new(part));
    let rb = a
        .rollback_file
        .clone()
        .or_else(|| Some(PathBuf::from(format!("{path}.urmqtt-migrate-rollback"))));
    let rep = if a.rollback {
        migrate::rollback(&shared, &opts, rb.as_deref())?
    } else if a.resume {
        migrate::resume(&shared, &opts)?
    } else {
        migrate::run(&shared, &opts, rb.as_deref())?
    };
    for s in &rep.steps {
        println!("migrate: {s}");
    }
    if a.rollback {
        println!("migrate: rolled back: the data partition is layout v1 again");
        return Ok(());
    }
    // Verification of the result on a read-only view: layout, integrity,
    // row counts and the telemetry against the source.
    verify_migrated(path)?;
    println!("migrate: done");
    Ok(())
}

/// Compares the migrated disk with the v1 state saved in the migration
/// blocks: same database bytes, same row count in every table, same
/// telemetry records.
fn verify_migrated(path: &str) -> Result<(), String> {
    let (dev, f) = overlay(path)?;
    let mut raw = data_part(path, Box::new(dev.view()), &f)?;
    let saved = migrate::read_block(&mut raw, urmqtt_store::mig::BACKUP_LBA)?;
    let st = migrate::read_sizes(&mut raw)?;
    let l1 = v1::decode(&saved, raw.sectors())
        .ok()
        .flatten()
        .ok_or("the saved v1 superblock is gone: cannot compare")?;
    // Source: the old regions are untouched; read through the data
    // partition's window, with the saved v1 superblock.
    let window = || data_part(path, Box::new(dev.view()), &f);
    let src = || -> Result<Disk, String> {
        Ok(Disk::with_layout(Box::new(window()?), l1.clone(), st, 0))
    };
    let mut s = src()?;
    let src_tel = host::telemetry_digest(&mut s)?;
    let src_db = host::file_digest(&mut s, RegionKind::Db, st.sizes[0])?;
    let src_wal = host::file_digest(&mut s, RegionKind::Wal, st.sizes[1])?;
    let src_counts = if st.sizes[0] > 0 {
        Some(host::table_counts(&open_store(src()?)?)?)
    } else {
        None
    };
    let mut d2 = open_layout(data_part(path, Box::new(dev.view()), &f)?)?;
    println!(
        "verify: layout v2 ok ({} regions)",
        d2.layout().regions.len()
    );
    let dst_tel = host::telemetry_digest(&mut d2)?;
    if src_tel.records != dst_tel.records || src_tel.digest != dst_tel.digest {
        return Err(format!(
            "verify: telemetry differs: {src_tel:?} against {dst_tel:?}"
        ));
    }
    println!(
        "verify: telemetry identical ({} record(s), digest {:08x})",
        dst_tel.records, dst_tel.digest
    );
    if host::file_digest(&mut d2, RegionKind::Db, st.sizes[0])? != src_db
        || host::file_digest(&mut d2, RegionKind::Wal, st.sizes[1])? != src_wal
    {
        return Err("verify: the database or WAL bytes differ from the source".into());
    }
    if let Some(want) = src_counts {
        let store = open_store(open_layout(data_part(path, Box::new(dev.view()), &f)?)?)?;
        let ic = store
            .db()
            .query_text("PRAGMA integrity_check")
            .map_err(|e| e.to_string())?;
        if ic != "ok" {
            return Err(format!("verify: integrity_check: {ic}"));
        }
        let got = host::table_counts(&store)?;
        if got != want {
            return Err(format!(
                "verify: row counts differ: {want:?} against {got:?}"
            ));
        }
        println!(
            "verify: sqlite integrity_check ok; row counts identical in {} table(s): {}",
            got.len(),
            got.iter()
                .map(|(n, c)| format!("{n}={c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

// --- grow (S3) ----------------------------------------------------------------------

fn grow_cmd(path: &str, ratio: u32, write: bool, fault: Option<&str>) -> Result<(), String> {
    let mut dev: Box<dyn BlockDevice> = if write {
        writable(path, fault)?
    } else {
        Box::new(Overlay::new(Box::new(FileDisk::open(path, false)?)))
    };
    // `gpt::prepare` would create a data partition on a disk that has none
    // (the first-boot step): growing only ever works on a disk urMQTT booted.
    let found = inspect(dev.as_mut())?;
    if found.data.is_none() {
        return Err(format!(
            "{path}: no urMQTT data partition: nothing to grow (the first boot creates it)"
        ));
    }
    let (part, steps) = gpt::prepare(dev.as_mut(), random).map_err(|e| format!("gpt: {e:?}"))?;
    if steps.moved_backup {
        println!(
            "grow: the backup partition table {}to the end of the disk",
            if write { "moved " } else { "would move " }
        );
    }
    if steps.extended_partition {
        println!(
            "grow: the data partition {} to {} MiB",
            if write { "extended" } else { "would extend" },
            mib(part.sectors())
        );
    }
    let window = Partition::new(dev, part.first_lba, part.sectors())
        .ok_or("data partition beyond the end")?;
    let (mut disk, _) =
        Disk::open_keyed(Box::new(window), random, 8, KEY.get()).map_err(|e| match e {
            DiskError::Layout(LayoutError::OldVersion(_)) => V1_HINT.to_string(),
            e => key_error(e).unwrap_or_else(|| format!("data partition layout: {e:?}")),
        })?;
    match disk.grow(ratio).map_err(|e| format!("grow: {e:?}"))? {
        Some(g) => println!(
            "grow: layout {} MiB -> {} MiB, generation {}: database +{} MiB, telemetry +{} MiB ({}% database){}",
            mib(g.old_total),
            mib(g.new_total),
            g.generation,
            mib(g.db_sectors),
            mib(g.telemetry_sectors),
            ratio,
            if write {
                ""
            } else {
                " (dry run: nothing was written; add --write)"
            }
        ),
        None => println!(
            "grow: nothing to add ({} MiB of the device are not in the layout)",
            mib(disk.spare_sectors())
        ),
    }
    Ok(())
}

// --- scrub (S6) -----------------------------------------------------------------------

struct KeysArgs {
    write: bool,
    fault: Option<String>,
    passphrase: Option<String>,
    new_passphrase: Option<String>,
    key_out: Option<String>,
    slot: Option<usize>,
    iterations: u32,
}

/// `urmqtt-disk keys DISK [add|change|remove|unwrap]` (LATER-7, ADR-327).
fn keys_cmd(path: &str, sub: Option<&str>, a: KeysArgs) -> Result<(), String> {
    let op = match sub {
        None | Some("list") => {
            let (base, found) = overlay(path)?;
            let mut part = data_part(path, Box::new(base), &found)?;
            print!("{}", keys::list(&mut part)?);
            return Ok(());
        }
        Some("add") => keys::Op::Add,
        Some("change") => keys::Op::Change,
        Some("remove") => keys::Op::Remove,
        Some("unwrap") => keys::Op::Unwrap,
        Some(o) => {
            return Err(format!(
                "keys: unknown command {o:?} (add, change, remove, unwrap)"
            ));
        }
    };
    let auth = match (&a.passphrase, KEY.get()) {
        (Some(p), None) => keys::Auth::Passphrase(keys::read_passphrase(p)?),
        (None, Some(k)) => keys::Auth::Key(urmqtt_store::keyslot::Zeroizing::new(*k)),
        _ => return Err("keys: give --key FILE or --passphrase-file FILE".into()),
    };
    let new = a
        .new_passphrase
        .as_deref()
        .map(keys::read_passphrase)
        .transpose()?;
    // The header can be copied and guessed offline at one PBKDF2 per guess
    // (R060-S4, ADR-374): say so when a new slot is cheaper than usual.
    if let Some(p) = &new {
        if p.len() < 20 {
            eprintln!(
                "keys: warning: the new passphrase has {} characters; a copied header is guessed offline at one PBKDF2 per guess: use a generated one of 20 or more (openssl rand -base64 24)",
                p.len()
            );
        }
        if a.iterations < urmqtt_store::keyslot::DEFAULT_ITERATIONS {
            eprintln!(
                "keys: warning: --iterations {} is below the default {}: every offline guess at the new slot is that much cheaper",
                a.iterations,
                urmqtt_store::keyslot::DEFAULT_ITERATIONS
            );
        }
    }
    if op == keys::Op::Unwrap && matches!(auth, keys::Auth::Passphrase(_)) && a.key_out.is_none() {
        return Err("unwrap with a passphrase: give --key-out FILE, where the key is written (the image needs it from now on)".into());
    }
    let mut dev: Box<dyn BlockDevice> = if a.write {
        writable(path, a.fault.as_deref())?
    } else {
        Box::new(Overlay::new(Box::new(FileDisk::open(path, false)?)))
    };
    let found = inspect(dev.as_mut())?;
    let mut part = data_part(path, dev, &found)?;
    // The key for --key-out, before the slots go.
    let key_out = match (&a.key_out, op) {
        (Some(_), keys::Op::Unwrap) => Some(keys::key_of(&mut part, &auth)?.0),
        (Some(_), _) => return Err("--key-out goes with `keys DISK unwrap` only".into()),
        _ => None,
    };
    let mut salt = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    // The key file is written (and synced) before the slots are emptied:
    // were it written after, a refused file (one that exists already, a
    // missing directory, a full disk) would leave the key nowhere at all.
    if let (Some(out), Some(k)) = (&a.key_out, &key_out) {
        if a.write {
            write_secret(out, keys::key_hex(k).as_bytes())?;
            println!(
                "keys: the disk key was written to {out} (128 hex digits): it is the storage.disk_key of the image from now on; keep it secret"
            );
        } else if std::path::Path::new(out).exists() {
            return Err(format!("{out}: exists already (it must not exist yet)"));
        } else {
            println!("keys: dry run: the key would be written to {out}");
        }
    }
    let done = keys::apply(
        Box::new(part),
        op,
        &auth,
        a.slot,
        new.as_ref().map(|p| p.as_slice()),
        a.iterations,
        salt,
    )?;
    let what = match (done.op, done.slot) {
        (keys::Op::Add, Some(s)) => format!("key slot {s}: the disk key is wrapped under the new passphrase"),
        (keys::Op::Change, Some(s)) => format!("key slot {s}: new passphrase; the disk key is the same, so a copy of the old header still opens the disk with the old passphrase (if it leaked: rekey, then keys add)"),
        (keys::Op::Remove, Some(s)) => format!("key slot {s}: emptied"),
        _ => "every key slot emptied: the key must come from the image (storage.disk_key_source = \"image\", storage.disk_key)".into(),
    };
    println!(
        "keys: {what}{}{}",
        if done.scrubbed {
            "; the older superblock was brought up to date"
        } else {
            ""
        },
        if a.write {
            ""
        } else {
            " (dry run on an overlay: nothing was written; add --write)"
        }
    );
    Ok(())
}

/// Writes a secret file readable by its owner only.
fn write_secret(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{path}: {e} (it must not exist yet)"))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{path}: {e}"))
}

/// Writes a plaintext copy of the store (the database of `export-db`, a
/// snapshot of `backup-extract`): it holds the account hashes, revocations,
/// retained and queued messages, which on an encrypted disk exist nowhere
/// else in the clear. So it is readable by its owner only (0600, also when
/// the file already existed, before a byte is written), and synced
/// (R060-S2, ADR-371). Unlike `--key-out` it may replace an existing file.
fn write_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| f.write_all(bytes))
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{path}: {e}"))
}

fn convert_cmd(
    path: &str,
    from: Option<Key>,
    to: Option<Key>,
    write: bool,
    resume: bool,
    journal: Option<String>,
    fault: Option<&str>,
) -> Result<(), String> {
    let mut dev: Box<dyn BlockDevice> = if write {
        writable(path, fault)?
    } else {
        Box::new(Overlay::new(Box::new(FileDisk::open(path, false)?)))
    };
    let found = inspect(dev.as_mut())?;
    let d = found.data.ok_or_else(|| {
        format!("{path}: no urMQTT data partition (the image has not been booted yet)")
    })?;
    let mut part = Partition::new(dev, d.first_lba, d.sectors())
        .ok_or_else(|| format!("{path}: data partition beyond the end of the disk"))?;
    let mut file_j;
    let mut mem_j;
    let j: &mut dyn convert::Journal = if write {
        file_j = FileJournal(PathBuf::from(
            journal.unwrap_or_else(|| format!("{path}.convert-journal")),
        ));
        &mut file_j
    } else {
        mem_j = MemJournal::default();
        &mut mem_j
    };
    let r = convert::convert(
        &mut part,
        from.as_ref(),
        to.as_ref(),
        j,
        resume,
        |done, total| {
            eprint!("\rconverted {} of {} MiB", mib(done), mib(total));
        },
    )?;
    eprintln!();
    println!(
        "{}: {} MiB rewritten, {} chunk(s) of 1 MiB were empty{}{}",
        if write {
            "done"
        } else {
            "dry run on an overlay (nothing written)"
        },
        mib(r.sectors_rewritten),
        r.chunks_skipped,
        if r.resumed { ", resumed" } else { "" },
        if to.is_some() {
            "; the disk is now encrypted: boot it with the key in the ISO's configuration (storage.disk_key), or wrap it under a passphrase with `urmqtt-disk keys DISK add --key FILE` (any key slots were emptied: they wrapped the old key)"
        } else {
            "; the disk is now plain"
        }
    );
    Ok(())
}

fn scrub_cmd(path: &str) -> Result<(), String> {
    use urmqtt_store::scrub::{Finding, Scrubber};
    let (dev, f) = overlay(path)?;
    let mut disk = open_layout(data_part(path, Box::new(dev.view()), &f)?)?;
    // The telemetry log is opened the way the kernel does (recovery included)
    // on the overlay, so the disk is not changed.
    let (mut log, _) = TelemetryLog::open(&mut disk, now_unix(), u64::MAX / 4)
        .map_err(|e| format!("telemetry: {e:?}"))?;
    let store = open_store(disk)?;
    let mut scrubber = Scrubber::new();
    let mut findings: Vec<Finding> = Vec::new();
    while !scrubber
        .step(store.db(), Some(&mut log), 256 * 1024, &mut findings)
        .done
    {}
    let r = scrubber.report;
    for f in &findings {
        println!("scrub: {f:?}");
    }
    println!(
        "scrub: {} KiB read; database {} object(s), {} problem(s); backup {} slot(s) intact, {} bad; \
         telemetry {} segment(s), {} record(s), {} damaged, {} bad tail(s), {} bad header(s)",
        r.bytes_read / 1024,
        r.db_objects,
        r.db_errors,
        r.backup_slots_ok,
        r.backup_slots_bad,
        r.telemetry_segments,
        r.telemetry_records,
        r.telemetry_damaged,
        r.telemetry_bad_tails,
        r.telemetry_bad_headers
    );
    if r.errors() > 0 {
        Err(format!("scrub: {} problem(s) found", r.errors()))
    } else {
        println!("scrub: ok");
        Ok(())
    }
}

// --- backup (S5) ----------------------------------------------------------------------

/// The backup region of a disk as text lines, and the problems found: a
/// slot whose header is valid but whose payload fails its CRC.
fn backup_report(disk: &mut Disk) -> (Vec<String>, Vec<String>) {
    use urmqtt_store::backup;
    let (mut lines, mut bad) = (Vec::new(), Vec::new());
    let Some(g) = disk.layout().backup() else {
        lines.push(if disk.layout().minor == 0 {
            "backup: none (layout v2.0; the kernel adds the region at its next boot, or run `urmqtt-disk backup --write`)".to_string()
        } else {
            "backup: none".to_string()
        });
        return (lines, bad);
    };
    let pending = matches!(backup::read_control(disk), Ok(c) if c.restoring.is_some());
    lines.push(format!(
        "backup: region {} MiB, two slots of {} KiB{}",
        g.region_bytes >> 20,
        g.slot_bytes >> 10,
        if pending {
            ", a RESTORE IS PENDING (the next boot finishes it)"
        } else {
            ""
        }
    ));
    match backup::scan(disk) {
        Ok(slots) => {
            for (i, h) in slots.header.iter().enumerate() {
                let Some(h) = h else {
                    lines.push(format!("backup slot {i}: empty or invalid"));
                    continue;
                };
                let state = match backup::verify_slot(disk, i, h) {
                    Ok(true) => "intact",
                    Ok(false) => {
                        bad.push(format!(
                            "backup: slot {i} (seq {}) fails its payload CRC",
                            h.seq
                        ));
                        "PAYLOAD CRC MISMATCH"
                    }
                    Err(_) => "unreadable",
                };
                lines.push(format!(
                    "backup slot {i}: seq {}{}, taken at unix {}, {} KiB, schema v{}, {state}",
                    h.seq,
                    if slots.newest() == Some(i) {
                        " (newest)"
                    } else {
                        ""
                    },
                    h.created,
                    h.payload_bytes >> 10,
                    h.schema_version
                ));
            }
        }
        Err(e) => bad.push(format!("backup: unreadable: {e}")),
    }
    (lines, bad)
}

/// A disk for a backup command: a changeable one with `--write`, otherwise
/// an in-memory overlay (the run is rehearsed and nothing is changed).
fn open_for_backup(path: &str, write: bool, fault: Option<&str>) -> Result<Disk, String> {
    let mut dev: Box<dyn BlockDevice> = if write {
        writable(path, fault)?
    } else {
        Box::new(Overlay::new(Box::new(FileDisk::open(path, false)?)))
    };
    let found = inspect(dev.as_mut())?;
    let part = data_part(path, dev, &found)?;
    open_layout(part)
}

fn backup_cmd(path: &str, write: bool, fault: Option<&str>) -> Result<(), String> {
    use urmqtt_store::backup::{BackupJob, Progress};
    use urmqtt_store::disk::BackupRegion;
    let mut disk = open_for_backup(path, write, fault)?;
    match disk
        .ensure_backup()
        .map_err(|e| format!("backup region: {e:?}"))?
    {
        BackupRegion::Added { bytes, slot_bytes } => println!(
            "backup: region added (layout v2.1): {} MiB, two slots of {} KiB{}",
            bytes >> 20,
            slot_bytes >> 10,
            if write { "" } else { " (dry run)" }
        ),
        BackupRegion::NoRoom => {
            return Err("the database leaves no room for a backup region".into());
        }
        BackupRegion::Present => {}
    }
    let store = open_store(disk)?;
    let mut job = BackupJob::start(None, now_unix()).map_err(|e| e.to_string())?;
    loop {
        match job
            .step(store.db(), 64, 1 << 20)
            .map_err(|e| format!("backup: {e}"))?
        {
            Progress::Working => {}
            Progress::Done(h, slot) => {
                println!(
                    "backup: snapshot seq {} in slot {slot}: {} KiB, schema v{}, CRC {:08x}{}",
                    h.seq,
                    h.payload_bytes >> 10,
                    h.schema_version,
                    h.payload_crc,
                    if write {
                        ""
                    } else {
                        " (dry run: nothing was changed; add --write)"
                    }
                );
                return Ok(());
            }
        }
    }
}

fn backup_extract(path: &str, out: &str, slot: Option<usize>) -> Result<(), String> {
    use urmqtt_store::backup;
    let (dev, f) = overlay(path)?;
    let mut disk = open_layout(data_part(path, Box::new(dev.view()), &f)?)?;
    let slots = backup::scan(&mut disk).map_err(|e| e.to_string())?;
    let mut pick = None;
    for (i, h) in slots.by_age() {
        if slot.is_some_and(|s| s != i) {
            continue;
        }
        if backup::verify_slot(&mut disk, i, &h).map_err(|e| e.to_string())? {
            pick = Some((i, h));
            break;
        }
    }
    let (i, h) = pick.ok_or("no intact snapshot")?;
    let g = disk.layout().backup().ok_or("no backup region")?;
    let mut data = vec![0u8; h.payload_bytes as usize];
    disk.read_at(
        RegionKind::Backup,
        g.slot_offset(i) + urmqtt_store::layout::BACKUP_HEADER_BYTES,
        &mut data,
    )
    .map_err(|e| format!("{e:?}"))?;
    write_private(out, &data)?;
    eprintln!(
        "backup-extract: {out}: snapshot seq {} of slot {i}, {} bytes, taken at unix {}",
        h.seq,
        data.len(),
        h.created
    );
    Ok(())
}

fn backup_restore(path: &str, write: bool, fault: Option<&str>) -> Result<(), String> {
    if !write {
        return Err(
            "backup-restore replaces the database: add --write (with the VM stopped)".into(),
        );
    }
    let mut disk = open_for_backup(path, true, fault)?;
    let r = urmqtt_store::backup::restore(&mut disk, urmqtt_store::schema::VERSION as u32)
        .map_err(|e| format!("restore: {e}"))?;
    println!(
        "backup-restore: the database now holds snapshot seq {} of slot {} (taken at unix {}, {} KiB, schema v{}){}",
        r.header.seq,
        r.slot,
        r.header.created,
        r.header.payload_bytes >> 10,
        r.header.schema_version,
        if r.resumed {
            "; an interrupted restore was finished"
        } else {
            ""
        }
    );
    Ok(())
}

// --- fixture (test hook) ------------------------------------------------------------

/// A layout-v1 data partition on an image: the kernel only reads v2, so the
/// migration tests and the `layout-v1-refused` smoke scenario need this.
fn fixture_v1(path: &str, populate: bool, fault: Option<&str>) -> Result<(), String> {
    let mut dev = writable(path, fault)?;
    let (part, _) = gpt::prepare(dev.as_mut(), random).map_err(|e| format!("gpt: {e:?}"))?;
    let mut window = Partition::new(dev, part.first_lba, part.sectors()).ok_or("window")?;
    // Never over anything: the head of the data partition must be blank.
    let mut head = vec![0u8; 64 * S];
    window
        .read(0, &mut head)
        .map_err(|e| format!("read: {e:?}"))?;
    if head.iter().any(|&b| b != 0) {
        return Err(format!(
            "{path}: the data partition is not blank: fixture-v1 only formats a blank one"
        ));
    }
    host::format_v1(&mut window, random())?;
    eprintln!("fixture-v1: {path}: data partition formatted as layout v1");
    if populate {
        let disk = Disk::open_v1(Box::new(window)).map_err(|e| format!("{e:?}"))?;
        host::populate(disk)?;
        eprintln!(
            "fixture-v1: populated: 40 devices, 2 retained messages, 1 session with 1 queued message, 600 telemetry records"
        );
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let opt = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1).cloned())
    };
    if let Some(k) = opt("--key") {
        KEY.set(load_key(&k)?)
            .map_err(|_| "--key given twice".to_string())?;
    }
    if opt("--key").is_some() && opt("--passphrase-file").is_some() {
        return Err("give --key FILE or --passphrase-file FILE, not both".into());
    }
    let pos: Vec<&String> = {
        let mut v = Vec::new();
        let mut skip = false;
        for a in args {
            if skip {
                skip = false;
                continue;
            }
            if a.starts_with("--") {
                skip = !matches!(
                    a.as_str(),
                    "--write"
                        | "--allowlist"
                        | "--resume"
                        | "--rollback"
                        | "--force"
                        | "--populate"
                        | "--keep-config"
                        | "--replace-config"
                        | "--unsigned"
                        | "--allow-downgrade"
                        | "--allow-unsealed"
                        | "--one-way"
                        | "--retry"
                        | "--in-place"
                );
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
    let policy = || -> Result<config::Policy, String> {
        Ok(
            match (
                opt("--config"),
                flag("--keep-config"),
                flag("--replace-config"),
            ) {
                (None, false, false) => config::Policy::Auto,
                (None, true, false) => config::Policy::Keep,
                (None, false, true) => config::Policy::Replace,
                (Some(c), false, false) => config::Policy::Set(config::slot_from_file(
                    &std::fs::read(&c).map_err(|e| format!("{c}: {e}"))?,
                )?),
                _ => {
                    return Err(
                        "give at most one of --config FILE, --keep-config, --replace-config".into(),
                    );
                }
            },
        )
    };
    // LATER-7: a passphrase opens the key slots; every command but `keys`
    // (which takes it as its authorisation) then runs with the key.
    if let Some(p) = opt("--passphrase-file")
        && pos.first().map(|s| s.as_str()) != Some("keys")
    {
        let pass = keys::read_passphrase(&p)?;
        let path = arg(1, "DISK")?;
        let (base, found) = overlay(path)?;
        let mut part = data_part(path, Box::new(base), &found)?;
        let (k, _) = urmqtt_store::disk::unlock(&mut part, &pass).map_err(keys::disk_error)?;
        KEY.set(*k).map_err(|_| "--key given twice".to_string())?;
    }
    match pos.first().map(|s| s.as_str()) {
        Some("keys") => keys_cmd(
            arg(1, "DISK")?,
            pos.get(2).map(|s| s.as_str()),
            KeysArgs {
                write: flag("--write"),
                fault: opt("--fault"),
                passphrase: opt("--passphrase-file"),
                new_passphrase: opt("--new-passphrase-file"),
                key_out: opt("--key-out"),
                slot: opt("--slot")
                    .map(|s| s.parse::<usize>().map_err(|e| format!("--slot: {e}")))
                    .transpose()?,
                iterations: opt("--iterations")
                    .map(|s| s.parse::<u32>().map_err(|e| format!("--iterations: {e}")))
                    .transpose()?
                    .unwrap_or(urmqtt_store::keyslot::DEFAULT_ITERATIONS),
            },
        ),
        Some("slots") => {
            let sub = arg(1, "status|stage|activate|confirm|rollback")?;
            let path = arg(2, "DISK")?;
            let a = SlotArgs {
                write: flag("--write"),
                fault: opt("--fault"),
                image: opt("--image"),
                esp: opt("--esp"),
                sums: opt("--sums"),
                sig: opt("--sig"),
                pubkeys: args
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| *a == "--pubkey")
                    .filter_map(|(i, _)| args.get(i + 1).cloned())
                    .collect(),
                unsigned: flag("--unsigned"),
                allow_downgrade: flag("--allow-downgrade"),
                allow_unsealed: flag("--allow-unsealed"),
                tries: opt("--tries")
                    .map(|t| {
                        t.parse::<u8>()
                            .ok()
                            .filter(|n| (1..=slots::MAX_TRIES).contains(n))
                            .ok_or_else(|| format!("--tries: 1..={}", slots::MAX_TRIES))
                    })
                    .transpose()?
                    .unwrap_or(slots::DEFAULT_TRIES),
                one_way: flag("--one-way"),
                retry: flag("--retry"),
                policy: policy()?,
            };
            match sub {
                "status" => slots_status(path),
                "stage" => slots_stage(path, &a),
                "activate" => slots_activate(path, &a),
                "confirm" => slots_confirm(path, &a),
                "rollback" => slots_rollback(path, &a),
                other => Err(format!(
                    "unknown slots command {other:?}: status, stage, activate, confirm, rollback"
                )),
            }
        }
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
            opt("--config").as_deref(),
        ),
        Some("update-boot") => update_boot(
            arg(1, "DISK")?,
            &opt("--esp").ok_or("--esp ESP is required")?,
            flag("--write"),
            flag("--in-place"),
            flag("--allow-unsealed"),
            &policy()?,
        ),
        Some("migrate") => migrate_cmd(
            arg(1, "DISK")?,
            &MigrateArgs {
                write: flag("--write"),
                resume: flag("--resume"),
                rollback: flag("--rollback"),
                force: flag("--force"),
                rollback_file: opt("--rollback-file").map(PathBuf::from),
                align_mib: opt("--align-mib")
                    .map(|s| s.parse::<u32>().map_err(|e| format!("--align-mib: {e}")))
                    .transpose()?
                    .unwrap_or(1),
                fault: opt("--fault"),
            },
        ),
        Some("grow") => grow_cmd(
            arg(1, "DISK")?,
            opt("--ratio")
                .map(|s| s.parse::<u32>().map_err(|e| format!("--ratio: {e}")))
                .transpose()?
                .unwrap_or(50)
                .min(100),
            flag("--write"),
            opt("--fault").as_deref(),
        ),
        Some(c @ ("encrypt" | "decrypt" | "rekey")) => {
            let new = opt("--key-new").map(|k| load_key(&k)).transpose()?;
            let old = KEY.get().copied();
            let (from, to) = match (c, old, new) {
                ("encrypt", None, Some(n)) => (None, Some(n)),
                ("decrypt", Some(o), None) => (Some(o), None),
                ("rekey", Some(o), Some(n)) => (Some(o), Some(n)),
                ("encrypt", ..) => return Err("encrypt: give --key-new FILE (and no --key)".into()),
                ("decrypt", ..) => return Err("decrypt: give --key FILE (and no --key-new)".into()),
                _ => return Err("rekey: give --key FILE and --key-new FILE".into()),
            };
            convert_cmd(
                arg(1, "DISK")?,
                from,
                to,
                flag("--write"),
                flag("--resume"),
                opt("--journal"),
                opt("--fault").as_deref(),
            )
        }
        Some("scrub") => scrub_cmd(arg(1, "DISK")?),
        Some("backup") => backup_cmd(arg(1, "DISK")?, flag("--write"), opt("--fault").as_deref()),
        Some("backup-extract") => backup_extract(
            arg(1, "DISK")?,
            arg(2, "OUT")?,
            opt("--slot")
                .map(|s| s.parse::<usize>().map_err(|e| format!("--slot: {e}")))
                .transpose()?,
        ),
        Some("backup-restore") => {
            backup_restore(arg(1, "DISK")?, flag("--write"), opt("--fault").as_deref())
        }
        Some("fixture-v1") => {
            if !flag("--write") {
                return Err("fixture-v1 writes the image: add --write".into());
            }
            fixture_v1(
                arg(1, "DISK")?,
                flag("--populate"),
                opt("--fault").as_deref(),
            )
        }
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
