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
//! urmqtt-disk create OUT --esp ESP [--size BYTES[K|M|G]]
//!                                                a boot image (byte for byte mkraw.py), optionally
//!                                                on a larger disk; the first boot formats the data
//! urmqtt-disk update-boot DISK --esp ESP --write replace the kernel (ESP), keep the data
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
//! urmqtt-disk backup-restore DISK --write        replace the database by the newest intact snapshot
//!                                                (the kernel does the same at boot when the database
//!                                                is corrupt and storage.auto_restore is on)
//! ```
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

use urmqtt_disk::dev::{FileDisk, Overlay, S, Shared};
use urmqtt_disk::host::{self, mib, now_unix, open_store};
use urmqtt_disk::migrate;
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::gpt::{self, DataPartition, Table};
use urmqtt_store::layout::{FileKind, Layout, LayoutError, RegionKind, SECTOR, v1};
use urmqtt_store::part::Partition;
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

fn open_layout(part: Partition) -> Result<Disk, String> {
    match Disk::open(Box::new(part), || [0; 16]) {
        Ok((d, Opened::Existing)) => Ok(d),
        Ok((_, Opened::Formatted)) => Err("the data partition is blank (never booted)".into()),
        Err(DiskError::Layout(LayoutError::OldVersion(_))) => Err(V1_HINT.into()),
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
    let (dev, f) = overlay(path)?;
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
    let (mut disk, _) = Disk::open_with(Box::new(window), random, 8).map_err(|e| match e {
        DiskError::Layout(LayoutError::OldVersion(_)) => V1_HINT.to_string(),
        e => format!("data partition layout: {e:?}"),
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
    std::fs::write(out, &data).map_err(|e| format!("{out}: {e}"))?;
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
