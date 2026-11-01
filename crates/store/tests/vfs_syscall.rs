//! The kernel's side of the worker's system calls (ADR-211) with a hostile
//! caller: the worker is untrusted, so file numbers, lengths, offsets and
//! sizes are whatever it likes. Nothing here starts SQLite; the handler is
//! called the way the exception handler calls it.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use urmqtt_store::vfs;
use urmqtt_store::{Disk, MemDisk, Platform};
use urmqtt_usys::layout::SHM_IO;
use urmqtt_usys::proto::vfs as p;

static LONGEST_DELAY: AtomicU32 = AtomicU32::new(0);
static LAST_LOG: Mutex<String> = Mutex::new(String::new());

fn platform() -> Platform {
    Platform {
        random: |b| b.fill(0xa5),
        now_unix_ms: || Some(1_761_696_000_123),
        delay_us: |us| {
            LONGEST_DELAY.fetch_max(us, Ordering::Relaxed);
        },
        log: |code, msg| {
            *LAST_LOG.lock().unwrap() = format!("{code}:{msg}");
        },
    }
}

/// The handler works on the process-wide VFS state.
fn mounted() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    let g = L
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let m = MemDisk::new(32 << 20);
    let (disk, _) = Disk::open(m.device(), || [3; 16]).unwrap();
    vfs::install(disk, platform());
    g
}

fn call(nr: u64, a: [u64; 3], io: &mut [u8]) -> Option<u64> {
    vfs::syscall(nr, [a[0], a[1], a[2], 0, 0, 0], io)
}

#[test]
fn unknown_calls_are_not_vfs_calls() {
    let _g = mounted();
    let mut io = vec![0u8; SHM_IO];
    assert_eq!(call(0, [0; 3], &mut io), None, "exit is not ours");
    assert_eq!(call(1, [0; 3], &mut io), None);
    assert_eq!(call(14, [0; 3], &mut io), None);
    assert_eq!(call(u64::MAX, [0; 3], &mut io), None);
}

#[test]
fn only_the_four_files_can_be_named() {
    let _g = mounted();
    let mut io = vec![0u8; SHM_IO];
    for f in [p::FILE_DB, p::FILE_WAL, p::FILE_JOURNAL] {
        assert_eq!(call(p::OPEN, [f, 0, 0], &mut io), Some(0));
    }
    // No slot attached: the backup file does not exist.
    assert_eq!(call(p::OPEN, [p::FILE_BACKUP, 0, 0], &mut io), Some(1));
    for f in [4, 5, 255, 1 << 32, u64::MAX] {
        assert_eq!(call(p::OPEN, [f, 0, 0], &mut io), Some(1), "file {f}");
        assert_eq!(call(p::DELETE, [f, 0, 0], &mut io), Some(1), "file {f}");
        assert_eq!(call(p::EXISTS, [f, 0, 0], &mut io), Some(0), "file {f}");
        assert_eq!(call(p::READ, [f, 0, 16], &mut io), Some(p::RC_ERR));
        assert_eq!(call(p::WRITE, [f, 0, 16], &mut io), Some(p::RC_ERR));
        assert_eq!(call(p::TRUNCATE, [f, 0, 0], &mut io), Some(p::RC_ERR));
        assert_eq!(call(p::SIZE, [f, 0, 0], &mut io), Some(0));
    }
}

#[test]
fn write_read_size_round_trip_and_short_reads_are_zero_filled() {
    let _g = mounted();
    let mut io = vec![0u8; SHM_IO];
    for (i, b) in io.iter_mut().take(4096).enumerate() {
        *b = (i * 7 + 1) as u8;
    }
    let want = io[..4096].to_vec();
    assert_eq!(
        call(p::WRITE, [p::FILE_DB, 0, 4096], &mut io),
        Some(p::RC_OK)
    );
    assert_eq!(call(p::SIZE, [p::FILE_DB, 0, 0], &mut io), Some(4096));
    assert_eq!(call(p::EXISTS, [p::FILE_DB, 0, 0], &mut io), Some(1));
    io.fill(0xee);
    assert_eq!(
        call(p::READ, [p::FILE_DB, 0, 4096], &mut io),
        Some(p::RC_OK)
    );
    assert_eq!(&io[..4096], &want[..]);
    // Past the end: short, and the rest is zeros whatever the area held.
    io.fill(0xee);
    assert_eq!(
        call(p::READ, [p::FILE_DB, 0, 8192], &mut io),
        Some(p::RC_SHORT)
    );
    assert_eq!(&io[..4096], &want[..]);
    assert!(io[4096..8192].iter().all(|&b| b == 0));
    // A gap left by a write past the end reads as zeros.
    assert_eq!(
        call(p::WRITE, [p::FILE_DB, 16384, 16], &mut io),
        Some(p::RC_OK)
    );
    io.fill(0xee);
    assert_eq!(
        call(p::READ, [p::FILE_DB, 4096, 4096], &mut io),
        Some(p::RC_OK)
    );
    assert!(io[..4096].iter().all(|&b| b == 0), "the gap is zeros");
    // Truncate shrinks, and growing exposes zeros.
    assert_eq!(
        call(p::TRUNCATE, [p::FILE_DB, 100, 0], &mut io),
        Some(p::RC_OK)
    );
    assert_eq!(call(p::SIZE, [p::FILE_DB, 0, 0], &mut io), Some(100));
    assert_eq!(
        call(p::TRUNCATE, [p::FILE_DB, 8192, 0], &mut io),
        Some(p::RC_OK)
    );
    io.fill(0xee);
    assert_eq!(
        call(p::READ, [p::FILE_DB, 100, 8092], &mut io),
        Some(p::RC_OK)
    );
    assert!(io[..8092].iter().all(|&b| b == 0));
    assert_eq!(call(p::DELETE, [p::FILE_DB, 0, 0], &mut io), Some(0));
    assert_eq!(call(p::SIZE, [p::FILE_DB, 0, 0], &mut io), Some(0));
}

#[test]
fn lengths_offsets_and_sizes_are_checked_before_use() {
    let _g = mounted();
    let mut io = vec![0u8; SHM_IO];
    // A length the I/O area cannot hold.
    for len in [SHM_IO as u64 + 1, 1 << 32, u64::MAX] {
        assert_eq!(
            call(p::READ, [p::FILE_DB, 0, len], &mut io),
            Some(p::RC_ERR)
        );
        assert_eq!(
            call(p::WRITE, [p::FILE_DB, 0, len], &mut io),
            Some(p::RC_ERR)
        );
    }
    // An offset that overflows when the length is added.
    assert_eq!(
        call(p::WRITE, [p::FILE_DB, u64::MAX - 10, 100], &mut io),
        Some(p::RC_ERR)
    );
    // Offsets and sizes far beyond the file's region: the disk layer says no
    // and nothing is written or grown.
    for off in [1u64 << 40, 1 << 62, u64::MAX / 2] {
        let r = call(p::WRITE, [p::FILE_DB, off, 16], &mut io).unwrap();
        assert!(r == p::RC_FULL || r == p::RC_ERR, "offset {off:#x}: {r}");
    }
    assert_eq!(call(p::SIZE, [p::FILE_DB, 0, 0], &mut io), Some(0));
    for size in [(1u64 << 44) + 1, 1 << 63, u64::MAX] {
        assert_eq!(
            call(p::TRUNCATE, [p::FILE_DB, size, 0], &mut io),
            Some(p::RC_FULL)
        );
    }
    let r = call(p::TRUNCATE, [p::FILE_WAL, 1 << 43, 0], &mut io).unwrap();
    assert!(r == p::RC_FULL || r == p::RC_ERR, "{r}");
    assert_eq!(call(p::SIZE, [p::FILE_WAL, 0, 0], &mut io), Some(0));
    // A short I/O area (a buggy caller) is refused, not overrun.
    let mut small = [0u8; 16];
    assert_eq!(
        call(p::READ, [p::FILE_DB, 0, 64], &mut small),
        Some(p::RC_ERR)
    );
}

#[test]
fn random_time_sleep_and_log_are_bounded() {
    let _g = mounted();
    let mut io = vec![0u8; SHM_IO];
    assert_eq!(call(p::RANDOM, [0, 0, 32], &mut io), Some(32));
    assert!(io[..32].iter().all(|&b| b == 0xa5));
    assert_eq!(call(p::RANDOM, [0, 0, SHM_IO as u64 + 1], &mut io), Some(0));
    assert_eq!(call(p::TIME, [0; 3], &mut io), Some(1_761_696_000_123));
    // The worker cannot park the core.
    assert_eq!(call(p::SLEEP, [u64::MAX, 0, 0], &mut io), Some(0));
    assert_eq!(call(p::SLEEP, [60_000_000, 0, 0], &mut io), Some(0));
    assert!(LONGEST_DELAY.load(Ordering::Relaxed) <= 100_000);
    // The log text is cut and printable ASCII only.
    io.fill(b'x');
    io[0] = 0x1b;
    io[1] = 0xff;
    io[2] = b'\n';
    assert_eq!(call(p::LOG, [27, 10_000, 10_000], &mut io), Some(0));
    let line = LAST_LOG.lock().unwrap().clone();
    assert!(line.starts_with("27:???x"), "{line}");
    assert_eq!(line.len(), 3 + 400, "cut at 400 bytes: {line}");
}
