//! Live mode (O3, ADR-054): the ISO's first entry runs the broker with no
//! disk. The data store is an in-memory block device carved out of RAM at
//! boot; the data layout, SQLite and the telemetry log run on it through the
//! same block interface as on a disk. Nothing survives a reboot, and the
//! kernel says so on every channel it has.
//!
//! Which medium is used is decided by `storage.mode` of the baked
//! configuration and the `live` word of the kernel command line
//! (`urmqtt_config::StorageMode::backing`); this module holds the result and
//! the loud part.

#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_log::{info, warn};
use urmqtt_store::BlockDevice;
use urmqtt_store::ram::{self, RamDisk, Reservation};

use crate::vm;

/// RAM chunk the store is built from (a contiguous run of frames).
const CHUNK: usize = 2 << 20;

/// Bytes of the RAM store; 0 when the data lives on a disk.
static RAM_STORE_BYTES: AtomicU64 = AtomicU64::new(0);

/// Whether the data is lost on reboot.
pub fn ephemeral() -> bool {
    store_bytes() != 0
}

/// Bytes of the RAM store (0: none).
pub fn store_bytes() -> u64 {
    // Relaxed: set once at boot, before the data plane and the metrics.
    RAM_STORE_BYTES.load(Ordering::Relaxed)
}

/// The memory plan at boot, for the log.
pub fn announce_plan(total_ram: u64, plan: &Reservation, configured_heap_mb: u32) {
    let cfg = &urmqtt_config::CONFIG.storage;
    info!(
        "live: RAM store {} MiB = {}% of {} MiB RAM (storage.ram_percent), taken from the connection budget",
        plan.ram_bytes >> 20,
        cfg.ram_percent,
        total_ram >> 20
    );
    if plan.heap_shrunk {
        warn!(
            "live: kernel heap {} MiB instead of the configured {configured_heap_mb} MiB \
             (the RAM store, {} MiB SQLite heap and {} MiB of kernel overhead leave no more): \
             about {} connections instead of {}",
            plan.heap_mb,
            cfg.sqlite_heap_mb,
            ram::OVERHEAD_MB,
            connections(plan.heap_mb),
            connections(configured_heap_mb)
        );
    } else {
        info!(
            "live: kernel heap stays {} MiB, about {} connections",
            plan.heap_mb,
            connections(plan.heap_mb)
        );
    }
}

/// Idle connections a heap holds (about 500 B each, PROMPT M15).
fn connections(heap_mb: u32) -> u64 {
    (u64::from(heap_mb) << 20) / 500
}

/// Takes `bytes` of RAM for the store and returns it as a block device.
pub fn reserve(bytes: u64) -> Result<Box<dyn BlockDevice>, &'static str> {
    let want = usize::try_from(bytes / CHUNK as u64).map_err(|_| "RAM store too large")?;
    let mut chunks: Vec<&'static mut [u8]> = Vec::new();
    chunks
        .try_reserve_exact(want)
        .map_err(|_| "no memory for the RAM store's chunk table")?;
    for _ in 0..want {
        let Some((va, _pa, len)) = vm::dma_alloc(CHUNK) else {
            return Err("not enough free RAM for the RAM store (lower storage.ram_percent)");
        };
        // SAFETY: freshly allocated, zeroed frames reached through the HHDM,
        // owned by the store from here on and never freed.
        chunks.push(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len.min(CHUNK)) });
    }
    let dev = RamDisk::new(chunks).ok_or("RAM store chunks are inconsistent")?;
    // Relaxed: written once before the data plane starts.
    RAM_STORE_BYTES.store(dev.sectors() * 512, Ordering::Relaxed);
    Ok(Box::new(dev))
}

/// The banner, written whatever the log level, before the broker starts
/// serving; and the log line syslog collectors keep.
pub fn banner() {
    let bytes = store_bytes();
    urmqtt_log::raw(format_args!(
        "\n========================================================================\n\
         EPHEMERAL: data is lost on reboot\n\
         live mode: the broker keeps its data in {} MiB of RAM, not on a disk. Retained\n\
         messages, sessions, the telemetry log and runtime revocations are gone at the next\n\
         reboot or power loss. To persist, install to a disk (the \"Install\" menu entry).\n\
         ========================================================================\n\n",
        bytes >> 20
    ));
    warn!(
        "EPHEMERAL: data is lost on reboot (live mode, {} MiB RAM store)",
        bytes >> 20
    );
}
