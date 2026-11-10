//! The limit on established TLS connections per source address, the kernel's
//! side (NOW-14, ADR-280).
//!
//! The decisions are in `urmqtt_net::source_limit` (tested on the host); this
//! module holds what the cores share: one table behind a spin lock, made once
//! at boot, and the numbers `$SYS/broker/connections/per_address/...` report.
//! A client's connections spread over the cores by the hash of the 4-tuple, so
//! one table is the only way for the bound to be per address and not per core.
//!
//! Where a connection is checked and given back is in `mqtt_service`:
//! [`syn_ok`] at the SYN (read-only), [`open`] at the final ACK before
//! admission takes a handshake token, [`close`] in the one function every
//! close path ends in. Refusals are counted per core with the admission
//! counters (`Reason::PerIpEstablished`).

use core::sync::atomic::{AtomicU64, Ordering};
use urmqtt_net::addr::Addr;

use urmqtt_config::CONFIG;
use urmqtt_log::info;
use urmqtt_net::source_limit::{Open, SourceKey, SourceTable, Stats};
use urmqtt_sync::sync::{OnceCell, SpinLock};

/// Addresses the table can hold (a power of two of eight-slot buckets): 24 B
/// each, 768 KiB. More distinct addresses than this at once are let through
/// untracked, counted in `untracked`.
const SLOTS: usize = 32_768;

static TABLE: OnceCell<SpinLock<SourceTable>> = OnceCell::new();

/// The bound the table was built with, 0 while off.
static LIMIT: AtomicU64 = AtomicU64::new(0);

/// The limit in force: `limits.max_connections_per_ip`, 0 (off) under the
/// development command line word `limits=bench`, which is for load tests from
/// one address (ADR-082).
pub fn limit(bench: bool) -> u32 {
    if bench {
        0
    } else {
        CONFIG.limits.max_connections_per_ip
    }
}

/// Makes the table, if there is a limit. Boot calls it once, after the random
/// generator is up and before the data cores start.
pub fn init(bench: bool) {
    let max = limit(bench);
    if max == 0 {
        info!("limits: no limit on established connections per address");
        return;
    }
    let mut key = [0u8; 8];
    // Fail closed, as for the plaintext table: the table is hashed under a key
    // an attacker must not know.
    if urmqtt_tls::rng::fill_global(&mut key).is_err() {
        crate::boot::fatal("limits: no random generator for the address table's key");
    }
    let _ = TABLE.set(SpinLock::new(SourceTable::new(
        SLOTS,
        u64::from_le_bytes(key),
        max,
    )));
    // Relaxed: set once at boot, before the data cores run.
    LIMIT.store(u64::from(max), Ordering::Relaxed);
    info!(
        "limits: at most {max} established connection(s) per source address (all cores, TLS and WebSocket); \
         up to {SLOTS} addresses tracked"
    );
}

/// An IPv4 address, or the /64 of an IPv6 one (NEXT-1, ADR-332).
fn key(ip: Addr) -> SourceKey {
    SourceKey::of(ip)
}

/// A SYN from `ip` on a TLS port: whether the address is under its limit.
/// Never changes the table.
pub fn syn_ok(ip: Addr) -> bool {
    TABLE.get().is_none_or(|t| t.lock().syn_ok(key(ip)))
}

/// What [`open`] decided.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Counted {
    /// The connection counts: [`close`] it once.
    Yes,
    /// No limit, or the table is full: nothing to give back.
    No,
    /// Over the limit: refuse.
    Refuse,
}

/// The final ACK of a TLS connection from `ip`.
pub fn open(ip: Addr) -> Counted {
    let Some(t) = TABLE.get() else {
        return Counted::No;
    };
    match t.lock().open(key(ip)) {
        Open::Counted => Counted::Yes,
        Open::Untracked => Counted::No,
        Open::TooMany => Counted::Refuse,
    }
}

/// A counted connection from `ip` ended.
pub fn close(ip: Addr) {
    if let Some(t) = TABLE.get() {
        t.lock().close(key(ip));
    }
}

/// The numbers `$SYS` reports.
pub fn info() -> (u64, Stats) {
    let limit = LIMIT.load(Ordering::Relaxed);
    (
        limit,
        TABLE.get().map_or(Stats::default(), |t| t.lock().stats()),
    )
}
