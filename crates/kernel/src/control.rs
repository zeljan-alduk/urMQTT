//! The identity lifecycle at runtime (H1, docs/SECURITY.md "Control
//! channel"): revocation and the device allowlist, changed by signed
//! control messages without a new image.
//!
//! - The broker hands `$urmqtt/control` publishes of control identities to
//!   its data core, which forwards them to the DB core unchanged.
//! - The DB core ([`handle`]) verifies the signature, freshness and
//!   sequence number, commits the effect together with the new sequence
//!   number, and only then publishes the new sets here and wakes every
//!   core.
//! - Each data core notices the new [`epoch`] and closes its connections
//!   whose certificate is now revoked or whose identity left the allowlist.
//!   New handshakes read the sets directly.
//!
//! Every rejection is counted by reason and logged rate-limited, without
//! message content.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use urmqtt_config::CONFIG;
use urmqtt_control::{Command, Policy, Reject};
use urmqtt_log::{info, warn};
use urmqtt_store::Store;
use urmqtt_sync::sync::{OnceCell, SpinLock};
use urmqtt_tls::RevocationList;

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(
    same(urmqtt_broker::CONTROL_TOPIC, urmqtt_control::TOPIC),
    "broker and control crate must agree on the control topic"
);

static REVOKED: OnceCell<Arc<RevocationList>> = OnceCell::new();
/// Serial tags (32-bit, see [`tag32`]) of every revoked serial, sorted,
/// for the live-connection scan.
static REVOKED_TAGS: SpinLock<Option<Arc<Vec<u32>>>> = SpinLock::new(None);
static ALLOWED: SpinLock<Option<Arc<BTreeSet<Box<str>>>>> = SpinLock::new(None);
static ALLOWLIST_MODE: AtomicBool = AtomicBool::new(false);
/// Bumped after every applied change (Release), read by every data core
/// (Acquire) before it looks at the sets.
static EPOCH: AtomicU64 = AtomicU64::new(0);

// Relaxed throughout: statistics.
pub static REJECTED: [AtomicU64; Reject::ALL.len()] =
    [const { AtomicU64::new(0) }; Reject::ALL.len()];
pub static APPLIED: AtomicU64 = AtomicU64::new(0);
/// Unknown identities refused after the handshake (allowlist mode).
pub static REGISTRY_REFUSED: AtomicU64 = AtomicU64::new(0);
/// Live connections closed because of a revocation or a disallow.
pub static LIVE_CLOSED: AtomicU64 = AtomicU64::new(0);

/// Normalised lowercase hex of a serial (no leading zero bytes), the form
/// the store and the configuration use.
pub fn serial_hex(serial: &[u8]) -> String {
    let first = serial.iter().position(|&b| b != 0).unwrap_or(serial.len());
    let mut s = String::with_capacity(2 * serial.len());
    for b in serial.get(first..).unwrap_or(&[]) {
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}

fn hex_bytes(h: &str) -> Option<Vec<u8>> {
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len() / 2)
        .map(|i| {
            h.get(2 * i..2 * i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

/// The sets at boot: revocations from the store (or the image without
/// storage) and the stored allowlist. `allowlist_mode` is the
/// configuration's mode, or the dev command line's stricter override.
pub fn init(revoked_hex: &[String], allowlist: &[String], allowlist_mode: bool) {
    let list = Arc::new(RevocationList::new(Vec::new()));
    let _ = REVOKED.set(list);
    // Relaxed: set before the data plane starts.
    ALLOWLIST_MODE.store(allowlist_mode, Ordering::Relaxed);
    publish(revoked_hex, allowlist);
    info!(
        "control: {}; registry {}, {} allowlisted identit{}; unrevoke {}",
        if CONFIG.control.service_ids.is_empty() {
            "channel off (no control.service_ids)".into()
        } else {
            alloc::format!(
                "channel on $urmqtt/control for {:?}, Ed25519 key {:02x}{:02x}{:02x}{:02x}…",
                CONFIG.control.service_ids,
                urmqtt_config::CONTROL_PUBLIC_KEY[0],
                urmqtt_config::CONTROL_PUBLIC_KEY[1],
                urmqtt_config::CONTROL_PUBLIC_KEY[2],
                urmqtt_config::CONTROL_PUBLIC_KEY[3]
            )
        },
        if allowlist_mode { "allowlist" } else { "open" },
        allowlist.len(),
        if allowlist.len() == 1 { "y" } else { "ies" },
        if CONFIG.control.allow_unrevoke {
            "allowed"
        } else {
            "off"
        }
    );
}

/// Replaces the sets every core reads and bumps the epoch.
fn publish(revoked_hex: &[String], allowlist: &[String]) {
    let serials: Vec<Vec<u8>> = revoked_hex.iter().filter_map(|h| hex_bytes(h)).collect();
    let mut tags: Vec<u32> = serials
        .iter()
        .map(|s| tag32(urmqtt_tls::serial_tag(s)))
        .collect();
    tags.sort_unstable();
    tags.dedup();
    if let Some(r) = REVOKED.get() {
        r.replace(serials);
    }
    *REVOKED_TAGS.lock() = Some(Arc::new(tags));
    *ALLOWED.lock() = Some(Arc::new(
        allowlist.iter().map(|s| s.as_str().into()).collect(),
    ));
    // Release: the sets above are visible to a core that sees the epoch.
    EPOCH.fetch_add(1, Ordering::Release);
}

/// The revocation list every TLS server shares.
pub fn revocations() -> Arc<RevocationList> {
    match REVOKED.get() {
        Some(r) => r.clone(),
        // Only before `init`: an empty list, never shared.
        None => Arc::new(RevocationList::new(Vec::new())),
    }
}

pub fn epoch() -> u64 {
    // Acquire: pairs with the Release in `publish`.
    EPOCH.load(Ordering::Acquire)
}

/// The per-connection form of a serial tag: its low 32 bits, never 0 (0
/// means "no certificate").
pub fn tag32(tag: u64) -> u32 {
    (tag as u32).max(1)
}

pub fn revoked_tags() -> Arc<Vec<u32>> {
    REVOKED_TAGS.lock().clone().unwrap_or_default()
}

pub fn allowlist_mode() -> bool {
    // Relaxed: set once at boot.
    ALLOWLIST_MODE.load(Ordering::Relaxed)
}

/// Identities the allowlist never applies to: the configured services and
/// control identities (they are named in the image already).
fn exempt(id: &str) -> bool {
    CONFIG.control.service_ids.contains(&id)
        || CONFIG
            .acl
            .service_ids
            .iter()
            .any(|p| match p.strip_suffix('*') {
                Some(prefix) => id.starts_with(prefix),
                None => *p == id,
            })
}

/// May operational identity `id` connect under the registry mode?
pub fn admitted(id: &str) -> bool {
    !allowlist_mode() || exempt(id) || ALLOWED.lock().as_ref().is_some_and(|set| set.contains(id))
}

/// Counts a rejection and logs it rate-limited (1st, 2nd, 4th, … of each
/// reason), naming only the publisher.
pub fn reject(r: Reject, from: &str) {
    let n = REJECTED
        .get(r.index())
        .map_or(0, |c| c.fetch_add(1, Ordering::Relaxed) + 1);
    if n.is_power_of_two() {
        warn!(
            "control: message from {from} rejected: {} ({n} so far)",
            r.reason()
        );
    }
}

fn policy() -> Policy {
    Policy {
        max_message_age_s: u64::from(CONFIG.control.max_message_age_s),
        allow_unrevoke: CONFIG.control.allow_unrevoke,
        allowlist_mode: allowlist_mode(),
    }
}

/// DB core: authenticates and applies one control message. `last_seq` is
/// the last accepted sequence number (also in the store). The store has
/// no open transaction.
pub fn handle(store: &mut Store, last_seq: &mut u64, from: &str, payload: &[u8]) {
    match apply(store, last_seq, from, payload) {
        Ok((cmd, n, seq)) => {
            APPLIED.fetch_add(1, Ordering::Relaxed);
            info!(
                "control: seq {seq} from {from}: {} of {n} item(s) applied",
                cmd.name()
            );
        }
        Err(r) => reject(r, from),
    }
}

fn apply(
    store: &mut Store,
    last_seq: &mut u64,
    from: &str,
    payload: &[u8],
) -> Result<(Command, usize, u64), Reject> {
    // The broker checked this already; the DB core does not rely on it.
    if !CONFIG.control.service_ids.contains(&from) {
        return Err(Reject::Unauthorized);
    }
    let m = urmqtt_control::verify(CONFIG.env, &urmqtt_config::CONTROL_PUBLIC_KEY, payload)?;
    urmqtt_control::check(&m, crate::boot::now_unix(), *last_seq, &policy())?;
    if m.command == Command::Unrevoke
        && m.items.iter().any(|s| {
            let h = serial_hex(s);
            CONFIG
                .tls
                .revoked_serials
                .iter()
                .any(|c| c.trim_start_matches("00") == h)
        })
    {
        return Err(Reject::ImageListed);
    }
    let now = crate::boot::now_unix().unwrap_or(0) as i64;
    let r = (|| {
        store.begin()?;
        for item in &m.items {
            match m.command {
                Command::Revoke => store.revoke(&serial_hex(item), "control", now)?,
                Command::Unrevoke => store.unrevoke(&serial_hex(item))?,
                Command::Allow => {
                    store.allow(core::str::from_utf8(item).unwrap_or_default(), m.seq, now)?
                }
                Command::Disallow => {
                    store.disallow(core::str::from_utf8(item).unwrap_or_default())?
                }
            }
        }
        store.set_control_seq(m.seq)?;
        store.commit()?;
        Ok::<_, urmqtt_store::StoreError>((store.revoked()?, store.allowlist()?))
    })();
    let (revoked, allowed) = match r {
        Ok(v) => v,
        Err(e) => {
            store.rollback();
            warn!("control: storing seq {} failed: {e}", m.seq);
            return Err(Reject::StorageFailed);
        }
    };
    *last_seq = m.seq;
    publish(&revoked, &allowed);
    wake_data_cores();
    Ok((m.command, m.items.len(), m.seq))
}

/// Gets every core out of `wfi` so it notices the new epoch at once.
fn wake_data_cores() {
    for cpu in 0..crate::smp::count() {
        if cpu != crate::smp::current() {
            crate::smp::send_wake(cpu);
        }
    }
}

/// A data core without durable storage refuses control messages.
pub fn refuse_without_storage(from: &str) {
    reject(Reject::NoStorage, from);
}
