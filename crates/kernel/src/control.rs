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
//! Password accounts (NOW-15, ADR-285) ride the same channel: `set-account`
//! and `remove-account` change the table in the store (PBKDF2 hashes only),
//! and every data core reloads the accounts of its plaintext and WebSocket
//! listeners on the new epoch and closes the live logins of an account that
//! was removed or changed.
//!
//! Every rejection is counted by reason and logged rate-limited, without
//! message content.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use urmqtt_config::CONFIG;
use urmqtt_control::{Command, Policy, Reject};
use urmqtt_log::{info, warn};
use urmqtt_plain::{Account, Accounts};
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
/// The run-time password accounts, sorted by id (ADR-285).
static ACCOUNTS: SpinLock<Option<Accounts>> = SpinLock::new(None);
/// Their number, so that the class lookup of a login session costs nothing
/// when there are none.
static ACCOUNT_COUNT: AtomicUsize = AtomicUsize::new(0);
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
pub fn init(
    revoked_hex: &[String],
    allowlist: &[String],
    accounts: &[(String, String, u8)],
    allowlist_mode: bool,
) {
    let list = Arc::new(RevocationList::new(Vec::new()));
    let _ = REVOKED.set(list);
    // Relaxed: set before the data plane starts.
    ALLOWLIST_MODE.store(allowlist_mode, Ordering::Relaxed);
    publish(revoked_hex, allowlist, accounts);
    info!(
        "control: {}; registry {}, {} allowlisted identit{}; unrevoke {}",
        if CONFIG.control.service_ids.is_empty() {
            "channel off (no control.service_ids)".into()
        } else {
            alloc::format!(
                "channel on $urmqtt/control for {:?}, Ed25519 key {:02x}{:02x}{:02x}{:02x}…",
                CONFIG.control.service_ids,
                urmqtt_config::CONFIG.control.public_key[0],
                urmqtt_config::CONFIG.control.public_key[1],
                urmqtt_config::CONFIG.control.public_key[2],
                urmqtt_config::CONFIG.control.public_key[3]
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
    if CONFIG.limits.max_runtime_accounts > 0 {
        info!(
            "control: run-time password accounts on: {} stored, at most {}",
            accounts.len(),
            CONFIG.limits.max_runtime_accounts
        );
    }
}

/// Replaces the sets every core reads and bumps the epoch.
fn publish(revoked_hex: &[String], allowlist: &[String], accounts: &[(String, String, u8)]) {
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
    // A stored hash that no longer parses can never log in.
    let mut list: Vec<Account> = accounts
        .iter()
        // The image wins: a row for an id the image itself lists since
        // (or names as a service, operator or control identity) is inert, so
        // that it neither narrows nor closes the image's own account.
        .filter(|(id, _, _)| !reserved_id(id))
        .filter_map(|(id, hash, class)| Account::parse(id, hash, *class))
        .collect();
    list.sort_by(|a, b| a.id.cmp(&b.id));
    ACCOUNT_COUNT.store(list.len(), Ordering::Relaxed);
    *ACCOUNTS.lock() = Some(Arc::new(list));
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

/// The run-time password accounts, sorted by id.
pub fn accounts() -> Accounts {
    ACCOUNTS.lock().clone().unwrap_or_default()
}

/// The ACL class byte of the run-time account `id` (0, full, when there is
/// none): the broker asks at every publish and SUBSCRIBE of a login session.
pub fn account_class(id: &str) -> u8 {
    // Relaxed: a hint; the lock decides.
    if ACCOUNT_COUNT.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let guard = ACCOUNTS.lock();
    let Some(list) = guard.as_ref() else { return 0 };
    list.binary_search_by(|a| a.id.as_str().cmp(id))
        .ok()
        .and_then(|i| list.get(i))
        .map_or(0, |a| a.class)
}

/// Whether some listener of this image checks passwords: without one a
/// run-time account could never log in.
pub fn password_listener() -> bool {
    use urmqtt_config::{PlainAuth, WsAuth};
    (CONFIG.plaintext.enabled && CONFIG.plaintext.auth == PlainAuth::Password)
        || (CONFIG.websocket.enabled
            && CONFIG.network.mqtt_tls_port != 0
            && CONFIG.websocket.auth == WsAuth::Password)
}

/// Whether the image itself lists a password account `id` (on either
/// listener), or names it as a service, operator or control identity: such
/// an id cannot be a run-time account (the image wins).
fn reserved_id(id: &str) -> bool {
    CONFIG.plaintext.users.iter().any(|u| u.id == id)
        || CONFIG.websocket.users.iter().any(|u| u.id == id)
        || exempt(id)
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

/// Identities the allowlist never applies to: the configured services,
/// operators and control identities (they are named in the image already).
fn exempt(id: &str) -> bool {
    CONFIG.control.service_ids.contains(&id)
        || CONFIG.acl.operator_ids.contains(&id)
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
        accounts: CONFIG.limits.max_runtime_accounts > 0,
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
    let m = urmqtt_control::verify(
        CONFIG.env,
        &urmqtt_config::CONFIG.control.public_key,
        payload,
    )?;
    urmqtt_control::check(&m, crate::boot::now_unix(), *last_seq, &policy())?;
    if m.command.on_boot() {
        return apply_boot(store, last_seq, &m);
    }
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
    if m.command == Command::SetAccount {
        if !password_listener() {
            return Err(Reject::NoPasswordListener);
        }
        for item in &m.items {
            let a = urmqtt_control::parse_account(item)?;
            if reserved_id(a.id) {
                return Err(Reject::AccountShadowsImage);
            }
        }
    }
    let now = crate::boot::now_unix().unwrap_or(0) as i64;
    let r = (|| {
        store.begin()?;
        for item in &m.items {
            match m.command {
                Command::SetAccount => {
                    // The decoder checked the item; a failure here is a bug
                    // and leaves the row alone.
                    if let Ok(a) = urmqtt_control::parse_account(item) {
                        store.account_set(a.id, a.hash, a.class as u8, m.seq, now)?;
                    }
                }
                Command::RemoveAccount => {
                    store.account_del(core::str::from_utf8(item).unwrap_or_default())?
                }
                // Handled by `apply_boot` above.
                Command::BootConfirm | Command::BootRollback => {}
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
        let count = store.account_count()?;
        if m.command.on_accounts() && count > i64::from(CONFIG.limits.max_runtime_accounts) {
            // Nothing is stored and the sequence number is not used up.
            store.rollback();
            return Ok::<_, urmqtt_store::StoreError>(None);
        }
        store.set_control_seq(m.seq)?;
        store.commit()?;
        Ok(Some((
            store.revoked()?,
            store.allowlist()?,
            store.accounts()?,
        )))
    })();
    let (revoked, allowed, accounts) = match r {
        Ok(Some(v)) => v,
        Ok(None) => return Err(Reject::AccountLimit),
        Err(e) => {
            store.rollback();
            warn!("control: storing seq {} failed: {e}", m.seq);
            return Err(Reject::StorageFailed);
        }
    };
    *last_seq = m.seq;
    if m.command.on_accounts() {
        // Audit: which accounts changed and how, never a hash or a password.
        for item in &m.items {
            match m.command {
                Command::SetAccount => {
                    if let Ok(a) = urmqtt_control::parse_account(item) {
                        info!(
                            "control: seq {} from {from}: password account {} set (class {}, {} run-time account(s))",
                            m.seq,
                            a.id,
                            a.class.name(),
                            accounts.len()
                        );
                    }
                }
                _ => info!(
                    "control: seq {} from {from}: password account {} removed ({} run-time account(s) left)",
                    m.seq,
                    core::str::from_utf8(item).unwrap_or("?"),
                    accounts.len()
                ),
            }
        }
    }
    publish(&revoked, &allowed, &accounts);
    wake_data_cores();
    Ok((m.command, m.items.len(), m.seq))
}

/// A boot command (ADR-298): its one item must be this boot disk's GUID.
/// The sequence number commits first (a replay is refused even if the slot
/// write fails), then the slot table changes; a rollback resets.
fn apply_boot(
    store: &mut Store,
    last_seq: &mut u64,
    m: &urmqtt_control::Message,
) -> Result<(Command, usize, u64), Reject> {
    let disk = m.items.first().ok_or(Reject::Malformed)?;
    let r = (|| {
        store.begin()?;
        store.set_control_seq(m.seq)?;
        store.commit()
    })();
    if let Err(e) = r {
        store.rollback();
        warn!("control: storing seq {} failed: {e}", m.seq);
        return Err(Reject::StorageFailed);
    }
    *last_seq = m.seq;
    crate::bootslot::control(m.command == Command::BootRollback, disk)?;
    Ok((m.command, 1, m.seq))
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
