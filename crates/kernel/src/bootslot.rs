//! A/B boot slots in the kernel (NEXT-11, ADR-295 to ADR-299): the boot
//! step that counts a trial boot or switches back, the health confirmation,
//! the operator's confirm and rollback, and the build note an offline tool
//! reads to learn what a kernel image is.
//!
//! The partition-table work is `urmqtt_store::slots` (host-tested with a
//! power cut at every write); this module decides *when*:
//!
//! - [`at_boot`], from `devices::prepare_boot_disk`, right after the GPT
//!   first-boot steps and before the self-test, the store, the network and
//!   the other cores. A trial boot is counted before anything a broken
//!   update could break runs.
//! - [`after_store`], once the store is open: a one-way update that just
//!   migrated the store marks the previous slot unusable.
//! - [`poll`], on the DB core: the automatic confirmation (store open, a
//!   listener up, `update.confirm_after_s` of uptime), the trial timeout.
//! - [`control`], a `boot-confirm` or `boot-rollback` control message.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use urmqtt_config::{CONFIG, UpdateConfirm};
use urmqtt_log::{error, info, warn};
use urmqtt_store::BlockDevice;
use urmqtt_store::gpt::Guid;
use urmqtt_store::slots::{self, Boot, SlotError};
use urmqtt_sync::sync::SpinLock;

/// The store schema this kernel writes, as the slot state records it.
pub fn own_schema() -> u8 {
    u8::try_from(urmqtt_store::schema::VERSION).unwrap_or(u8::MAX)
}

/// The build note (`urmqtt_store::slots::build_note`): `urmqtt-disk slots
/// stage` finds it in an ESP image and refuses a kernel without one (it
/// would never confirm a trial).
pub static NOTE: [u8; slots::NOTE_LEN] = slots::build_note(
    crate::VERSION,
    urmqtt_store::schema::VERSION as u32,
    urmqtt_config::FORMAT_VERSION,
);

// Relaxed throughout: each flag is written by one core and read by others
// only to decide whether to act; the partition table on the disk is the
// state, these are hints.
/// This boot is a trial (the active slot is not confirmed).
static TRIAL: AtomicBool = AtomicBool::new(false);
/// The trial was confirmed during this boot.
static CONFIRMED: AtomicBool = AtomicBool::new(false);
/// A listener accepted its configuration (set by the MQTT service).
static LISTENING: AtomicBool = AtomicBool::new(false);
/// The activation allowed a one-way store migration.
static ONE_WAY: AtomicBool = AtomicBool::new(false);
/// The letter of the running slot (0: not an A/B disk).
static SLOT: AtomicU8 = AtomicU8::new(0);
/// When a listener came up (uptime ms).
static LISTENING_SINCE_MS: AtomicU64 = AtomicU64::new(0);
/// The boot disk's GPT disk GUID, for the control messages that name it.
static DISK_GUID: SpinLock<Option<Guid>> = SpinLock::new(None);

/// What the slot step did, for `$SYS` and the console.
pub fn slot() -> Option<char> {
    match SLOT.load(Ordering::Relaxed) {
        0 => None,
        c => Some(char::from(c)),
    }
}

pub fn on_trial() -> bool {
    TRIAL.load(Ordering::Relaxed) && !CONFIRMED.load(Ordering::Relaxed)
}

/// A listener is up (the first data core's MQTT service, any listener).
pub fn set_listening() {
    if !LISTENING.swap(true, Ordering::Relaxed) {
        LISTENING_SINCE_MS.store(
            urmqtt_arch::time::uptime_ns() / 1_000_000,
            Ordering::Relaxed,
        );
    }
}

fn letter(c: char) -> u8 {
    u8::try_from(u32::from(c)).unwrap_or(0)
}

/// The boot step on the boot disk (whole disk, after the GPT steps).
/// `booted` is the partition GUID Limine reports for the kernel file.
/// Returns `Err` only for an I/O error (the caller decides whether that is
/// an injected power cut).
pub fn at_boot(dev: &mut dyn BlockDevice, booted: Option<Guid>) -> Result<(), SlotError> {
    *DISK_GUID.lock() = urmqtt_store::gpt::disk_guid(dev).ok().flatten();
    let step = match slots::boot_step(dev, booted, own_schema()) {
        Ok(s) => s,
        Err(SlotError::Io(e)) => return Err(SlotError::Io(e)),
        Err(e) => {
            warn!("boot: the boot slots are unreadable ({e:?}); booting without A/B");
            return Ok(());
        }
    };
    let state = slots::read(dev).ok().flatten();
    let label = |which: Option<slots::Slot>| which.map(|s| s.label).unwrap_or_default();
    let active = state.as_ref().map(|s| s.active());
    let standby = state.as_ref().map(|s| s.standby_slot());
    let standby_text = || {
        standby
            .as_ref()
            .map(|s| {
                let st = s.state;
                if st.empty {
                    alloc::string::String::from("empty")
                } else {
                    alloc::format!(
                        "{} ({})",
                        s.label,
                        if st.bad {
                            "not bootable: failed, rolled back from, or its store schema is gone"
                        } else if st.trial {
                            "on trial"
                        } else {
                            "the way back"
                        }
                    )
                }
            })
            .unwrap_or_default()
    };
    match step {
        Boot::Single => info!(
            "boot: one boot slot (a disk prepared before v0.6.0): A/B updates need a disk installed by v0.6.0 or later; `urmqtt-disk update-boot` updates this one offline"
        ),
        Boot::Unknown => {
            info!("boot: the kernel was not loaded from this disk's boot slots: slot step skipped")
        }
        Boot::Confirmed {
            slot,
            schema_updated,
        } => {
            SLOT.store(letter(slot), Ordering::Relaxed);
            info!(
                "boot: slot {slot} ({}), confirmed; standby: {}{}",
                label(active),
                standby_text(),
                if schema_updated {
                    "; its recorded store schema was updated (the kernel was replaced in place)"
                } else {
                    ""
                }
            );
        }
        Boot::Trial { slot, left } => {
            SLOT.store(letter(slot), Ordering::Relaxed);
            TRIAL.store(true, Ordering::Relaxed);
            ONE_WAY.store(
                active.as_ref().is_some_and(|a| a.state.one_way),
                Ordering::Relaxed,
            );
            let u = CONFIG.update;
            warn!(
                "boot: slot {slot} ({}) ON TRIAL: {left} trial boot(s) left after this one; {}; standby: {}",
                label(active),
                match u.confirm {
                    UpdateConfirm::Auto => alloc::format!(
                        "confirmed after {} s with the store open and a listener up",
                        u.confirm_after_s
                    ),
                    UpdateConfirm::Operator => alloc::string::String::from(
                        "waiting for a boot-confirm control message (update.confirm = operator)",
                    ),
                },
                standby_text()
            );
        }
        Boot::RolledBack { from, to, why } => {
            error!(
                "boot: slot {from} gave up: {}; slot {to} ({}) is active again, resetting to boot it",
                why.text(),
                label(active)
            );
            crate::power::reboot();
        }
        Boot::AdoptedStandby { slot } => {
            SLOT.store(letter(slot), Ordering::Relaxed);
            warn!(
                "boot: {}; slot {slot} ({}) is active again and the slot on trial is marked bad",
                slots::Why::FirmwareFellBack.text(),
                label(active)
            );
        }
        Boot::StandbyBooted { slot } => {
            SLOT.store(letter(slot), Ordering::Relaxed);
            warn!(
                "boot: the firmware booted the standby slot {slot} although the active slot is confirmed: the active EFI system partition may be damaged; nothing changed (urmqtt-disk slots status)"
            );
        }
        Boot::Exhausted {
            slot,
            why,
            standby: n,
        } => {
            SLOT.store(letter(slot), Ordering::Relaxed);
            TRIAL.store(true, Ordering::Relaxed);
            error!(
                "boot: slot {slot} ({}): {}, but there is no way back (the previous slot: {}); booting it anyway",
                label(active),
                why.text(),
                n.text()
            );
        }
    }
    Ok(())
}

/// Runs `f` on the whole boot disk behind the open store.
fn with_whole_disk<R>(f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Option<R> {
    urmqtt_store::vfs::with_disk(|d| d.device_mut().whole_disk().map(f)).flatten()
}

/// After the store opened (schema `from` before its migrations): a trial
/// boot of a one-way update that migrated the store marks the previous slot
/// bad, since its kernel cannot read the store any more.
pub fn after_store(from: i64) {
    if !TRIAL.load(Ordering::Relaxed) || from >= i64::from(own_schema()) {
        return;
    }
    if !ONE_WAY.load(Ordering::Relaxed) {
        return;
    }
    match with_whole_disk(|d| slots::strand_standby(d, own_schema())) {
        Some(Ok(true)) => warn!(
            "boot: the store migrated from schema {from} to {}: the previous slot cannot read it any more and is no longer a way back (one-way update)",
            own_schema()
        ),
        Some(Ok(false)) | None => {}
        Some(Err(e)) => warn!("boot: marking the previous slot after the migration failed: {e:?}"),
    }
}

fn confirm_now(why: &str) -> Result<(), SlotError> {
    match with_whole_disk(slots::confirm) {
        Some(Ok(_)) => {
            CONFIRMED.store(true, Ordering::Relaxed);
            info!(
                "boot: slot {} confirmed ({why}); the previous slot stays as the way back",
                slot().unwrap_or('?')
            );
            Ok(())
        }
        Some(Err(e)) => Err(e),
        None => Err(SlotError::NotAb),
    }
}

/// The DB core, between its jobs: the automatic confirmation and the trial
/// timeout. Cheap when there is nothing to do.
pub fn poll(now_ms: u64) -> bool {
    if !on_trial() {
        return false;
    }
    let u = CONFIG.update;
    let timeout_ms = u64::from(u.trial_timeout_s) * 1000;
    if timeout_ms > 0 && now_ms >= timeout_ms {
        error!(
            "boot: slot {} was not confirmed within update.trial_timeout_s = {} s: resetting (the attempt counts)",
            slot().unwrap_or('?'),
            u.trial_timeout_s
        );
        crate::power::reboot();
    }
    if u.confirm != UpdateConfirm::Auto || !LISTENING.load(Ordering::Relaxed) {
        return false;
    }
    let since = LISTENING_SINCE_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(since) < u64::from(u.confirm_after_s) * 1000 {
        return false;
    }
    if let Err(e) = confirm_now(&alloc::format!(
        "healthy for {} s: store open, listener up",
        u.confirm_after_s
    )) {
        warn!("boot: the confirmation could not be written ({e:?}); trying again");
        return false;
    }
    true
}

/// A `boot-confirm` or `boot-rollback` control message for `disk` (DB core,
/// its sequence number already committed). `false`: refused.
pub fn control(rollback: bool, disk: &[u8]) -> Result<(), urmqtt_control::Reject> {
    use urmqtt_control::Reject;
    let ours = DISK_GUID.lock().map(|g| g.0);
    if ours.as_ref().map(|g| &g[..]) != Some(disk) {
        return Err(Reject::OtherDisk);
    }
    if !rollback {
        if !on_trial() {
            warn!("boot: boot-confirm: the running slot is not on trial");
            return Err(Reject::BootRefused);
        }
        return confirm_now("boot-confirm control message").map_err(|e| {
            warn!("boot: boot-confirm failed: {e:?}");
            Reject::BootRefused
        });
    }
    match with_whole_disk(slots::rollback) {
        Some(Ok((from, to))) => {
            error!(
                "boot: boot-rollback control message: slot {to} is active again, slot {from} is marked bad; resetting"
            );
            crate::power::reboot();
        }
        Some(Err(e)) => {
            warn!("boot: boot-rollback refused: {e:?}");
            Err(Reject::BootRefused)
        }
        None => Err(Reject::BootRefused),
    }
}

/// The build note's bytes, read once at boot so that the linker keeps them.
pub fn announce() {
    let n = core::hint::black_box(&NOTE);
    if let Some(note) = slots::parse_note(n) {
        info!(
            "build: {} (A/B protocol {}, store schema {}, configuration formats up to {})",
            note.version, note.ab_protocol, note.schema, note.cfg_format
        );
    }
}
