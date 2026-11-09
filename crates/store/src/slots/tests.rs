use super::*;
use alloc::boxed::Box;

use crate::disk::MemDisk;
use crate::fault::{FaultDevice, FaultSpec};
use crate::gpt::{ALIGN, DATA_TYPE, Options, prepare, prepare_with, raw_image, read_table};

const MIB: usize = 1 << 20;
const ESP_SECTORS: usize = 4096; // 2 MiB

/// A fake ESP whose bytes depend on `seed`.
fn esp(seed: u8) -> Vec<u8> {
    (0..ESP_SECTORS * 512)
        .map(|i| (i * 7 % 251) as u8 ^ seed)
        .collect()
}

fn counter() -> impl FnMut() -> [u8; 16] {
    let mut n = 0u8;
    move || {
        n = n.wrapping_add(1);
        [n; 16]
    }
}

const INIT: Init<'static> = Init {
    label: "v0.6.0",
    schema: 5,
};

/// An image of ESP `esp(0)` on a 64 MiB disk after its first boot with
/// slots.
fn ab_disk() -> MemDisk {
    let mut img = raw_image(&esp(0)).unwrap();
    img.resize(64 * MIB, 0);
    let m = MemDisk::from_image(img);
    let (_, steps) = prepare_with(
        m.device().as_mut(),
        counter(),
        Options {
            boot_slot: Some(INIT),
        },
    )
    .unwrap();
    assert!(steps.created_boot_slot && steps.created_partition);
    m
}

fn slots(m: &MemDisk) -> Slots {
    read(m.device().as_mut()).unwrap().unwrap()
}

/// The bytes of the region the ESP entry points at, as far as `esp` goes.
fn active_bytes(m: &MemDisk) -> Vec<u8> {
    let a = slots(m).active();
    m.raw(a.first_lba as usize * 512, ESP_SECTORS * 512)
}

fn note(version: &str, schema: u32) -> [u8; NOTE_LEN] {
    build_note(version, schema, 17)
}

#[test]
fn the_first_boot_reserves_the_standby_before_the_data_partition() {
    let m = ab_disk();
    let s = slots(&m);
    let t = &s.table;
    assert_eq!(t.entries.len(), 3);
    assert_eq!((s.esp, s.standby), (0, 1), "ESP first, then the standby");
    let (a, b) = (s.active(), s.standby_slot());
    assert_eq!(a.first_lba, ALIGN);
    assert_eq!(b.first_lba % ALIGN, 0);
    assert!(b.first_lba > a.last_lba);
    assert_eq!(a.sectors(), b.sectors());
    let data = t.data_partition().unwrap();
    assert!(data.first_lba > b.last_lba && data.first_lba.is_multiple_of(ALIGN));
    assert_eq!(a.label, "v0.6.0");
    assert_eq!(
        a.state,
        State {
            schema: 5,
            ..State::default()
        }
    );
    assert!(b.state.empty && !b.state.sealed);
    assert_eq!(t.entries[s.standby].attributes & NO_BLOCK_IO, NO_BLOCK_IO);
    assert_eq!(t.entries[s.esp].attributes & NO_BLOCK_IO, 0);
    assert_eq!((s.letter(&a), s.letter(&b)), ('A', 'B'));
    // The ESP's bytes are untouched; the standby's head is zero.
    assert_eq!(active_bytes(&m), esp(0));
    assert!(
        m.raw(b.first_lba as usize * 512, 32 * 1024)
            .iter()
            .all(|&x| x == 0)
    );
    // The next boot changes nothing.
    let before = m.raw(0, 64 * MIB);
    let (_, steps) = prepare_with(
        m.device().as_mut(),
        counter(),
        Options {
            boot_slot: Some(INIT),
        },
    )
    .unwrap();
    assert_eq!(steps, gpt::Steps::default());
    assert_eq!(m.raw(0, 64 * MIB), before);
    // And the first boot step on the active slot writes nothing either.
    let g = s.esp_guid();
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::Confirmed {
            slot: 'A',
            schema_updated: false
        }
    );
    assert_eq!(m.raw(0, 64 * MIB), before);
}

#[test]
fn without_room_or_with_a_data_partition_the_disk_stays_single() {
    // 2 MiB ESP, 20 MiB disk: the data partition's 16 MiB leave no room.
    let mut img = raw_image(&esp(0)).unwrap();
    img.resize(20 * MIB, 0);
    let m = MemDisk::from_image(img);
    let (_, steps) = prepare_with(
        m.device().as_mut(),
        counter(),
        Options {
            boot_slot: Some(INIT),
        },
    )
    .unwrap();
    assert!(steps.created_partition && !steps.created_boot_slot);
    assert!(read(m.device().as_mut()).unwrap().is_none());
    assert_eq!(
        boot_step(m.device().as_mut(), None, 5).unwrap(),
        Boot::Single
    );
    // An existing single-slot disk (prepared by an older kernel) stays so.
    let mut img = raw_image(&esp(0)).unwrap();
    img.resize(64 * MIB, 0);
    let m = MemDisk::from_image(img);
    prepare(m.device().as_mut(), counter()).unwrap();
    let (_, steps) = prepare_with(
        m.device().as_mut(),
        counter(),
        Options {
            boot_slot: Some(INIT),
        },
    )
    .unwrap();
    assert!(!steps.created_boot_slot);
    assert!(read(m.device().as_mut()).unwrap().is_none());
    assert_eq!(
        stage(m.device().as_mut(), &esp(1), "x", 5),
        Err(SlotError::NotAb)
    );
}

#[test]
fn the_first_boot_with_slots_survives_a_crash_at_every_write() {
    let mut img = raw_image(&esp(0)).unwrap();
    img.resize(64 * MIB, 0);
    let opts = Options {
        boot_slot: Some(INIT),
    };
    let probe = MemDisk::from_image(img.clone());
    let mut f = FaultDevice::new(probe.device(), FaultSpec::default());
    prepare_with(&mut f, counter(), opts).unwrap();
    let writes = f.writes();
    for n in 1..=writes {
        for spec in [
            FaultSpec {
                stop_after_writes: Some(n),
                ..FaultSpec::default()
            },
            FaultSpec {
                tear_write: Some((n, 1)),
                ..FaultSpec::default()
            },
        ] {
            for keep in [false, true] {
                let m = MemDisk::from_image(img.clone());
                let mut f = FaultDevice::new(m.device(), spec);
                assert!(prepare_with(&mut f, counter(), opts).is_err());
                m.crash(|_| keep);
                prepare_with(m.device().as_mut(), counter(), opts).unwrap();
                let s = slots(&m);
                assert_eq!(s.table.entries.len(), 3, "{spec:?} {keep}");
                assert_eq!(s.active().first_lba, ALIGN);
                assert_eq!(active_bytes(&m), esp(0));
            }
        }
    }
}

/// Stages `esp(seed)` into the standby with the note's version.
fn stage_seed(m: &MemDisk, seed: u8, schema: u8) -> Staged {
    stage(
        m.device().as_mut(),
        &esp(seed),
        &alloc::format!("v0.6.{seed}"),
        schema,
    )
    .unwrap()
}

const ACT: Activation = Activation {
    tries: 2,
    one_way: false,
    retry: false,
};

#[test]
fn an_update_that_confirms() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    let st = stage_seed(&m, 1, 5);
    assert_eq!(st.slot, 'B');
    let s = slots(&m);
    let b = s.standby_slot();
    assert!(b.state.sealed && !b.state.empty && b.state.schema == 5);
    assert_eq!(b.label, "v0.6.1");
    assert_eq!(b.digest, Some(commitment(&st.sha256)));
    // Staging did not touch the active slot.
    assert_eq!(active_bytes(&m), esp(0));
    assert_eq!(activate(m.device().as_mut(), ACT).unwrap(), ('A', 'B'));
    let s = slots(&m);
    assert_eq!(s.esp_guid(), g, "the ESP entry keeps its GUID");
    assert_eq!(active_bytes(&m), esp(1));
    let a = s.active();
    assert!(a.state.trial && a.state.tries == 2);
    assert_eq!(s.letter(&a), 'B');
    assert_eq!(s.table.entries[s.esp].attributes & NO_BLOCK_IO, 0);
    assert_eq!(
        s.table.entries[s.standby].attributes & NO_BLOCK_IO,
        NO_BLOCK_IO
    );
    // Staging again while on trial would destroy the way back.
    assert_eq!(
        stage(m.device().as_mut(), &esp(2), "x", 5),
        Err(SlotError::TrialPending)
    );
    assert_eq!(
        activate(m.device().as_mut(), ACT),
        Err(SlotError::TrialPending)
    );
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::Trial { slot: 'B', left: 1 }
    );
    assert!(confirm(m.device().as_mut()).unwrap());
    assert!(!confirm(m.device().as_mut()).unwrap());
    let a = slots(&m).active();
    assert!(!a.state.trial && !a.state.bad && a.state.sealed);
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::Confirmed {
            slot: 'B',
            schema_updated: false
        }
    );
    // The next update goes to A, and the operator may go back to B's
    // predecessor... which is A's old content until it is staged over.
    let st = stage_seed(&m, 2, 5);
    assert_eq!(st.slot, 'A');
    assert_eq!(activate(m.device().as_mut(), ACT).unwrap(), ('B', 'A'));
    assert_eq!(active_bytes(&m), esp(2));
}

#[test]
fn an_update_that_never_confirms_rolls_back() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    stage_seed(&m, 1, 5);
    activate(m.device().as_mut(), ACT).unwrap();
    for left in [1, 0] {
        assert_eq!(
            boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
            Boot::Trial { slot: 'B', left }
        );
    }
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::RolledBack {
            from: 'B',
            to: 'A',
            why: Why::Attempts
        }
    );
    let s = slots(&m);
    assert_eq!(active_bytes(&m), esp(0));
    assert!(!s.active().state.trial && !s.active().state.bad);
    assert!(s.standby_slot().state.bad);
    // The rolled-back slot is not activated again by accident.
    assert_eq!(
        activate(m.device().as_mut(), ACT),
        Err(SlotError::NotEligible(NotEligible::Bad))
    );
    assert_eq!(
        activate(m.device().as_mut(), Activation { retry: true, ..ACT }).unwrap(),
        ('A', 'B')
    );
    assert!(slots(&m).active().state.trial);
}

#[test]
fn rollback_needs_an_eligible_standby() {
    let m = ab_disk();
    // Fresh disk: the standby is empty.
    assert_eq!(
        rollback(m.device().as_mut()),
        Err(SlotError::NotEligible(NotEligible::Empty))
    );
    stage_seed(&m, 1, 5);
    activate(m.device().as_mut(), ACT).unwrap();
    confirm(m.device().as_mut()).unwrap();
    // A's bytes changed behind the tool's back: A was never sealed (the
    // first boot's slot), so it is still eligible.
    assert_eq!(rollback(m.device().as_mut()).unwrap(), ('B', 'A'));
    assert!(slots(&m).standby_slot().state.bad);
    // B is bad now: going back to it needs a new activation.
    assert_eq!(
        rollback(m.device().as_mut()),
        Err(SlotError::NotEligible(NotEligible::Bad))
    );
    // A sealed slot whose bytes changed is refused.
    stage_seed(&m, 3, 5);
    let b = slots(&m).standby_slot();
    let mut d = m.device();
    let mut sector = [0u8; 512];
    d.read(b.first_lba + 9, &mut sector).unwrap();
    sector[0] ^= 1;
    d.write(b.first_lba + 9, &sector).unwrap();
    d.flush().unwrap();
    assert_eq!(
        activate(m.device().as_mut(), ACT),
        Err(SlotError::NotEligible(NotEligible::Changed))
    );
}

#[test]
fn an_exhausted_trial_without_a_way_back_keeps_running() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    stage_seed(&m, 1, 5);
    activate(m.device().as_mut(), Activation { tries: 1, ..ACT }).unwrap();
    // The previous slot (A, now standby) gets damaged... by being marked
    // bad (a one-way migration ran).
    let s = slots(&m);
    let entries = s.with_states(
        s.active().state,
        State {
            bad: true,
            ..s.standby_slot().state
        },
    );
    s.commit(m.device().as_mut(), &entries).unwrap();
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::Trial { slot: 'B', left: 0 }
    );
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 5).unwrap(),
        Boot::Exhausted {
            slot: 'B',
            why: Why::Attempts,
            standby: NotEligible::Bad
        }
    );
    assert_eq!(active_bytes(&m), esp(1));
}

#[test]
fn a_newer_store_schema_needs_a_one_way_activation() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    stage_seed(&m, 1, 6);
    activate(m.device().as_mut(), ACT).unwrap();
    // The new kernel writes schema 6, the previous slot's reads 5.
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 6).unwrap(),
        Boot::RolledBack {
            from: 'B',
            to: 'A',
            why: Why::OneWayNotAllowed
        }
    );
    activate(
        m.device().as_mut(),
        Activation {
            one_way: true,
            retry: true,
            ..ACT
        },
    )
    .unwrap();
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 6).unwrap(),
        Boot::Trial { slot: 'B', left: 1 }
    );
    // The store migrated: the old kernel cannot read it any more.
    assert!(strand_standby(m.device().as_mut(), 6).unwrap());
    assert!(!strand_standby(m.device().as_mut(), 6).unwrap());
    assert_eq!(
        rollback(m.device().as_mut()),
        Err(SlotError::NotEligible(NotEligible::Bad))
    );
}

#[test]
fn the_firmware_booting_the_standby_during_a_trial_is_adopted() {
    let m = ab_disk();
    let (g, gs) = (slots(&m).esp_guid(), slots(&m).standby_guid());
    assert_ne!(g, gs);
    // Not on trial: the standby booting says something is wrong with the
    // ESP; nothing is written.
    let before = m.raw(0, 64 * MIB);
    assert_eq!(
        boot_step(m.device().as_mut(), Some(gs), 5).unwrap(),
        Boot::StandbyBooted { slot: 'B' }
    );
    assert_eq!(m.raw(0, 64 * MIB), before);
    assert_eq!(
        boot_step(m.device().as_mut(), Some(Guid([9; 16])), 5).unwrap(),
        Boot::Unknown
    );
    assert_eq!(
        boot_step(m.device().as_mut(), None, 5).unwrap(),
        Boot::Unknown
    );
    stage_seed(&m, 1, 5);
    activate(m.device().as_mut(), ACT).unwrap();
    assert_eq!(
        boot_step(m.device().as_mut(), Some(gs), 5).unwrap(),
        Boot::AdoptedStandby { slot: 'A' }
    );
    let s = slots(&m);
    assert_eq!(active_bytes(&m), esp(0));
    assert!(s.standby_slot().state.bad && !s.active().state.trial);
}

#[test]
fn an_in_place_kernel_update_refreshes_the_recorded_schema() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    assert_eq!(
        boot_step(m.device().as_mut(), Some(g), 6).unwrap(),
        Boot::Confirmed {
            slot: 'A',
            schema_updated: true
        }
    );
    assert_eq!(slots(&m).active().state.schema, 6);
}

/// What a reader sees: the bytes the ESP points at, the active and standby states.
type Seen = (Vec<u8>, State, State);

/// The state a reader sees after a cut: what the firmware boots (the valid
/// primary, else the backup) after the next boot's repair.
fn after_crash(m: &MemDisk) -> Seen {
    prepare(m.device().as_mut(), counter()).unwrap();
    let s = slots(m);
    (active_bytes(m), s.active().state, s.standby_slot().state)
}

/// Runs `op` on a fresh copy of `image` with a cut at every write (clean
/// and torn, the volatile cache lost and kept) and checks that the result
/// is `before` or `after` (bytes the ESP points at, states).
fn cut_everywhere(
    image: &[u8],
    op: &dyn Fn(&mut dyn BlockDevice) -> Result<(), SlotError>,
    ok: &dyn Fn(&Seen) -> bool,
) -> u64 {
    let probe = MemDisk::from_image(image.to_vec());
    let mut f = FaultDevice::new(probe.device(), FaultSpec::default());
    op(&mut f).unwrap();
    let writes = f.writes();
    assert!(writes > 0);
    for n in 1..=writes {
        for spec in [
            FaultSpec {
                stop_after_writes: Some(n),
                ..FaultSpec::default()
            },
            FaultSpec {
                tear_write: Some((n, 1)),
                ..FaultSpec::default()
            },
        ] {
            for keep in [false, true] {
                let m = MemDisk::from_image(image.to_vec());
                let mut f = FaultDevice::new(m.device(), spec);
                assert!(op(&mut f).is_err(), "{spec:?} must hit the fault");
                m.crash(|_| keep);
                let seen = after_crash(&m);
                assert!(ok(&seen), "{spec:?} keep={keep}: {:?} {:?}", seen.1, seen.2);
            }
        }
    }
    writes
}

#[test]
fn every_operation_survives_a_cut_at_every_write() {
    let m = ab_disk();
    let g = slots(&m).esp_guid();
    let fresh = m.raw(0, 64 * MIB);
    // Staging: the active slot is never touched; the standby is staged or
    // reads as empty (never sealed over half its bytes).
    let n = cut_everywhere(
        &fresh,
        &|d| stage(d, &esp(1), "v0.6.1", 5).map(|_| ()),
        &|(bytes, a, b)| {
            *bytes == esp(0) && !a.trial && (b.empty && !b.sealed || b.sealed && !b.empty)
        },
    );
    assert!(n >= 4, "{n}");
    stage_seed(&m, 1, 5);
    let staged = m.raw(0, 64 * MIB);
    // Activation: A in force, or B on trial with both tries.
    cut_everywhere(&staged, &|d| activate(d, ACT).map(|_| ()), &|(
        bytes,
        a,
        b,
    )| {
        (*bytes == esp(0) && !a.trial && b.sealed)
            || (*bytes == esp(1) && a.trial && a.tries == 2 && !b.trial)
    });
    activate(m.device().as_mut(), ACT).unwrap();
    let trial = m.raw(0, 64 * MIB);
    // A trial boot: two tries left, or one.
    cut_everywhere(&trial, &|d| boot_step(d, Some(g), 5).map(|_| ()), &|(
        bytes,
        a,
        _,
    )| {
        *bytes == esp(1) && a.trial && (a.tries == 2 || a.tries == 1)
    });
    // Confirmation: on trial, or confirmed.
    cut_everywhere(&trial, &|d| confirm(d).map(|_| ()), &|(bytes, a, _)| {
        *bytes == esp(1) && (a.trial || !a.trial && !a.bad)
    });
    // The automatic rollback: B on trial with no tries, or A in force and B bad.
    boot_step(m.device().as_mut(), Some(g), 5).unwrap();
    boot_step(m.device().as_mut(), Some(g), 5).unwrap();
    let spent = m.raw(0, 64 * MIB);
    cut_everywhere(&spent, &|d| boot_step(d, Some(g), 5).map(|_| ()), &|(
        bytes,
        a,
        b,
    )| {
        (*bytes == esp(1) && a.trial && a.tries == 0)
            || (*bytes == esp(0) && !a.trial && !a.bad && b.bad)
    });
    // The operator's rollback.
    cut_everywhere(&trial, &|d| rollback(d).map(|_| ()), &|(bytes, a, b)| {
        (*bytes == esp(1) && a.trial) || (*bytes == esp(0) && !a.trial && b.bad)
    });
}

#[test]
fn a_table_whose_backup_disagrees_is_repaired_from_the_primary() {
    let m = ab_disk();
    stage_seed(&m, 1, 5);
    // A cut after the backup copy of the activation: the backup says B,
    // the primary (in force) says A.
    let mut f = FaultDevice::new(
        m.device(),
        FaultSpec {
            stop_after_flushes: Some(1),
            ..FaultSpec::default()
        },
    );
    assert!(activate(&mut f, ACT).is_err());
    assert_eq!(
        read(m.device().as_mut()).err(),
        Some(SlotError::NeedsRepair)
    );
    let (_, steps) = prepare(m.device().as_mut(), counter()).unwrap();
    assert!(steps.repaired_backup);
    assert_eq!(active_bytes(&m), esp(0));
    assert!(!slots(&m).active().state.trial);
}

#[test]
fn tables_that_are_not_one_esp_and_one_standby_are_refused() {
    let m = ab_disk();
    let s = slots(&m);
    let mut entries = s.table.entries.clone();
    // A second standby.
    let mut extra = entries[s.standby];
    extra.first_lba = 60_000;
    extra.last_lba = 60_000 + ESP_SECTORS as u64 - 1;
    entries.insert(2, extra);
    assert_eq!(locate(&entries), Err(SlotError::Inconsistent));
    // Different sizes.
    let mut entries = s.table.entries.clone();
    entries[s.standby].last_lba -= 8;
    assert_eq!(locate(&entries), Err(SlotError::Inconsistent));
    // No standby: a single-slot table.
    let entries: Vec<Entry> = s
        .table
        .entries
        .iter()
        .copied()
        .filter(|e| e.type_guid != SLOT_TYPE)
        .collect();
    assert_eq!(locate(&entries), Ok(None));
    assert!(entries.iter().any(|e| e.type_guid == DATA_TYPE));
}

#[test]
fn state_bits_round_trip_and_stay_in_their_field() {
    for attr in [
        0u64,
        u64::MAX,
        0x0123_4567_89ab_cdef,
        STATE_MASK,
        !STATE_MASK,
    ] {
        let st = State::decode(attr);
        assert_eq!(st.encode(), attr & STATE_MASK);
        assert_eq!(st.encode() & !STATE_MASK, 0);
        assert_eq!(State::decode(st.encode()), st);
    }
    let st = State {
        tries: 200,
        ..State::default()
    };
    assert_eq!(State::decode(st.encode()).tries, MAX_TRIES);
}

#[test]
fn names_carry_label_and_commitment() {
    let d = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3];
    let n = slot_name("v0.6.0-12-g1234567-dirty-and-long-label", Some(d));
    let text = name_text(&n);
    assert_eq!(text.encode_utf16().count(), NAME_UNITS);
    assert!(text.ends_with("|deadbeef00010203"));
    let mut e = Entry::new(SLOT_TYPE, Guid::default(), 1, 2, "");
    e.name = n;
    e.attributes = State {
        sealed: true,
        ..State::default()
    }
    .encode();
    let s = Slot::from_entry(&e);
    assert_eq!(s.digest, Some(d));
    assert_eq!(s.label, "v0.6.0-12-g1234567-");
    // A label with a bar does not forge a commitment.
    let n = slot_name("a|0000000000000000", None);
    assert_eq!(name_text(&n), "a/0000000000000000");
    // Unsealed: the name is all label.
    e.attributes = 0;
    assert_eq!(Slot::from_entry(&e).digest, None);
}

#[test]
fn build_notes_are_found_and_checked() {
    let a = note("v0.6.0-3-gabcdef0", 5);
    let mut img = vec![0u8; 10_000];
    img[100..164].copy_from_slice(&a);
    img[7000..7064].copy_from_slice(&a);
    // A bare magic (the constant itself, followed by code) is no note.
    img[5000..5016].copy_from_slice(&NOTE_MAGIC);
    img[5016] = 0xff;
    let found = find_notes(&img);
    assert_eq!(found.len(), 2);
    assert_eq!(
        found[0],
        Note {
            ab_protocol: AB_PROTOCOL,
            schema: 5,
            cfg_format: 17,
            version: "v0.6.0-3-gabcdef0".into()
        }
    );
    // Every byte of the note is checked.
    for i in 16..NOTE_LEN {
        let mut b = a;
        b[i] ^= 0x80;
        let p = parse_note(&b);
        if (18..26).contains(&i) {
            // Protocol, schema and format are numbers: any value but 0 parses.
            assert!(p.is_some(), "byte {i}");
        } else {
            assert!(p.is_none(), "byte {i}");
        }
    }
    assert!(parse_note(&note("", 5)).is_none());
    assert!(parse_note(&note("v1", 0)).is_none());
    assert!(parse_note(&a[..63]).is_none());
    // A long version is cut at 32 bytes.
    let long = "v1.2.3-4567-gabcdefabcdefabcdefabcdef";
    assert_eq!(parse_note(&note(long, 5)).unwrap().version, &long[..32]);
}

#[test]
fn versions_parse_like_git_describe() {
    assert_eq!(parse_version("v0.6.0"), Some((0, 6, 0, 0)));
    assert_eq!(parse_version("0.5.1"), Some((0, 5, 1, 0)));
    assert_eq!(
        parse_version("v0.5.0-23-g6324d30-dirty"),
        Some((0, 5, 0, 23))
    );
    assert_eq!(parse_version("v0.6.0-rc1"), Some((0, 6, 0, 0)));
    assert!(parse_version("6324d30").is_none());
    assert!(parse_version("v1.2").is_none());
    assert!(parse_version("v1.2.3.4").is_none());
    assert!(parse_version("").is_none());
}

#[test]
fn a_stage_that_does_not_fit_is_refused_before_any_write() {
    let m = ab_disk();
    let before = m.raw(0, 64 * MIB);
    let big = vec![1u8; (ESP_SECTORS + 1) * 512];
    assert!(matches!(
        stage(m.device().as_mut(), &big, "x", 5),
        Err(SlotError::TooLarge { .. })
    ));
    assert!(matches!(
        stage(m.device().as_mut(), &[1u8; 100], "x", 5),
        Err(SlotError::TooLarge { .. })
    ));
    assert_eq!(m.raw(0, 64 * MIB), before);
    let _: Box<dyn BlockDevice> = m.device();
    let _ = read_table(m.device().as_mut(), 1).unwrap().unwrap();
}
