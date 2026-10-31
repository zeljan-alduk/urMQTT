//! The write guard: whether the diagnostic may write to a disk at all, and
//! where. The rules, in order:
//!
//! 1. Never the installation medium, never a read-only device, never a disk
//!    that could not be read.
//! 2. Only inside a free extent (`space::free_extents`): sectors that no
//!    partition and no region of the data layout owns, and never the first
//!    or the last mebibyte of the disk (the backup GPT lives at the end).
//! 3. A disk this product did not install (blank, or holding something
//!    else) needs a typed confirmation before the first write. A disk
//!    without a partition table that is not blank is never written: its
//!    free space cannot be known.
//! 4. An installed disk needs no confirmation, because the window cannot
//!    touch anything it owns; with no free space the test is skipped and
//!    says why.

use crate::space::{self, Extent};

/// Smallest window worth measuring: 4 MiB.
pub const MIN_WINDOW_SECTORS: u64 = 8192;
/// Largest window written: 64 MiB.
pub const MAX_WINDOW_SECTORS: u64 = 64 * 2048;

/// What the disk holds, from reading its first and last mebibyte and its
/// partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskClass {
    /// A urMQTT data partition exists (its superblock may or may not parse).
    Installed,
    /// No partition table and zeros at both ends.
    Blank,
    /// Anything else; `gpt` says whether a valid partition table was found
    /// (so its unallocated space is known).
    Foreign { gpt: bool },
    /// The sectors needed to classify it could not be read.
    Unreadable,
}

/// What reading the disk showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub read_ok: bool,
    pub head_zero: bool,
    pub tail_zero: bool,
    pub gpt_valid: bool,
    pub has_data_partition: bool,
}

pub fn classify(p: &Probe) -> DiskClass {
    if !p.read_ok {
        DiskClass::Unreadable
    } else if p.gpt_valid && p.has_data_partition {
        DiskClass::Installed
    } else if !p.gpt_valid && p.head_zero && p.tail_zero {
        DiskClass::Blank
    } else {
        DiskClass::Foreign { gpt: p.gpt_valid }
    }
}

/// The facts the decision rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub class: DiskClass,
    pub read_only: bool,
    /// The medium the system booted from (the ISO as a disk).
    pub boot_medium: bool,
}

/// Why the write test did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    BootMedium,
    ReadOnly,
    Unreadable,
    /// No unallocated space of at least 4 MiB (installed disk: every sector
    /// belongs to a partition or a region).
    NoFreeSpace,
    /// A disk that is not blank and has no partition table.
    UnknownContents,
    /// The confirmation was not typed.
    NotConfirmed,
}

impl Skip {
    /// The sentence shown on the dashboard and in the JSON.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::BootMedium => "this is the boot medium, never written",
            Self::ReadOnly => "the device is read-only",
            Self::Unreadable => "the disk could not be read",
            Self::NoFreeSpace => {
                "no unallocated space: every sector belongs to a partition or a data region"
            }
            Self::UnknownContents => {
                "holds data but has no partition table, so its free space is unknown"
            }
            Self::NotConfirmed => "not confirmed on the keyboard",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Write inside this window.
    Run(Extent),
    /// The same window, once the operator has typed the confirmation.
    NeedConfirmation(Extent),
    Skip(Skip),
}

/// The window to write: the start of the largest free extent, at most
/// [`MAX_WINDOW_SECTORS`] long. `None` if none is long enough.
pub fn window(free: &[Extent]) -> Option<Extent> {
    let big = space::largest(free)?;
    let len = big.len().min(MAX_WINDOW_SECTORS);
    (len >= MIN_WINDOW_SECTORS).then(|| Extent::span(big.start, len))
}

/// Decides, given the free extents of the disk (`space::free_extents`) and
/// whether the operator has confirmed.
pub fn decide(f: &Facts, free: &[Extent], confirmed: bool) -> Decision {
    if f.boot_medium {
        return Decision::Skip(Skip::BootMedium);
    }
    if f.read_only {
        return Decision::Skip(Skip::ReadOnly);
    }
    match f.class {
        DiskClass::Unreadable => Decision::Skip(Skip::Unreadable),
        DiskClass::Foreign { gpt: false } => Decision::Skip(Skip::UnknownContents),
        DiskClass::Installed => match window(free) {
            Some(w) => Decision::Run(w),
            None => Decision::Skip(Skip::NoFreeSpace),
        },
        DiskClass::Blank | DiskClass::Foreign { gpt: true } => match window(free) {
            None => Decision::Skip(Skip::NoFreeSpace),
            Some(w) if confirmed => Decision::Run(w),
            Some(w) => Decision::NeedConfirmation(w),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 2048;

    fn facts(class: DiskClass) -> Facts {
        Facts {
            class,
            read_only: false,
            boot_medium: false,
        }
    }

    fn probe() -> Probe {
        Probe {
            read_ok: true,
            head_zero: false,
            tail_zero: false,
            gpt_valid: false,
            has_data_partition: false,
        }
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify(&Probe {
                read_ok: false,
                ..probe()
            }),
            DiskClass::Unreadable
        );
        assert_eq!(
            classify(&Probe {
                gpt_valid: true,
                has_data_partition: true,
                ..probe()
            }),
            DiskClass::Installed
        );
        // Installed beats "zeros at both ends" (cannot happen, but order matters).
        assert_eq!(
            classify(&Probe {
                gpt_valid: true,
                has_data_partition: true,
                head_zero: true,
                tail_zero: true,
                ..probe()
            }),
            DiskClass::Installed
        );
        assert_eq!(
            classify(&Probe {
                head_zero: true,
                tail_zero: true,
                ..probe()
            }),
            DiskClass::Blank
        );
        // Zero head but data at the tail: someone's disk.
        assert_eq!(
            classify(&Probe {
                head_zero: true,
                ..probe()
            }),
            DiskClass::Foreign { gpt: false }
        );
        assert_eq!(
            classify(&Probe {
                gpt_valid: true,
                ..probe()
            }),
            DiskClass::Foreign { gpt: true }
        );
        // A data partition entry without a valid table is not "installed".
        assert_eq!(
            classify(&Probe {
                has_data_partition: true,
                ..probe()
            }),
            DiskClass::Foreign { gpt: false }
        );
    }

    #[test]
    fn window_choice() {
        assert_eq!(window(&[]), None);
        assert_eq!(
            window(&[Extent::new(MIB, MIB + 3 * MIB)]),
            None,
            "3 MiB is below the minimum"
        );
        assert_eq!(
            window(&[Extent::new(MIB, 5 * MIB)]),
            Some(Extent::new(MIB, 5 * MIB))
        );
        // Capped at 64 MiB, from the start of the largest extent.
        assert_eq!(
            window(&[Extent::new(10 * MIB, 20 * MIB), Extent::new(MIB, 900 * MIB)]),
            Some(Extent::new(MIB, 65 * MIB))
        );
    }

    /// The whole table: class x read-only x boot medium x free space x
    /// confirmed.
    #[test]
    fn decision_table() {
        let none: [Extent; 0] = [];
        let some = [Extent::new(MIB, 101 * MIB)];
        let win = Extent::new(MIB, 65 * MIB);
        let skip = |s| Decision::Skip(s);

        // Rule 1 beats everything.
        for class in [
            DiskClass::Installed,
            DiskClass::Blank,
            DiskClass::Foreign { gpt: true },
            DiskClass::Foreign { gpt: false },
            DiskClass::Unreadable,
        ] {
            for confirmed in [false, true] {
                let mut f = facts(class);
                f.boot_medium = true;
                assert_eq!(
                    decide(&f, &some, confirmed),
                    skip(Skip::BootMedium),
                    "{class:?}"
                );
                f.boot_medium = false;
                f.read_only = true;
                assert_eq!(
                    decide(&f, &some, confirmed),
                    skip(Skip::ReadOnly),
                    "{class:?}"
                );
            }
        }
        // Boot medium is reported before read-only.
        assert_eq!(
            decide(
                &Facts {
                    class: DiskClass::Blank,
                    read_only: true,
                    boot_medium: true
                },
                &some,
                true
            ),
            skip(Skip::BootMedium)
        );

        // Installed: runs without confirmation if (and only if) space exists.
        assert_eq!(
            decide(&facts(DiskClass::Installed), &some, false),
            Decision::Run(win)
        );
        assert_eq!(
            decide(&facts(DiskClass::Installed), &some, true),
            Decision::Run(win)
        );
        assert_eq!(
            decide(&facts(DiskClass::Installed), &none, false),
            skip(Skip::NoFreeSpace)
        );
        assert_eq!(
            decide(&facts(DiskClass::Installed), &none, true),
            skip(Skip::NoFreeSpace)
        );
        assert_eq!(
            decide(
                &facts(DiskClass::Installed),
                &[Extent::new(MIB, 2 * MIB)],
                true
            ),
            skip(Skip::NoFreeSpace),
            "a 1 MiB gap is too small"
        );

        // Blank and foreign-with-a-table: confirmation first.
        for class in [DiskClass::Blank, DiskClass::Foreign { gpt: true }] {
            assert_eq!(
                decide(&facts(class), &some, false),
                Decision::NeedConfirmation(win),
                "{class:?}"
            );
            assert_eq!(
                decide(&facts(class), &some, true),
                Decision::Run(win),
                "{class:?}"
            );
            assert_eq!(
                decide(&facts(class), &none, true),
                skip(Skip::NoFreeSpace),
                "{class:?}"
            );
        }

        // Unknown contents without a table, and unreadable: never, however confirmed.
        for confirmed in [false, true] {
            assert_eq!(
                decide(&facts(DiskClass::Foreign { gpt: false }), &some, confirmed),
                skip(Skip::UnknownContents)
            );
            assert_eq!(
                decide(&facts(DiskClass::Unreadable), &some, confirmed),
                skip(Skip::Unreadable)
            );
        }
    }

    /// Whatever the decision, a `Run` window is inside the free space and
    /// clear of both guards, over many disks.
    #[test]
    fn a_run_window_is_always_free_and_guarded() {
        for total_mib in [3u64, 4, 5, 6, 9, 16, 64, 100, 1000, 100_000] {
            let total = total_mib * MIB + 17;
            let free = space::free_extents(total, &[]);
            if let Decision::Run(w) | Decision::NeedConfirmation(w) =
                decide(&facts(DiskClass::Blank), &free, true)
            {
                assert!(space::window_is_free(w, &free), "{total_mib} MiB");
                assert!(w.start >= space::HEAD_GUARD, "{total_mib} MiB");
                assert!(w.end <= total - space::TAIL_GUARD, "{total_mib} MiB");
                assert!(w.len() <= MAX_WINDOW_SECTORS);
            }
        }
        // A 5 MiB disk has no 4 MiB window between the guards; 6 MiB has.
        let tiny = space::free_extents(5 * MIB, &[]);
        assert_eq!(
            decide(&facts(DiskClass::Blank), &tiny, true),
            Decision::Skip(Skip::NoFreeSpace)
        );
        let ok = space::free_extents(6 * MIB, &[]);
        assert!(matches!(
            decide(&facts(DiskClass::Blank), &ok, true),
            Decision::Run(_)
        ));
    }

    #[test]
    fn reasons_are_sentences() {
        for s in [
            Skip::BootMedium,
            Skip::ReadOnly,
            Skip::Unreadable,
            Skip::NoFreeSpace,
            Skip::UnknownContents,
            Skip::NotConfirmed,
        ] {
            assert!(s.reason().len() > 10);
        }
    }
}
