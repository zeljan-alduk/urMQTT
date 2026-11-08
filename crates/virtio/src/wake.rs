//! How a sleeping dispatcher learns that its NIC received a frame: the
//! receive queue's MSI-X interrupt, or a poll (ADR-270, amending ADR-224).
//! Pure logic: the kernel feeds it the interrupt counter and what it found
//! after each sleep, and asks it how long a sleep may last.
//!
//! The protocol around a sleep (the queue side is
//! [`SplitQueue::enable_interrupts`](crate::queue::SplitQueue::enable_interrupts)):
//! interrupts stay suppressed while the dispatcher works (no storm under a
//! flood: it polls while busy); just before it sleeps, with the CPU's own
//! interrupts masked, it enables them and re-checks the used ring; it
//! sleeps only when nothing is there; awake, it suppresses them again.
//!
//! The interrupt is not trusted until it has been seen to work: the mode
//! starts **on probation**, arming the interrupt before every sleep but also
//! keeping ADR-224's poll deadline, so a broken delivery costs nothing. It is
//! *verified* once [`VERIFY_HITS`] sleeps were ended by the receive interrupt
//! (the first DHCP, ARP and ICMP replies of the boot do that); only then does
//! the dispatcher sleep without a deadline. A *miss* is an armed sleep that
//! ended with a received frame waiting and no receive interrupt counted: on
//! probation [`MISSES_BEFORE_POLLING`] misses before the verification, and
//! later that many misses among any [`MISS_WINDOW`] armed sleeps that ended
//! with a frame, make the mode fall back to polling for good, and the kernel
//! says so (ADR-270). A delivery that works only sometimes is caught as well
//! as one that never works.

/// Misses that end the trust in the interrupt (see the module text). A frame
/// can legitimately land between reading the counter and the ring, or the
/// interrupt be delivered just after a deadline ended the sleep, but not a
/// quarter of the time.
pub const MISSES_BEFORE_POLLING: u8 = 8;
/// Armed sleeps ended with a frame (hits and misses) per counting window.
pub const MISS_WINDOW: u8 = 32;
/// Sleeps ended by the receive interrupt that verify it.
pub const VERIFY_HITS: u8 = 3;
/// On probation the dispatcher comes back after this long at the latest while
/// connections exist (ns). Longer than ADR-224's 200 us so that an interrupt
/// delivered a little late (an emulated interrupt controller) does not count as
/// a miss because a deadline ended the sleep first; short enough that a broken
/// delivery costs at most a millisecond per frame until the fallback.
pub const PROBATION_POLL_NS: u64 = 1_000_000;

/// After NIC traffic, interrupt mode keeps polling for this long before it
/// arms the interrupt (ns). Under a steady stream a dispatcher that armed the
/// interrupt at every short idle gap was woken once per gap by an MSI, which
/// on the rig (one data core, HVF) cost a fifth of the QoS 0 flood rate and
/// raised the 99th percentile at 16 000 messages/s; polling while traffic is
/// recent batches frames as ADR-224 did, and the interrupt takes over once the
/// NIC has been quiet for this long (ADR-270).
pub const HOLD_NS: u64 = 2_000_000;

/// What a dispatcher does before it sleeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Ask for the receive interrupt (and re-check the ring).
    pub arm: bool,
    /// Come back after this long at the latest (ns; 0: only the tick and
    /// wake-ups).
    pub poll_ns: u64,
}

/// Why the receive queue is polled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// `devices.virtio_net_interrupt = "off"`.
    Configured,
    /// The device has no MSI-X capability.
    NoMsix,
    /// The platform offers no MSI target (aarch64: neither a GICv2m frame
    /// nor a GICv3 ITS).
    NoMsiSource,
    /// The GICv3 ITS could not be set up (the kernel logs why).
    ItsFailed,
    /// Every MSI vector or SPI of the platform is already in use.
    NoVector,
    /// The MSI-X table could not be mapped.
    TableUnmapped,
    /// The device refused the vector for its receive queue.
    Rejected,
    /// The interrupt was set up but never arrived (see [`MISSES_BEFORE_POLLING`]).
    Silent,
}

impl Why {
    /// For the boot log and the fallback warning.
    pub const fn text(self) -> &'static str {
        match self {
            Self::Configured => "devices.virtio_net_interrupt = \"off\"",
            Self::NoMsix => "the device has no MSI-X",
            Self::NoMsiSource => "no MSI target on this platform (no GICv2m frame, no GICv3 ITS)",
            Self::ItsFailed => "the GICv3 ITS could not be set up",
            Self::NoVector => "no free MSI vector",
            Self::TableUnmapped => "the MSI-X table could not be mapped",
            Self::Rejected => "the device refused the MSI-X vector",
            Self::Silent => "the receive interrupt did not arrive for frames that waited",
        }
    }
}

/// How the dispatcher is woken for received frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The receive queue's MSI-X vector, routed to the dispatcher's core, and
    /// verified (see the module text).
    Interrupt,
    /// The vector is set up but not yet verified: armed before every sleep,
    /// and the poll deadline kept.
    Probation,
    /// The deadline timer, at most every poll period while connections exist
    /// (ADR-224), and the 10 ms tick.
    Polling(Why),
}

/// The dispatcher's receive wake-up state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxWake {
    mode: Mode,
    /// In the current window: armed sleeps that ended with a frame and no
    /// interrupt (misses), and that ended by the interrupt (hits).
    misses: u8,
    hits: u8,
    /// The interrupt counter when the queue was last armed.
    irqs_at_arm: u64,
}

/// What a sleep changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    /// The interrupt is verified: no more poll deadline while idle.
    Verified,
    /// The interrupt is not trusted any more: polling from now on.
    FellBack,
}

impl RxWake {
    /// `Mode::Interrupt` asked for starts on probation.
    pub const fn new(mode: Mode) -> Self {
        Self {
            mode: match mode {
                Mode::Interrupt => Mode::Probation,
                m => m,
            },
            misses: 0,
            hits: 0,
            irqs_at_arm: 0,
        }
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether the receive interrupt is in use (verified or on probation).
    pub const fn interrupt(&self) -> bool {
        matches!(self.mode, Mode::Interrupt | Mode::Probation)
    }

    /// How often a sleeping dispatcher must come back by itself (ns; 0: only
    /// the tick and wake-ups): never in interrupt mode, `poll_ns` while
    /// connections exist in polling mode (ADR-224).
    pub const fn poll_ns(&self, connections: bool, poll_ns: u64) -> u64 {
        match self.mode {
            Mode::Interrupt => 0,
            Mode::Probation | Mode::Polling(_) if connections => poll_ns,
            Mode::Probation | Mode::Polling(_) => 0,
        }
    }

    /// The plan for the next sleep: `connections` whether any data core holds
    /// one, `since_traffic_ns` how long ago the NIC last moved a frame.
    /// Interrupt mode: poll as ADR-224 did while traffic is recent (within
    /// [`HOLD_NS`], and only with connections), else arm the interrupt and do
    /// not poll at all. Polling mode: [`poll_ns`](Self::poll_ns).
    pub const fn plan(&self, connections: bool, since_traffic_ns: u64, poll_ns: u64) -> Plan {
        match self.mode {
            Mode::Interrupt if connections && since_traffic_ns < HOLD_NS => Plan {
                arm: false,
                poll_ns,
            },
            Mode::Interrupt => Plan {
                arm: true,
                poll_ns: 0,
            },
            // Armed, with a deadline while connections exist, until verified.
            Mode::Probation => Plan {
                arm: true,
                poll_ns: if connections {
                    if poll_ns > PROBATION_POLL_NS {
                        poll_ns
                    } else {
                        PROBATION_POLL_NS
                    }
                } else {
                    0
                },
            },
            Mode::Polling(_) => Plan {
                arm: false,
                poll_ns: self.poll_ns(connections, poll_ns),
            },
        }
    }

    /// The interrupt counter when the queue was last armed.
    pub const fn irqs_at_arm(&self) -> u64 {
        self.irqs_at_arm
    }

    /// The queue was armed; `irqs` is the interrupt counter now.
    pub fn armed(&mut self, irqs: u64) {
        self.irqs_at_arm = irqs;
    }

    /// After an armed sleep: `irqs` is the interrupt counter now, `waiting`
    /// whether a received frame was waiting. Returns what changed (the caller
    /// logs a verification or a fallback once).
    pub fn after_sleep(&mut self, irqs: u64, waiting: bool) -> Change {
        if !self.interrupt() {
            return Change::None;
        }
        if irqs != self.irqs_at_arm {
            self.hits = self.hits.saturating_add(1);
        } else if waiting {
            self.misses = self.misses.saturating_add(1);
        } else {
            return Change::None;
        }
        if self.misses >= MISSES_BEFORE_POLLING {
            self.mode = Mode::Polling(Why::Silent);
            return Change::FellBack;
        }
        if self.mode == Mode::Probation && self.hits >= VERIFY_HITS {
            self.mode = Mode::Interrupt;
            self.hits = 0;
            self.misses = 0;
            return Change::Verified;
        }
        if self.mode == Mode::Interrupt && self.hits.saturating_add(self.misses) >= MISS_WINDOW {
            self.hits = 0;
            self.misses = 0;
        }
        Change::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL: u64 = 200_000;

    /// An interrupt asked for, verified by `VERIFY_HITS` sleeps it ended.
    fn verified() -> RxWake {
        let mut w = RxWake::new(Mode::Interrupt);
        for i in 0..u64::from(VERIFY_HITS) {
            w.armed(i);
            let c = w.after_sleep(i + 1, true);
            assert_eq!(c == Change::Verified, i + 1 == u64::from(VERIFY_HITS));
        }
        assert_eq!(w.mode(), Mode::Interrupt);
        w
    }

    #[test]
    fn an_interrupt_starts_on_probation_with_a_deadline() {
        let w = RxWake::new(Mode::Interrupt);
        assert_eq!(w.mode(), Mode::Probation);
        assert!(w.interrupt());
        assert_eq!(
            w.plan(true, u64::MAX, POLL),
            Plan {
                arm: true,
                poll_ns: PROBATION_POLL_NS
            }
        );
        assert_eq!(
            w.plan(true, 0, POLL),
            Plan {
                arm: true,
                poll_ns: PROBATION_POLL_NS
            }
        );
        assert_eq!(
            w.plan(false, u64::MAX, POLL),
            Plan {
                arm: true,
                poll_ns: 0
            }
        );
        // A longer poll period than the probation's is kept.
        assert_eq!(w.plan(true, 0, 5_000_000).poll_ns, 5_000_000);
    }

    #[test]
    fn a_verified_interrupt_never_polls_when_quiet() {
        let w = verified();
        assert_eq!(
            w.plan(true, HOLD_NS, POLL),
            Plan {
                arm: true,
                poll_ns: 0
            }
        );
        assert_eq!(
            w.plan(false, 0, POLL),
            Plan {
                arm: true,
                poll_ns: 0
            }
        );
        assert_eq!(w.poll_ns(true, POLL), 0);
    }

    #[test]
    fn interrupt_mode_polls_while_traffic_is_recent() {
        let w = verified();
        assert_eq!(
            w.plan(true, 0, POLL),
            Plan {
                arm: false,
                poll_ns: POLL
            }
        );
        assert_eq!(
            w.plan(true, HOLD_NS - 1, POLL),
            Plan {
                arm: false,
                poll_ns: POLL
            }
        );
        let p = RxWake::new(Mode::Polling(Why::Configured));
        assert_eq!(
            p.plan(true, u64::MAX, POLL),
            Plan {
                arm: false,
                poll_ns: POLL
            }
        );
        assert_eq!(
            p.plan(false, 0, POLL),
            Plan {
                arm: false,
                poll_ns: 0
            }
        );
    }

    #[test]
    fn polling_mode_polls_only_with_connections() {
        for why in [
            Why::Configured,
            Why::NoMsix,
            Why::NoMsiSource,
            Why::Rejected,
        ] {
            let w = RxWake::new(Mode::Polling(why));
            assert!(!w.interrupt());
            assert_eq!(w.poll_ns(true, POLL), POLL);
            assert_eq!(w.poll_ns(false, POLL), 0);
        }
    }

    #[test]
    fn sleeps_without_a_frame_change_nothing() {
        let mut w = RxWake::new(Mode::Interrupt);
        for _ in 0..1000 {
            w.armed(0);
            assert_eq!(w.after_sleep(0, false), Change::None);
        }
        assert_eq!(w.mode(), Mode::Probation);
    }

    #[test]
    fn a_silent_interrupt_on_probation_falls_back_after_8_frames() {
        let mut w = RxWake::new(Mode::Interrupt);
        for i in 1..=MISSES_BEFORE_POLLING {
            w.armed(0);
            let c = w.after_sleep(0, true);
            assert_eq!(
                c == Change::FellBack,
                i == MISSES_BEFORE_POLLING,
                "frame {i}"
            );
        }
        assert_eq!(w.mode(), Mode::Polling(Why::Silent));
        assert_eq!(
            w.plan(true, u64::MAX, POLL),
            Plan {
                arm: false,
                poll_ns: POLL
            }
        );
        // Reported once.
        w.armed(0);
        assert_eq!(w.after_sleep(0, true), Change::None);
    }

    /// The CI failure's suspicion (QEMU 8.2, ITS): an interrupt that arrives for
    /// some frames only. Two hits verify it, but the misses in between end the
    /// trust before it can be verified, or within a window after.
    #[test]
    fn an_interrupt_that_works_only_sometimes_falls_back() {
        // On probation: one hit per four misses.
        let mut w = RxWake::new(Mode::Interrupt);
        let (mut irqs, mut fell) = (0u64, false);
        for i in 0..40u64 {
            w.armed(irqs);
            if i % 5 == 0 {
                irqs += 1;
            }
            if w.after_sleep(irqs, true) == Change::FellBack {
                fell = true;
                break;
            }
        }
        assert!(fell);
        // Verified first, then a quarter of the frames lost.
        let mut w = verified();
        let (mut irqs, mut fell_at) = (100u64, None);
        for i in 0..200u64 {
            w.armed(irqs);
            if i % 4 != 0 {
                irqs += 1;
            }
            if w.after_sleep(irqs, true) == Change::FellBack {
                fell_at = Some(i);
                break;
            }
        }
        assert!(
            fell_at.is_some_and(|i| i < u64::from(MISS_WINDOW)),
            "{fell_at:?}"
        );
    }

    #[test]
    fn a_working_interrupt_keeps_the_mode() {
        let mut w = verified();
        let mut irqs = 10;
        for i in 0..10_000u64 {
            w.armed(irqs);
            if i % 2 == 0 {
                irqs += 1;
                assert_eq!(w.after_sleep(irqs, true), Change::None);
            } else {
                assert_eq!(w.after_sleep(irqs, false), Change::None);
            }
        }
        assert_eq!(w.mode(), Mode::Interrupt);
    }

    #[test]
    fn occasional_races_do_not_fall_back() {
        // One race (a frame found, its interrupt not yet counted) in every 8
        // frames: well below a quarter.
        let mut w = verified();
        let mut irqs = 10;
        for i in 0..10_000u64 {
            w.armed(irqs);
            if i % 8 != 0 {
                irqs += 1;
            }
            assert_eq!(w.after_sleep(irqs, true), Change::None, "sleep {i}");
        }
        assert_eq!(w.mode(), Mode::Interrupt);
    }

    #[test]
    fn polling_mode_ignores_sleeps() {
        let mut w = RxWake::new(Mode::Polling(Why::Configured));
        for _ in 0..100 {
            assert_eq!(w.after_sleep(0, true), Change::None);
        }
        assert_eq!(w.mode(), Mode::Polling(Why::Configured));
    }

    #[test]
    fn every_reason_has_a_text() {
        for why in [
            Why::Configured,
            Why::NoMsix,
            Why::NoMsiSource,
            Why::ItsFailed,
            Why::NoVector,
            Why::TableUnmapped,
            Why::Rejected,
            Why::Silent,
        ] {
            assert!(!why.text().is_empty());
        }
    }
}
