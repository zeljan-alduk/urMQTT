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
//! A hypervisor that accepts the vector but never delivers it would leave the
//! dispatcher waiting for the 10 ms tick: after [`MISSES_BEFORE_POLLING`]
//! sleeps in a row that ended with a frame waiting and no interrupt counted,
//! the mode falls back to polling for good, and the kernel says so.

/// Sleeps in a row that ended with a received frame waiting but no receive
/// interrupt since the queue was armed, before the dispatcher stops trusting
/// the interrupt. A frame can legitimately land in the few nanoseconds
/// between reading the counter and the ring, but not eight times in a row.
pub const MISSES_BEFORE_POLLING: u8 = 8;

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
            Self::Silent => "the receive interrupt never arrived",
        }
    }
}

/// How the dispatcher is woken for received frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The receive queue's MSI-X vector, routed to the dispatcher's core.
    Interrupt,
    /// The deadline timer, at most every poll period while connections exist
    /// (ADR-224), and the 10 ms tick.
    Polling(Why),
}

/// The dispatcher's receive wake-up state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxWake {
    mode: Mode,
    /// Consecutive sleeps that ended with a frame waiting and no interrupt.
    misses: u8,
    /// The interrupt counter when the queue was last armed.
    irqs_at_arm: u64,
}

impl RxWake {
    pub const fn new(mode: Mode) -> Self {
        Self {
            mode,
            misses: 0,
            irqs_at_arm: 0,
        }
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether the dispatcher arms the receive interrupt before it sleeps.
    pub const fn interrupt(&self) -> bool {
        matches!(self.mode, Mode::Interrupt)
    }

    /// How often a sleeping dispatcher must come back by itself (ns; 0: only
    /// the tick and wake-ups): never in interrupt mode, `poll_ns` while
    /// connections exist in polling mode (ADR-224).
    pub const fn poll_ns(&self, connections: bool, poll_ns: u64) -> u64 {
        match self.mode {
            Mode::Interrupt => 0,
            Mode::Polling(_) if connections => poll_ns,
            Mode::Polling(_) => 0,
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
            Mode::Polling(_) => Plan {
                arm: false,
                poll_ns: self.poll_ns(connections, poll_ns),
            },
        }
    }

    /// The queue was armed; `irqs` is the interrupt counter now.
    pub fn armed(&mut self, irqs: u64) {
        self.irqs_at_arm = irqs;
    }

    /// After a sleep in interrupt mode: `irqs` is the counter now, `waiting`
    /// whether a received frame was waiting. Returns `true` when this sleep
    /// made the mode fall back to polling (the caller logs it once).
    pub fn after_sleep(&mut self, irqs: u64, waiting: bool) -> bool {
        if !self.interrupt() {
            return false;
        }
        if irqs != self.irqs_at_arm || !waiting {
            self.misses = 0;
            return false;
        }
        self.misses = self.misses.saturating_add(1);
        if self.misses >= MISSES_BEFORE_POLLING {
            self.mode = Mode::Polling(Why::Silent);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL: u64 = 200_000;

    #[test]
    fn interrupt_mode_never_polls() {
        let w = RxWake::new(Mode::Interrupt);
        assert!(w.interrupt());
        assert_eq!(w.poll_ns(true, POLL), 0);
        assert_eq!(w.poll_ns(false, POLL), 0);
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
    fn interrupt_mode_polls_while_traffic_is_recent() {
        let w = RxWake::new(Mode::Interrupt);
        // Busy NIC with connections: poll, do not arm (no MSI per idle gap).
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
        // Quiet for the hold time: the interrupt, no polling.
        assert_eq!(
            w.plan(true, HOLD_NS, POLL),
            Plan {
                arm: true,
                poll_ns: 0
            }
        );
        // Without connections: always the interrupt (the first SYN wakes it).
        assert_eq!(
            w.plan(false, 0, POLL),
            Plan {
                arm: true,
                poll_ns: 0
            }
        );
        // Polling mode never arms.
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
    fn a_working_interrupt_keeps_the_mode() {
        let mut w = RxWake::new(Mode::Interrupt);
        let mut irqs = 0;
        for i in 0..10_000u64 {
            w.armed(irqs);
            // Every other sleep ends with a frame and its interrupt, the
            // others by the tick with nothing waiting.
            if i % 2 == 0 {
                irqs += 1;
                assert!(!w.after_sleep(irqs, true));
            } else {
                assert!(!w.after_sleep(irqs, false));
            }
        }
        assert_eq!(w.mode(), Mode::Interrupt);
    }

    #[test]
    fn occasional_races_do_not_fall_back() {
        let mut w = RxWake::new(Mode::Interrupt);
        let mut irqs = 0;
        for _ in 0..1000 {
            // A frame that landed between the counter and the ring.
            for _ in 0..MISSES_BEFORE_POLLING - 1 {
                w.armed(irqs);
                assert!(!w.after_sleep(irqs, true));
            }
            w.armed(irqs);
            irqs += 1;
            assert!(!w.after_sleep(irqs, true));
        }
        assert!(w.interrupt());
    }

    #[test]
    fn a_silent_interrupt_falls_back_once() {
        let mut w = RxWake::new(Mode::Interrupt);
        for i in 1..=MISSES_BEFORE_POLLING {
            w.armed(5);
            let fell = w.after_sleep(5, true);
            assert_eq!(fell, i == MISSES_BEFORE_POLLING, "sleep {i}");
        }
        assert_eq!(w.mode(), Mode::Polling(Why::Silent));
        assert_eq!(w.poll_ns(true, POLL), POLL);
        // Reported once; later sleeps change nothing.
        w.armed(5);
        assert!(!w.after_sleep(5, true));
        assert_eq!(w.mode(), Mode::Polling(Why::Silent));
    }

    #[test]
    fn polling_mode_ignores_sleeps() {
        let mut w = RxWake::new(Mode::Polling(Why::Configured));
        for _ in 0..100 {
            assert!(!w.after_sleep(0, true));
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
