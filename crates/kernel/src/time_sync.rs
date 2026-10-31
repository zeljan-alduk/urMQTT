//! SNTP on the network core (T1, ADR-100): one round of queries at boot and
//! then every `time.interval_s`, over the interface's UDP path. The pure
//! part (packets, checks, median, bounds) is `urmqtt-sntp`; this moves the
//! datagrams and, when the servers agree and the bounds allow it, the wall
//! clock of `boot.rs`. Servers are IPv4 literals: there is no DNS resolver.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use urmqtt_config::CONFIG;
use urmqtt_log::{info, warn};
use urmqtt_net::iface::Iface;
use urmqtt_sntp::{
    Bounds, Client, Config, Decision, Discipline, Outcome, Refusal, Source, StepKind,
};

use crate::boot;

/// Our UDP source port; an answer must come to it from a server we asked.
pub const SPORT: u16 = 40123;

/// The `sntp=` word, packed as ip << 16 | port (0: none).
static DEV_SERVER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn set_dev_server(s: Option<([u8; 4], u16)>) {
    let v = s.map_or(0, |(a, p)| {
        (u64::from(u32::from_be_bytes(a)) << 16) | u64::from(p)
    });
    // Relaxed: set once at boot, before core 0 starts the network loop.
    DEV_SERVER.store(v, core::sync::atomic::Ordering::Relaxed);
}

fn dev_server() -> Option<([u8; 4], u16)> {
    let v = DEV_SERVER.load(core::sync::atomic::Ordering::Relaxed);
    (v != 0).then(|| (((v >> 16) as u32).to_be_bytes(), (v & 0xffff) as u16))
}

pub struct TimeSync {
    client: Client<'static>,
    discipline: Discipline,
    last_resolve_ms: u64,
}

fn ip(a: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

impl TimeSync {
    pub fn new(now_ms: u64) -> Self {
        let t = &CONFIG.time;
        let mut servers: Vec<([u8; 4], u16)> = t.servers.iter().map(|a| (a.addr, a.port)).collect();
        if let Some(d) = dev_server()
            && !servers.contains(&d)
            && servers.len() < urmqtt_sntp::MAX_SERVERS
        {
            servers.push(d);
        }
        let list: &'static [([u8; 4], u16)] = Box::leak(servers.into_boxed_slice());
        let client = Client::new(
            Config {
                servers: list,
                interval_ms: u64::from(t.interval_s) * 1000,
            },
            now_ms,
        );
        let discipline = Discipline::new(Bounds {
            floor_unix_s: boot::BUILD_UNIX,
            max_step_ms: i64::from(t.max_step_s) * 1000,
        });
        if list.is_empty() {
            info!(
                "time: no SNTP servers (time.servers is empty): the wall clock is the firmware RTC ({})",
                boot::clock_source().name()
            );
        } else {
            let names: Vec<String> = list
                .iter()
                .map(|&(a, p)| alloc::format!("{}:{p}", ip(a)))
                .collect();
            info!(
                "time: sntp servers [{}], every {} s, corrections at most {} s each and in total after the first, clock now from {}",
                names.join(", "),
                t.interval_s,
                t.max_step_s,
                boot::clock_source().name()
            );
        }
        Self {
            client,
            discipline,
            last_resolve_ms: 0,
        }
    }

    /// Sends what is due and finishes rounds. Call every pass of the loop.
    pub fn poll(&mut self, iface: &mut Iface, now_ms: u64, out: &mut impl FnMut(&[u8])) {
        if !self.client.due(now_ms) || iface.addr().is_none() {
            return;
        }
        loop {
            let mut nonce = [0u8; 4];
            // Fail closed: without randomness the origin check is worthless.
            if urmqtt_tls::rng::fill_global(&mut nonce).is_err() {
                return;
            }
            let (req, outcome) =
                self.client
                    .poll(now_ms, boot::clock_raw_ms(), u32::from_le_bytes(nonce));
            if let Some(o) = outcome {
                self.outcome(now_ms, o);
            }
            let Some(r) = req else { break };
            if !iface.send_udp(r.dst, SPORT, r.port, &r.payload, out) {
                self.client.unsent(r.dst);
                if let Some(hop) = iface.next_hop(r.dst)
                    && now_ms.saturating_sub(self.last_resolve_ms) >= 1000
                {
                    self.last_resolve_ms = now_ms;
                    iface.resolve(hop, out);
                }
                break;
            }
        }
    }

    /// A UDP datagram arrived.
    pub fn input(&mut self, now_ms: u64, src: [u8; 4], sport: u16, dport: u16, payload: &[u8]) {
        if dport != SPORT {
            return;
        }
        self.client
            .input(now_ms, boot::clock_raw_ms(), src, sport, payload);
    }

    fn outcome(&mut self, now_ms: u64, o: Outcome) {
        let st = self.client.stats;
        match o {
            Outcome::Failed { answered, asked } => warn!(
                "time: sntp round failed: {answered} of {asked} server(s) gave a usable answer and a majority is needed ({} accepted, {} rejected, {} unsolicited, {} kiss-of-death so far); the clock stays {}",
                st.accepted,
                st.rejected,
                st.unsolicited,
                st.kiss_of_death,
                boot::clock_source().name()
            ),
            Outcome::Agreed(c) => {
                let known = boot::clock_source() != Source::Unknown;
                let local = known.then(boot::clock_raw_ms);
                if known {
                    boot::note_offset(c.offset_ms);
                }
                match self.discipline.decide(local, c.offset_ms) {
                    Decision::Apply { adjust_ms, step } => {
                        boot::apply_clock_adjust(adjust_ms);
                        let kind = match step {
                            StepKind::Slew => "adjusted",
                            StepKind::Step => "stepped",
                            StepKind::Boot => "set (first synchronisation)",
                        };
                        let by = if known {
                            alloc::format!(" by {adjust_ms} ms")
                        } else {
                            String::from(" (it was unknown)")
                        };
                        info!(
                            "time: sntp {kind} the clock{by} ({} of {} server(s) agree); source sntp, unix {}",
                            c.agreeing,
                            c.answered,
                            boot::now_unix().unwrap_or(0)
                        );
                        self.client.succeeded(now_ms);
                    }
                    Decision::Refuse(why) => {
                        warn!(
                            "time: sntp offset {} ms refused: {}; the clock stays {}",
                            c.offset_ms,
                            why.name(),
                            boot::clock_source().name()
                        );
                        if why == Refusal::BelowFloor {
                            warn!("time: the servers claim a date before this image was built");
                        }
                        self.client.backoff(now_ms);
                    }
                }
            }
        }
    }
}
