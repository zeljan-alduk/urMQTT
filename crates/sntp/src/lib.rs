//! SNTP client (RFC 4330) for the wall clock (T1, ADR-100). Pure: packets in
//! and out, checks, the median over several servers and the bounds on what
//! the clock may be moved by. The kernel owns the socket and the clock.
//!
//! Plain SNTP is unauthenticated, so a man in the middle can lie. The defence
//! is in this crate: the response must echo our random transmit timestamp
//! (origin check), come from the server and port we asked, pass the stratum /
//! leap / delay checks, agree with the other servers (median, majority), and
//! the result is bounded: never below the image's build time, a large forward
//! step only at the first synchronisation after boot, later corrections at
//! most `max_step` each and `max_step` in total.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)
)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub type Ip = [u8; 4];

/// UDP port of NTP servers.
pub const PORT: u16 = 123;
/// Length of an SNTP packet without extension fields or MAC.
pub const PACKET_LEN: usize = 48;
/// Servers a round can ask.
pub const MAX_SERVERS: usize = 4;
/// Seconds between 1900-01-01 (NTP era 0) and 1970-01-01.
const NTP_UNIX_DELTA: u64 = 2_208_988_800;
/// A round that has not got its answers by then ends with what it has.
pub const ROUND_TIMEOUT_MS: u64 = 4_000;
/// Smallest gap between two rounds, whatever happened (rate limit).
pub const MIN_ROUND_GAP_MS: u64 = 10_000;
/// First retry after a failed round; it doubles up to the interval.
pub const RETRY_MS: u64 = 15_000;
/// A round trip longer than this is not used (it bounds the asymmetry).
pub const MAX_DELAY_MS: i64 = 2_000;
/// A server whose root dispersion is larger is not trusted for the time.
const MAX_ROOT_DISPERSION_MS: u64 = 5_000;
/// Servers whose offsets differ by more than this do not agree.
pub const AGREE_MS: i64 = 1_000;
/// Offsets below this are applied as they are (a slew in effect).
pub const SLEW_MS: i64 = 128;

/// An NTP timestamp: 32.32 fixed point seconds since 1900.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ts(pub u64);

impl Ts {
    /// The timestamp of a Unix time in milliseconds.
    pub fn from_unix_ms(ms: u64) -> Ts {
        let secs = ms / 1000 + NTP_UNIX_DELTA;
        let frac = ((ms % 1000) << 32) / 1000;
        Ts(((secs & 0xffff_ffff) << 32) | frac)
    }

    /// Unix milliseconds. Era 0 ends in 2036: seconds below 2^31 are taken
    /// as era 1. `None` before 1970.
    pub fn to_unix_ms(self) -> Option<i64> {
        let mut secs = self.0 >> 32;
        if secs < 0x8000_0000 {
            secs += 1 << 32;
        }
        let secs = secs.checked_sub(NTP_UNIX_DELTA)?;
        let ms = ((self.0 & 0xffff_ffff) * 1000) >> 32;
        i64::try_from(secs * 1000 + ms).ok()
    }

    /// With the low 32 bits replaced by `nonce`: the unpredictable part a
    /// server echoes back.
    pub fn with_nonce(self, nonce: u32) -> Ts {
        Ts((self.0 & 0xffff_ffff_0000_0000) | u64::from(nonce))
    }
}

/// The request: LI 0, version 4, mode 3 (client); only the transmit
/// timestamp is set, to `xmit` (the server echoes it as origin).
pub fn build_request(xmit: Ts) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    if let Some(b) = p.first_mut() {
        *b = (4 << 3) | 3;
    }
    if let Some(d) = p.get_mut(40..48) {
        d.copy_from_slice(&xmit.0.to_be_bytes());
    }
    p
}

/// Why a datagram was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooShort,
    /// Not mode 4 (server) or a version we do not speak.
    BadMode,
    /// Leap indicator 3: the server's clock is unsynchronised.
    Unsynchronised,
    /// Stratum 0: a kiss-of-death (RATE, DENY, ...); the server must not be
    /// asked again soon.
    KissOfDeath,
    /// Stratum 16 or more: unsynchronised.
    BadStratum,
    /// The origin timestamp is not the one we sent: a stale, forged or
    /// replayed answer.
    WrongOrigin,
    /// Receive or transmit timestamp zero or before 1970, or transmit
    /// before receive.
    BadTimestamps,
    /// The server's own root dispersion or delay is unusable.
    BadRoot,
}

/// A checked response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub stratum: u8,
    pub leap: u8,
    /// The server's clock when it received the request (T2), Unix ms.
    pub t2_ms: i64,
    /// The server's clock when it answered (T3), Unix ms.
    pub t3_ms: i64,
}

fn be32(p: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(p.get(at..at + 4)?.try_into().ok()?))
}

fn be64(p: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(p.get(at..at + 8)?.try_into().ok()?))
}

/// NTP short format (16.16 seconds) in ms.
fn short_ms(v: u32) -> u64 {
    (u64::from(v) * 1000) >> 16
}

/// Checks a response against the request we sent (`origin`).
pub fn parse_response(p: &[u8], origin: Ts) -> Result<Sample, Reject> {
    if p.len() < PACKET_LEN {
        return Err(Reject::TooShort);
    }
    let b0 = *p.first().ok_or(Reject::TooShort)?;
    let (leap, version, mode) = (b0 >> 6, (b0 >> 3) & 7, b0 & 7);
    if mode != 4 || !(3..=4).contains(&version) {
        return Err(Reject::BadMode);
    }
    if leap == 3 {
        return Err(Reject::Unsynchronised);
    }
    let stratum = *p.get(1).ok_or(Reject::TooShort)?;
    match stratum {
        0 => return Err(Reject::KissOfDeath),
        1..=15 => {}
        _ => return Err(Reject::BadStratum),
    }
    // The origin check comes before anything trusts a timestamp.
    if origin.0 == 0 || be64(p, 24) != Some(origin.0) {
        return Err(Reject::WrongOrigin);
    }
    let root_delay = be32(p, 4).ok_or(Reject::TooShort)?;
    let root_disp = be32(p, 8).ok_or(Reject::TooShort)?;
    if short_ms(root_delay) > MAX_ROOT_DISPERSION_MS * 4
        || short_ms(root_disp) > MAX_ROOT_DISPERSION_MS
    {
        return Err(Reject::BadRoot);
    }
    let t2 = Ts(be64(p, 32).ok_or(Reject::TooShort)?);
    let t3 = Ts(be64(p, 40).ok_or(Reject::TooShort)?);
    if t2.0 == 0 || t3.0 == 0 {
        return Err(Reject::BadTimestamps);
    }
    let (Some(t2_ms), Some(t3_ms)) = (t2.to_unix_ms(), t3.to_unix_ms()) else {
        return Err(Reject::BadTimestamps);
    };
    if t3_ms < t2_ms {
        return Err(Reject::BadTimestamps);
    }
    Ok(Sample {
        stratum,
        leap,
        t2_ms,
        t3_ms,
    })
}

/// One server's measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measure {
    /// How far the local clock is behind the server (add this), ms.
    pub offset_ms: i64,
    pub delay_ms: i64,
}

/// The offset and delay (RFC 4330 §5) from our send (`t1_ms`) and receive
/// (`t4_ms`) times on the local clock. `None`: the round trip is negative
/// or longer than [`MAX_DELAY_MS`].
pub fn measure(t1_ms: i64, t4_ms: i64, s: &Sample) -> Option<Measure> {
    let delay = t4_ms
        .checked_sub(t1_ms)?
        .checked_sub(s.t3_ms.checked_sub(s.t2_ms)?)?;
    // A little below zero is rounding in ms.
    if !(-1..=MAX_DELAY_MS).contains(&delay) {
        return None;
    }
    let a = s.t2_ms.checked_sub(t1_ms)?;
    let b = s.t3_ms.checked_sub(t4_ms)?;
    Some(Measure {
        offset_ms: a.checked_add(b)? / 2,
        delay_ms: delay.max(0),
    })
}

/// The agreed offset of several servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consensus {
    pub offset_ms: i64,
    /// Servers that answered, and of those the ones within [`AGREE_MS`] of
    /// the median.
    pub answered: usize,
    pub agreeing: usize,
}

/// The median of the offsets, if a strict majority of them lies within
/// [`AGREE_MS`] of it. With an even count the lower middle one is taken.
pub fn consensus(offsets: &[i64]) -> Option<Consensus> {
    let n = offsets.len().min(MAX_SERVERS);
    let mut buf = [0i64; MAX_SERVERS];
    for (d, s) in buf.iter_mut().zip(offsets) {
        *d = *s;
    }
    let v = buf.get_mut(..n)?;
    v.sort_unstable();
    let median = *v.get(n.checked_sub(1)? / 2)?;
    let agreeing = v
        .iter()
        .filter(|&&o| o.saturating_sub(median).saturating_abs() <= AGREE_MS)
        .count();
    if agreeing * 2 <= n {
        return None;
    }
    Some(Consensus {
        offset_ms: median,
        answered: n,
        agreeing,
    })
}

/// Where the wall clock comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Unknown,
    Rtc,
    Sntp,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Source::Unknown => "unknown",
            Source::Rtc => "rtc",
            Source::Sntp => "sntp",
        }
    }
}

/// The bounds on moving the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The clock never goes below this (the image's build time), Unix s.
    pub floor_unix_s: u64,
    /// The most a single correction may move the clock after the first
    /// one, and the most all of them together may (ms).
    pub max_step_ms: i64,
}

/// What to do with an agreed offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Move the clock by this much (ms).
    Apply { adjust_ms: i64, step: StepKind },
    /// Leave it, with the reason.
    Refuse(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// Below [`SLEW_MS`].
    Slew,
    /// A bounded step.
    Step,
    /// The one large step of the first synchronisation (or the first time
    /// the clock is known at all).
    Boot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The result would be before the build time.
    BelowFloor,
    /// One correction larger than `max_step` after the first.
    TooLarge,
    /// Corrections since the first add up beyond `max_step`.
    DriftBudget,
    /// A backward step at boot beyond `max_step`.
    BootBackward,
}

impl Refusal {
    pub const fn name(self) -> &'static str {
        match self {
            Refusal::BelowFloor => "result below the image build time",
            Refusal::TooLarge => "offset larger than time.max_step",
            Refusal::DriftBudget => "total correction since the first beyond time.max_step",
            Refusal::BootBackward => "backward step at boot beyond time.max_step",
        }
    }
}

/// The clock's state for the decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discipline {
    pub bounds: Bounds,
    /// A correction has been applied since boot.
    pub synced: bool,
    /// Sum of the corrections after the first (ms).
    pub drift_ms: i64,
}

impl Discipline {
    pub const fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            synced: false,
            drift_ms: 0,
        }
    }

    /// Decides on `offset_ms` while the clock reads `local_ms` (Unix ms;
    /// `None`: it is not known, the RTC was wrong). Updates the state when
    /// the answer is `Apply`.
    pub fn decide(&mut self, local_ms: Option<i64>, offset_ms: i64) -> Decision {
        let floor =
            i64::try_from(self.bounds.floor_unix_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        // Unknown: the local reading is meaningless (uptime), the offset is
        // the result.
        let result = match local_ms {
            Some(l) => l.saturating_add(offset_ms),
            None => offset_ms,
        };
        if result < floor {
            return Decision::Refuse(Refusal::BelowFloor);
        }
        let max = self.bounds.max_step_ms;
        let mag = offset_ms.saturating_abs();
        if !self.synced {
            // The first correction: the clock may be anywhere (an empty RTC
            // battery) so it may go far forward, once; backward only within
            // the bound.
            if local_ms.is_some() && offset_ms < 0 && mag > max {
                return Decision::Refuse(Refusal::BootBackward);
            }
            self.synced = true;
            return Decision::Apply {
                adjust_ms: offset_ms,
                step: if local_ms.is_none() || mag > max {
                    StepKind::Boot
                } else if mag < SLEW_MS {
                    StepKind::Slew
                } else {
                    StepKind::Step
                },
            };
        }
        if mag > max {
            return Decision::Refuse(Refusal::TooLarge);
        }
        let drift = self.drift_ms.saturating_add(offset_ms);
        if drift.saturating_abs() > max {
            return Decision::Refuse(Refusal::DriftBudget);
        }
        self.drift_ms = drift;
        Decision::Apply {
            adjust_ms: offset_ms,
            step: if mag < SLEW_MS {
                StepKind::Slew
            } else {
                StepKind::Step
            },
        }
    }
}

/// The client's configuration.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    pub servers: &'a [(Ip, u16)],
    pub interval_ms: u64,
}

/// A datagram to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub dst: Ip,
    pub port: u16,
    pub payload: [u8; PACKET_LEN],
}

/// What a round produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Enough servers agreed.
    Agreed(Consensus),
    /// Too few answers or no majority.
    Failed { answered: usize, asked: usize },
}

#[derive(Clone, Copy)]
struct Slot {
    sent: bool,
    /// Our transmit timestamp (the origin we expect) and T1; `None` once
    /// answered or if unsent.
    pending: Option<(Ts, i64)>,
    kod_until_ms: u64,
    result: Option<i64>,
}

const EMPTY: Slot = Slot {
    sent: false,
    pending: None,
    kod_until_ms: 0,
    result: None,
};

/// How many datagrams were used or thrown away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub rounds: u32,
    pub accepted: u32,
    pub rejected: u32,
    pub unsolicited: u32,
    pub kiss_of_death: u32,
}

/// The query schedule and the answers of the round in progress.
pub struct Client<'a> {
    cfg: Config<'a>,
    slots: [Slot; MAX_SERVERS],
    in_round: bool,
    round_started_ms: u64,
    /// Next round no earlier than.
    next_round_ms: u64,
    retry_ms: u64,
    pub stats: Stats,
}

impl<'a> Client<'a> {
    pub fn new(cfg: Config<'a>, now_ms: u64) -> Self {
        Self {
            cfg,
            slots: [EMPTY; MAX_SERVERS],
            in_round: false,
            round_started_ms: now_ms,
            next_round_ms: now_ms,
            retry_ms: RETRY_MS,
            stats: Stats::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.cfg.servers.is_empty()
    }

    fn servers(&self) -> usize {
        self.cfg.servers.len().min(MAX_SERVERS)
    }

    /// Servers that must answer for a round to count: two when two or more
    /// are configured, so that one cannot decide alone.
    pub fn quorum(&self) -> usize {
        self.servers().min(2)
    }

    /// Whether [`Client::poll`] has something to do now (a round is due or
    /// in progress): the caller fetches fresh randomness only then.
    pub fn due(&self, now_ms: u64) -> bool {
        self.enabled() && (self.in_round || now_ms >= self.next_round_ms)
    }

    /// Postpones the next round (the caller's boundary refused a result, or
    /// the network is not up): retry delays double up to the interval.
    pub fn backoff(&mut self, now_ms: u64) {
        let wait = self
            .retry_ms
            .min(self.cfg.interval_ms)
            .max(MIN_ROUND_GAP_MS);
        self.retry_ms = self.retry_ms.saturating_mul(2).min(self.cfg.interval_ms);
        self.next_round_ms = now_ms.saturating_add(wait);
    }

    /// After a result the bounds accepted: the next round is one interval
    /// away.
    pub fn succeeded(&mut self, now_ms: u64) {
        self.retry_ms = RETRY_MS;
        self.next_round_ms = now_ms.saturating_add(self.cfg.interval_ms.max(MIN_ROUND_GAP_MS));
    }

    /// Advances the schedule. `now_ms` is monotonic time, `wall_ms` the
    /// local clock (T1), `nonce` fresh random bytes. Returns the next
    /// datagram to send, if any (call again until `None`), or the outcome
    /// of a round that just ended. If the caller cannot send a datagram
    /// (next hop's MAC unknown), [`Client::unsent`] puts it back. After an
    /// `Agreed` outcome the caller calls [`Client::succeeded`] or
    /// [`Client::backoff`], after a `Failed` one nothing: the retry is set.
    pub fn poll(
        &mut self,
        now_ms: u64,
        wall_ms: i64,
        nonce: u32,
    ) -> (Option<Request>, Option<Outcome>) {
        if !self.enabled() {
            return (None, None);
        }
        if !self.in_round {
            if now_ms < self.next_round_ms {
                return (None, None);
            }
            self.in_round = true;
            self.round_started_ms = now_ms;
            self.stats.rounds = self.stats.rounds.saturating_add(1);
            for s in self.slots.iter_mut() {
                let kod = s.kod_until_ms;
                *s = EMPTY;
                s.kod_until_ms = kod;
            }
        }
        let n = self.servers();
        let done = now_ms.saturating_sub(self.round_started_ms) >= ROUND_TIMEOUT_MS
            || self
                .slots
                .iter()
                .take(n)
                .all(|s| s.sent && s.pending.is_none());
        if done {
            return (None, Some(self.finish(now_ms)));
        }
        let Some((i, s)) = self
            .slots
            .iter_mut()
            .enumerate()
            .take(n)
            .find(|(_, s)| !s.sent)
        else {
            return (None, None);
        };
        s.sent = true;
        // A server that sent a kiss-of-death is left alone for the interval.
        if now_ms < s.kod_until_ms {
            return (None, None);
        }
        let Some(&(dst, port)) = self.cfg.servers.get(i) else {
            return (None, None);
        };
        let xmit = Ts::from_unix_ms(u64::try_from(wall_ms).unwrap_or(0)).with_nonce(nonce | 1);
        s.pending = Some((xmit, wall_ms));
        (
            Some(Request {
                dst,
                port,
                payload: build_request(xmit),
            }),
            None,
        )
    }

    /// The datagram last returned for `dst` could not be sent.
    pub fn unsent(&mut self, dst: Ip) {
        for (s, a) in self.slots.iter_mut().zip(self.cfg.servers) {
            if a.0 == dst && s.pending.is_some() {
                s.sent = false;
                s.pending = None;
                return;
            }
        }
    }

    /// A UDP datagram from `src:sport` to our port arrived. `wall_ms` is the
    /// local clock now (T4).
    pub fn input(&mut self, now_ms: u64, wall_ms: i64, src: Ip, sport: u16, payload: &[u8]) {
        let interval = self.cfg.interval_ms;
        let found = self
            .slots
            .iter_mut()
            .zip(self.cfg.servers)
            .find(|(s, a)| a.0 == src && a.1 == sport && s.pending.is_some());
        let (Some((slot, _)), true) = (found, self.in_round) else {
            self.stats.unsolicited = self.stats.unsolicited.saturating_add(1);
            return;
        };
        let Some((origin, t1)) = slot.pending else {
            return;
        };
        match parse_response(payload, origin) {
            // A wrong origin leaves the request pending: a forger who
            // guesses wrong does not use up the real answer.
            Err(Reject::WrongOrigin) => self.stats.rejected += 1,
            Err(Reject::KissOfDeath) => {
                slot.pending = None;
                slot.kod_until_ms = now_ms.saturating_add(interval);
                self.stats.kiss_of_death += 1;
            }
            Err(_) => {
                slot.pending = None;
                self.stats.rejected += 1;
            }
            Ok(sample) => {
                slot.pending = None;
                if let Some(m) = measure(t1, wall_ms, &sample) {
                    slot.result = Some(m.offset_ms);
                    self.stats.accepted += 1;
                } else {
                    self.stats.rejected += 1;
                }
            }
        }
    }

    fn finish(&mut self, now_ms: u64) -> Outcome {
        self.in_round = false;
        let n = self.servers();
        let mut v = [0i64; MAX_SERVERS];
        let mut answered = 0;
        for s in self.slots.iter().take(n) {
            if let (Some(o), Some(d)) = (s.result, v.get_mut(answered)) {
                *d = o;
                answered += 1;
            }
        }
        let agreed = if answered >= self.quorum() {
            v.get(..answered).and_then(consensus)
        } else {
            None
        };
        match agreed {
            Some(c) => {
                // The caller refines this with `succeeded` / `backoff`.
                self.next_round_ms = now_ms.saturating_add(MIN_ROUND_GAP_MS);
                Outcome::Agreed(c)
            }
            None => {
                self.backoff(now_ms);
                Outcome::Failed { answered, asked: n }
            }
        }
    }
}

#[cfg(test)]
mod tests;
