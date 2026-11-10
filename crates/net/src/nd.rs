//! The IPv6 side of one core's interface (NEXT-1, ADR-331): addresses,
//! Duplicate Address Detection, SLAAC, the default router, the neighbour
//! cache, and the Neighbour Discovery and echo answers of the core that owns
//! the NIC.
//!
//! - **Addresses.** The link-local address `fe80::` + the modified EUI-64 of
//!   the MAC, and at most one global address: with SLAAC the first
//!   autonomous /64 of the Router Advertisements + the same EUI-64, or the
//!   configured static one. Further prefixes are counted and ignored. A
//!   server's address must be predictable (it goes into DNS records and
//!   allow-lists of the clients' firewalls), so neither temporary addresses
//!   (RFC 8981) nor RFC 7217 stable-opaque ones are made (ADR-331).
//! - **DAD** (RFC 4862 §5.4): one Neighbour Solicitation from `::` per new
//!   address, then one second; an advertisement or a DAD probe for the same
//!   address in that second marks it duplicate, and it is never used.
//! - **SLAAC** (RFC 4862 §5.5): Router Solicitations (three, four seconds
//!   apart) once the link-local address is usable; Router Advertisements give
//!   the default router (its lifetime), its link-layer address, the MTU (from
//!   1280 to the link's) and prefixes. Lifetimes follow §5.5.3 with the
//!   two-hour rule; an address whose valid lifetime ends is removed. A
//!   deprecated address (preferred lifetime over) keeps serving: inbound
//!   connections choose it, not this host.
//! - **Neighbours.** Learned from every frame for us (as for IPv4, ADR-033:
//!   a server answers peers that reached it) and from Neighbour Discovery; a
//!   frame from off the link has the router's MAC. The owner sends a
//!   solicitation for a next hop it does not know (at most one per second
//!   per address); the segment that needed it is dropped and counted (TCP
//!   retransmits).
//! - The cores other than the owner take the result ([`V6Config`]) from core
//!   0 and answer nothing but their own TCP flows.

use alloc::vec::Vec;

use crate::addr::{V6Locals, is_link_local};
use crate::ipv4::{self, Mac};
use crate::ipv6::{
    self, ALL_NODES, ALL_ROUTERS, ICMP6_ECHO_REPLY, ICMP6_NA, ICMP6_NS, ICMP6_RS, Icmp6, Ip6, Ipv6,
    NH_ICMPV6, UNSPECIFIED, eui64, link_local_of, multicast_mac, same_prefix, solicited_node,
    with_iid,
};

const NEIGHBOURS: usize = 32;
/// RFC 4861 §10: RetransTimer.
pub const DAD_WAIT_MS: u64 = 1000;
/// RFC 4861 §10: MAX_RTR_SOLICITATIONS and RTR_SOLICITATION_INTERVAL.
pub const RS_COUNT: u8 = 3;
pub const RS_INTERVAL_MS: u64 = 4000;
/// Neighbour Solicitations for one unknown next hop at most this often.
const SOLICIT_EVERY_MS: u64 = 1000;
/// Neighbour Discovery answers (NA) per second.
const ND_PER_SEC: u32 = 100;
/// RFC 4862 §5.5.3 (e): two hours.
const TWO_HOURS_MS: u64 = 2 * 3600 * 1000;

/// How the global address comes about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode6 {
    /// From Router Advertisements.
    Slaac,
    /// Configured: the address, its prefix length (the on-link prefix) and
    /// the default router (often a link-local address on a VPS).
    Static {
        addr: Ip6,
        prefix_len: u8,
        gateway: Ip6,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// DAD in progress: its probe went out at `since` (if `sent`).
    Tentative {
        since: u64,
        sent: bool,
    },
    Preferred,
    /// Another node has it: never used.
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub addr: Ip6,
    pub state: State,
    /// The prefix the address belongs to (64 for SLAAC).
    pub prefix_len: u8,
    /// Whether that prefix is on the link (the L flag; static: yes).
    pub on_link: bool,
    /// ms; `u64::MAX`: forever.
    pub valid_until: u64,
}

impl Slot {
    fn usable(&self) -> bool {
        self.state == State::Preferred
    }
}

/// What the other cores need: the addresses in use, the on-link prefix, the
/// default router and the MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct V6Config {
    pub locals: V6Locals,
    /// The global address's prefix length when it is on the link (0: only
    /// `fe80::/10` is).
    pub onlink_len: u8,
    pub router: Option<Ip6>,
    pub mtu: u16,
}

/// What changed, for the kernel's log and the other cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event6 {
    /// An address passed DAD (`global`: not the link-local one).
    AddressUp {
        addr: Ip6,
        global: bool,
    },
    /// An address failed DAD.
    Duplicate {
        addr: Ip6,
    },
    /// The global address's valid lifetime ended.
    AddressExpired {
        addr: Ip6,
    },
    /// A default router appeared or changed (lifetime in s, 0: static).
    Router {
        addr: Ip6,
        lifetime_s: u16,
    },
    RouterGone {
        addr: Ip6,
    },
    /// The MTU an RA announced, now in use.
    Mtu {
        mtu: u16,
    },
    /// An advertised prefix not used (one global address only).
    PrefixIgnored {
        prefix: Ip6,
        len: u8,
    },
    /// No Router Advertisement after the solicitations.
    NoRouter,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats6 {
    pub frames_in: u64,
    pub frames_out: u64,
    /// Dropped for any reason (the reasons below are part of it).
    pub dropped: u64,
    pub fragments: u64,
    pub ext_headers: u64,
    pub bad_address: u64,
    pub bad_icmp: u64,
    pub not_for_us: u64,
    pub udp: u64,
    pub echo_replies: u64,
    pub ns_in: u64,
    pub na_in: u64,
    pub ns_out: u64,
    pub na_out: u64,
    pub ra_in: u64,
    pub ra_ignored: u64,
    pub rs_out: u64,
    pub nd_limited: u64,
    pub dad_ok: u64,
    pub dad_duplicate: u64,
    pub prefixes_ignored: u64,
    pub no_neighbour: u64,
    /// A TCP segment to an address of ours that is not the one this host
    /// answers that peer from (ADR-331).
    pub wrong_local: u64,
    pub too_big: u64,
}

pub struct Host6 {
    mac: Mac,
    owner: bool,
    mode: Option<Mode6>,
    ll: Option<Slot>,
    global: Option<Slot>,
    router: Option<(Ip6, u64)>,
    router_mac: Option<Mac>,
    neighbours: [(Ip6, Mac, u64); NEIGHBOURS],
    /// The configuration of a core other than the owner.
    cfg: V6Config,
    link_mtu: u16,
    mtu: u16,
    rs_sent: u8,
    rs_next: u64,
    ra_seen: bool,
    solicited: [(Ip6, u64); 4],
    nd_tokens: u32,
    nd_since: u64,
    mld_due: bool,
    buf: Vec<u8>,
    pub stats: Stats6,
}

fn until(now: u64, s: u32) -> u64 {
    if s == u32::MAX {
        u64::MAX
    } else {
        now.saturating_add(u64::from(s) * 1000)
    }
}

impl Host6 {
    /// Off until [`Host6::start`] (owner) or [`Host6::set_config`].
    pub fn new(mac: Mac, owner: bool) -> Self {
        Self {
            mac,
            owner,
            mode: None,
            ll: None,
            global: None,
            router: None,
            router_mac: None,
            neighbours: [([0; 16], [0; 6], 0); NEIGHBOURS],
            cfg: V6Config::default(),
            link_mtu: crate::iface::DEFAULT_MTU,
            mtu: crate::iface::DEFAULT_MTU,
            rs_sent: 0,
            rs_next: 0,
            ra_seen: false,
            solicited: [([0; 16], 0); 4],
            nd_tokens: ND_PER_SEC,
            nd_since: 0,
            mld_due: false,
            buf: Vec::with_capacity(256),
            stats: Stats6::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.mode.is_some() || self.cfg.locals != V6Locals::NONE
    }

    /// The owner: start with the link-local address (and the static one).
    pub fn start(&mut self, now: u64, mode: Mode6) {
        if !self.owner {
            return;
        }
        self.mode = Some(mode);
        let tentative = State::Tentative {
            since: now,
            sent: false,
        };
        self.ll = Some(Slot {
            addr: link_local_of(self.mac),
            state: tentative,
            prefix_len: 64,
            on_link: true,
            valid_until: u64::MAX,
        });
        if let Mode6::Static {
            addr,
            prefix_len,
            gateway,
        } = mode
        {
            self.global = Some(Slot {
                addr,
                state: tentative,
                prefix_len,
                on_link: true,
                valid_until: u64::MAX,
            });
            self.router = Some((gateway, u64::MAX));
        }
        self.mld_due = true;
    }

    /// The link MTU (IPv4's, the driver's bound): the IPv6 MTU is at most it.
    pub fn set_link_mtu(&mut self, mtu: u16) {
        self.link_mtu = mtu.max(ipv6::MIN_MTU);
        if !self.ra_seen || self.mtu > self.link_mtu {
            self.mtu = self.link_mtu;
        }
    }

    /// The largest IPv6 packet sent.
    pub fn mtu(&self) -> u16 {
        if self.owner {
            self.mtu
        } else {
            self.cfg.mtu.max(ipv6::MIN_MTU)
        }
    }

    /// What the other cores should use.
    pub fn config(&self) -> V6Config {
        if !self.owner {
            return self.cfg;
        }
        let pick = |s: &Option<Slot>| s.filter(Slot::usable).map(|s| s.addr);
        let g = self.global.filter(Slot::usable);
        V6Config {
            locals: V6Locals {
                link_local: pick(&self.ll),
                global: pick(&self.global),
            },
            onlink_len: g.filter(|s| s.on_link).map_or(0, |s| s.prefix_len),
            router: self.router.map(|r| r.0),
            mtu: self.mtu,
        }
    }

    /// A core other than the owner: the owner's state.
    pub fn set_config(&mut self, cfg: V6Config) {
        if self.cfg.router != cfg.router {
            self.router_mac = None;
        }
        self.cfg = cfg;
    }

    pub fn locals(&self) -> V6Locals {
        self.config().locals
    }

    pub fn global_slot(&self) -> Option<Slot> {
        self.global
    }

    pub fn link_local_slot(&self) -> Option<Slot> {
        self.ll
    }

    pub fn router(&self) -> Option<Ip6> {
        self.config().router
    }

    fn on_link(&self, a: &Ip6) -> bool {
        if is_link_local(a) {
            return true;
        }
        let c = self.config();
        match c.locals.global {
            Some(g) if c.onlink_len > 0 => same_prefix(a, &g, c.onlink_len),
            _ => false,
        }
    }

    /// Learns `ip`'s MAC from a frame it sent us (`ip` on the link), or the
    /// router's (`ip` off the link).
    pub fn learn_from_frame(&mut self, ip: &Ip6, mac: Mac, now: u64) {
        if self.on_link(ip) {
            self.learn(ip, mac, now);
        } else if self.router().is_some() {
            self.router_mac = Some(mac);
        }
    }

    fn learn(&mut self, ip: &Ip6, mac: Mac, now: u64) {
        if *ip == UNSPECIFIED || mac[0] & 1 != 0 {
            return;
        }
        if let Some(e) = self.neighbours.iter_mut().find(|e| e.0 == *ip) {
            e.1 = mac;
            e.2 = now;
            return;
        }
        if let Some(e) = self.neighbours.iter_mut().min_by_key(|e| e.2) {
            *e = (*ip, mac, now);
        }
    }

    /// The next hop of a packet to `dst`.
    pub fn next_hop(&self, dst: &Ip6) -> Option<Ip6> {
        if self.on_link(dst) {
            Some(*dst)
        } else {
            self.router()
        }
    }

    /// The MAC a packet to `dst` goes to, if known.
    pub fn neighbour(&self, dst: &Ip6) -> Option<Mac> {
        let hop = self.next_hop(dst)?;
        self.neighbours
            .iter()
            .find(|e| e.0 == hop && e.0 != UNSPECIFIED)
            .map(|e| e.1)
            .or_else(|| self.router_mac.filter(|_| Some(hop) == self.router()))
    }

    /// Whether frames to Ethernet address `dst` are ours: the all-nodes group
    /// and the solicited-node groups of our addresses (tentative ones too:
    /// DAD listens on them).
    pub fn accepts_mac(&self, dst: &Mac) -> bool {
        if dst[0] != 0x33 || dst[1] != 0x33 || !self.enabled() {
            return false;
        }
        if *dst == multicast_mac(&ALL_NODES) {
            return true;
        }
        self.all_addrs()
            .iter()
            .flatten()
            .any(|a| multicast_mac(&solicited_node(a)) == *dst)
    }

    fn all_addrs(&self) -> [Option<Ip6>; 2] {
        if self.owner {
            [
                self.ll
                    .filter(|s| s.state != State::Duplicate)
                    .map(|s| s.addr),
                self.global
                    .filter(|s| s.state != State::Duplicate)
                    .map(|s| s.addr),
            ]
        } else {
            [self.cfg.locals.link_local, self.cfg.locals.global]
        }
    }

    /// Whether `dst` is an address this host takes ICMPv6 on.
    fn icmp_dst_ok(&self, dst: &Ip6) -> bool {
        *dst == ALL_NODES
            || self
                .all_addrs()
                .iter()
                .flatten()
                .any(|a| a == dst || solicited_node(a) == *dst)
    }

    fn nd_token(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.nd_since) >= 1000 {
            self.nd_tokens = ND_PER_SEC;
            self.nd_since = now;
        }
        if self.nd_tokens == 0 {
            self.stats.nd_limited += 1;
            return false;
        }
        self.nd_tokens -= 1;
        true
    }

    /// Sends one ICMPv6 message.
    #[allow(clippy::too_many_arguments)]
    fn send_icmp(
        &mut self,
        dst_mac: Mac,
        src: &Ip6,
        dst: &Ip6,
        t: u8,
        word: [u8; 4],
        body: &[u8],
        out: &mut impl FnMut(&[u8]),
    ) {
        let mut buf = core::mem::take(&mut self.buf);
        buf.clear();
        ipv4::push_eth(&mut buf, dst_mac, self.mac, ipv6::ETHERTYPE_IPV6);
        let at = buf.len();
        ipv6::push_ipv6(&mut buf, src, dst, NH_ICMPV6, 255, 0);
        ipv6::push_icmp6(&mut buf, src, dst, t, 0, word, body);
        ipv6::fix_len(&mut buf, at);
        if buf.len() - ipv4::ETH_HDR > usize::from(self.mtu()) {
            self.stats.too_big += 1;
        } else {
            out(&buf);
            self.stats.frames_out += 1;
        }
        self.buf = buf;
    }

    /// Sends a Neighbour Solicitation for the next hop of `dst` (owner, rate
    /// limited per address).
    pub fn solicit(&mut self, now: u64, dst: &Ip6, out: &mut impl FnMut(&[u8])) {
        let Some(hop) = self.next_hop(dst) else {
            return;
        };
        let Some(src) = self.locals().for_peer(&hop) else {
            return;
        };
        if !self.owner {
            return;
        }
        if let Some(e) = self.solicited.iter().find(|e| e.0 == hop)
            && now.saturating_sub(e.1) < SOLICIT_EVERY_MS
        {
            return;
        }
        if let Some(e) = self.solicited.iter_mut().min_by_key(|e| e.1) {
            *e = (hop, now);
        }
        let sn = solicited_node(&hop);
        let body = ipv6::ns_body(&hop, Some(self.mac));
        self.send_icmp(multicast_mac(&sn), &src, &sn, ICMP6_NS, [0; 4], &body, out);
        self.stats.ns_out += 1;
    }

    /// An ICMPv6 message for this host (owner: everything; other cores take
    /// no ICMPv6, core 0 keeps it).
    pub fn icmp(
        &mut self,
        now: u64,
        eth_src: Mac,
        ip: &Ipv6<'_>,
        echo_ok: &mut dyn FnMut() -> bool,
        out: &mut impl FnMut(&[u8]),
    ) -> Option<Event6> {
        if !self.owner || !self.icmp_dst_ok(&ip.dst) {
            self.stats.not_for_us += 1;
            self.stats.dropped += 1;
            return None;
        }
        let msg = match ipv6::parse_icmp6(ip) {
            Ok(m) => m,
            Err(_) => {
                self.stats.bad_icmp += 1;
                self.stats.dropped += 1;
                return None;
            }
        };
        match msg {
            Icmp6::Echo {
                request: true,
                ident,
                seq,
                data,
            } => {
                // Never to a multicast group (no amplification), only from a
                // usable address of ours.
                if ip.dst[0] == 0xff || !self.locals().holds(&ip.dst) || ip.src == UNSPECIFIED {
                    return None;
                }
                if !echo_ok() {
                    return None;
                }
                self.learn_from_frame(&ip.src, eth_src, now);
                let mut word = [0u8; 4];
                word[..2].copy_from_slice(&ident.to_be_bytes());
                word[2..].copy_from_slice(&seq.to_be_bytes());
                let (src, dst) = (ip.dst, ip.src);
                let mac = self.neighbour(&dst).unwrap_or(eth_src);
                self.send_icmp(mac, &src, &dst, ICMP6_ECHO_REPLY, word, data, out);
                self.stats.echo_replies += 1;
                None
            }
            Icmp6::NeighbourSolicit { target, slla } => {
                self.stats.ns_in += 1;
                self.on_ns(now, eth_src, ip, target, slla, out)
            }
            Icmp6::NeighbourAdvert { target, tlla, .. } => {
                self.stats.na_in += 1;
                self.on_na(now, target, tlla)
            }
            Icmp6::RouterAdvert(ra) => {
                self.stats.ra_in += 1;
                self.on_ra(now, ip, &ra)
            }
            Icmp6::Echo { .. } | Icmp6::RouterSolicit | Icmp6::Other(_) => None,
        }
    }

    fn slot_of(&mut self, a: &Ip6) -> Option<&mut Slot> {
        if self.ll.is_some_and(|s| s.addr == *a) {
            self.ll.as_mut()
        } else if self.global.is_some_and(|s| s.addr == *a) {
            self.global.as_mut()
        } else {
            None
        }
    }

    fn duplicate(&mut self, a: &Ip6) -> Option<Event6> {
        let s = self.slot_of(a)?;
        if !matches!(s.state, State::Tentative { .. }) {
            return None;
        }
        s.state = State::Duplicate;
        self.stats.dad_duplicate += 1;
        Some(Event6::Duplicate { addr: *a })
    }

    fn on_ns(
        &mut self,
        now: u64,
        eth_src: Mac,
        ip: &Ipv6<'_>,
        target: Ip6,
        slla: Option<Mac>,
        out: &mut impl FnMut(&[u8]),
    ) -> Option<Event6> {
        let state = self.slot_of(&target).map(|s| s.state)?;
        match state {
            State::Tentative { .. } => {
                // Another node probes the same address: both lose it (§5.4.3).
                if ip.src == UNSPECIFIED {
                    return self.duplicate(&target);
                }
                None
            }
            State::Duplicate => None,
            State::Preferred => {
                if !self.nd_token(now) {
                    return None;
                }
                let (w, body) = ipv6::na_parts(&target, ip.src != UNSPECIFIED, self.mac);
                if ip.src == UNSPECIFIED {
                    // Someone's DAD for our address: defend it to all nodes.
                    let (w, body) = ipv6::na_parts(&target, false, self.mac);
                    self.send_icmp(
                        multicast_mac(&ALL_NODES),
                        &target,
                        &ALL_NODES,
                        ICMP6_NA,
                        w,
                        &body,
                        out,
                    );
                } else {
                    let mac = slla.unwrap_or(eth_src);
                    if slla.is_some() {
                        self.learn(&ip.src, mac, now);
                    }
                    self.send_icmp(mac, &target, &ip.src, ICMP6_NA, w, &body, out);
                }
                self.stats.na_out += 1;
                None
            }
        }
    }

    fn on_na(&mut self, now: u64, target: Ip6, tlla: Option<Mac>) -> Option<Event6> {
        if let Some(s) = self.slot_of(&target).map(|s| s.state) {
            return match s {
                State::Tentative { .. } => self.duplicate(&target),
                // Someone else claims an address we hold: counted, kept.
                _ => {
                    self.stats.dad_duplicate += 1;
                    None
                }
            };
        }
        if let Some(m) = tlla {
            self.learn(&target, m, now);
        }
        None
    }

    fn on_ra(&mut self, now: u64, ip: &Ipv6<'_>, ra: &ipv6::RouterAdvert) -> Option<Event6> {
        if self.mode != Some(Mode6::Slaac) {
            self.stats.ra_ignored += 1;
            return None;
        }
        self.ra_seen = true;
        let mut ev = None;
        if let Some(m) = ra.slla {
            self.learn(&ip.src, m, now);
        }
        // The default router.
        if ra.router_lifetime_s > 0 {
            let changed = self.router.map(|r| r.0) != Some(ip.src);
            self.router = Some((ip.src, until(now, u32::from(ra.router_lifetime_s))));
            if changed {
                self.router_mac = None;
                ev = Some(Event6::Router {
                    addr: ip.src,
                    lifetime_s: ra.router_lifetime_s,
                });
            }
        } else if self.router.map(|r| r.0) == Some(ip.src) {
            self.router = None;
            ev = Some(Event6::RouterGone { addr: ip.src });
        }
        // The MTU (RFC 4861 §6.3.4: from 1280 to the link's).
        if let Some(m) = ra.mtu
            && m >= u32::from(ipv6::MIN_MTU)
            && m <= u32::from(self.link_mtu)
            && m as u16 != self.mtu
        {
            self.mtu = m as u16;
            ev = ev.or(Some(Event6::Mtu { mtu: self.mtu }));
        }
        for p in ra.prefixes() {
            if let Some(e) = self.on_prefix(now, p) {
                ev = ev.or(Some(e));
            }
        }
        if ra.prefixes_dropped > 0 {
            self.stats.prefixes_ignored += u64::from(ra.prefixes_dropped);
        }
        ev
    }

    fn on_prefix(&mut self, now: u64, p: &ipv6::PrefixInfo) -> Option<Event6> {
        if !p.autonomous || is_link_local(&p.prefix) || p.preferred_s > p.valid_s {
            return None;
        }
        if p.len != 64 {
            self.stats.prefixes_ignored += 1;
            return Some(Event6::PrefixIgnored {
                prefix: p.prefix,
                len: p.len,
            });
        }
        let addr = with_iid(&p.prefix, eui64(self.mac));
        match self.global.as_mut() {
            None => {
                if p.valid_s == 0 {
                    return None;
                }
                self.global = Some(Slot {
                    addr,
                    state: State::Tentative {
                        since: now,
                        sent: false,
                    },
                    prefix_len: 64,
                    on_link: p.on_link,
                    valid_until: until(now, p.valid_s),
                });
                self.mld_due = true;
                None
            }
            Some(g) if g.addr == addr => {
                // RFC 4862 §5.5.3 (e).
                let new = until(now, p.valid_s);
                let remaining = g.valid_until.saturating_sub(now);
                let asked = new.saturating_sub(now);
                if asked > TWO_HOURS_MS || new > g.valid_until {
                    g.valid_until = new;
                } else if remaining > TWO_HOURS_MS {
                    g.valid_until = now + TWO_HOURS_MS;
                }
                g.on_link |= p.on_link;
                None
            }
            Some(_) => {
                self.stats.prefixes_ignored += 1;
                Some(Event6::PrefixIgnored {
                    prefix: p.prefix,
                    len: p.len,
                })
            }
        }
    }

    /// Timers (owner): DAD probes and their end, the MLD report, Router
    /// Solicitations, lifetimes. At most one event per call; call until
    /// `None`.
    pub fn poll(&mut self, now: u64, out: &mut impl FnMut(&[u8])) -> Option<Event6> {
        if !self.owner || self.mode.is_none() {
            return None;
        }
        if self.mld_due {
            self.mld_due = false;
            let groups: Vec<Ip6> = self
                .all_addrs()
                .iter()
                .flatten()
                .map(solicited_node)
                .collect();
            let mut buf = core::mem::take(&mut self.buf);
            buf.clear();
            ipv4::push_eth(
                &mut buf,
                multicast_mac(&ipv6::MLDV2_ROUTERS),
                self.mac,
                ipv6::ETHERTYPE_IPV6,
            );
            ipv6::push_mld_report(&mut buf, &UNSPECIFIED, &groups);
            out(&buf);
            self.stats.frames_out += 1;
            self.buf = buf;
        }
        for which in [false, true] {
            let slot = if which { self.global } else { self.ll };
            let Some(s) = slot else { continue };
            match s.state {
                State::Tentative { sent: false, .. } => {
                    let sn = solicited_node(&s.addr);
                    let body = ipv6::ns_body(&s.addr, None);
                    self.send_icmp(
                        multicast_mac(&sn),
                        &UNSPECIFIED,
                        &sn,
                        ICMP6_NS,
                        [0; 4],
                        &body,
                        out,
                    );
                    self.stats.ns_out += 1;
                    if let Some(x) = self.slot_of(&s.addr) {
                        x.state = State::Tentative {
                            since: now,
                            sent: true,
                        };
                    }
                }
                State::Tentative { since, sent: true }
                    if now.saturating_sub(since) >= DAD_WAIT_MS =>
                {
                    if let Some(x) = self.slot_of(&s.addr) {
                        x.state = State::Preferred;
                    }
                    self.stats.dad_ok += 1;
                    if !which {
                        // RS once the link-local address is usable.
                        self.rs_next = now;
                    }
                    return Some(Event6::AddressUp {
                        addr: s.addr,
                        global: which,
                    });
                }
                _ => {}
            }
        }
        // Router Solicitations until an RA arrives.
        if self.mode == Some(Mode6::Slaac)
            && !self.ra_seen
            && let Some(ll) = self.ll.filter(Slot::usable)
            && now >= self.rs_next
        {
            if self.rs_sent < RS_COUNT {
                self.rs_sent += 1;
                self.rs_next = now + RS_INTERVAL_MS;
                let body = ipv6::rs_body(Some(self.mac));
                self.send_icmp(
                    multicast_mac(&ALL_ROUTERS),
                    &ll.addr,
                    &ALL_ROUTERS,
                    ICMP6_RS,
                    [0; 4],
                    &body,
                    out,
                );
                self.stats.rs_out += 1;
            } else if self.rs_sent == RS_COUNT {
                self.rs_sent += 1;
                return Some(Event6::NoRouter);
            }
        }
        // Lifetimes.
        if let Some(g) = self.global
            && g.valid_until <= now
        {
            self.global = None;
            return Some(Event6::AddressExpired { addr: g.addr });
        }
        if let Some((r, t)) = self.router
            && t <= now
        {
            self.router = None;
            self.router_mac = None;
            return Some(Event6::RouterGone { addr: r });
        }
        None
    }

    /// Whether [`Host6::poll`] has work within a second (DAD, MLD).
    pub fn busy(&self) -> bool {
        self.owner
            && self.mode.is_some()
            && (self.mld_due
                || self
                    .ll
                    .is_some_and(|s| matches!(s.state, State::Tentative { .. }))
                || self
                    .global
                    .is_some_and(|s| matches!(s.state, State::Tentative { .. })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv6::{ICMP6_RA, parse_ipv6};

    const MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const RMAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
    const RTR: Ip6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const PFX: Ip6 = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn pkt(src: &Ip6, dst: &Ip6, t: u8, word: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        ipv6::push_ipv6(&mut b, src, dst, NH_ICMPV6, 255, 0);
        ipv6::push_icmp6(&mut b, src, dst, t, 0, word, body);
        ipv6::fix_len(&mut b, 0);
        b
    }

    fn feed(h: &mut Host6, now: u64, p: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Event6> {
        let ip = parse_ipv6(p).unwrap();
        h.icmp(now, RMAC, &ip, &mut || true, &mut |f| out.push(f.to_vec()))
    }

    fn drain(h: &mut Host6, now: u64, out: &mut Vec<Vec<u8>>) -> Vec<Event6> {
        let mut ev = Vec::new();
        while let Some(e) = h.poll(now, &mut |f| out.push(f.to_vec())) {
            ev.push(e);
        }
        ev
    }

    fn icmp_of(f: &[u8]) -> (Ipv6<'_>, Icmp6<'_>) {
        let ip = parse_ipv6(&f[14..]).unwrap();
        let m = ipv6::parse_icmp6(&ip).unwrap();
        (ip, m)
    }

    fn ra(prefix: Ip6, valid: u32, preferred: u32, lifetime: u16, mtu: Option<u32>) -> Vec<u8> {
        let mut body = alloc::vec![0u8; 8];
        body.extend_from_slice(&[1, 1]);
        body.extend_from_slice(&RMAC);
        if let Some(m) = mtu {
            body.extend_from_slice(&[5, 1, 0, 0]);
            body.extend_from_slice(&m.to_be_bytes());
        }
        body.extend_from_slice(&[3, 4, 64, 0xc0]);
        body.extend_from_slice(&valid.to_be_bytes());
        body.extend_from_slice(&preferred.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&prefix);
        let lt = lifetime.to_be_bytes();
        pkt(&RTR, &ALL_NODES, ICMP6_RA, [64, 0, lt[0], lt[1]], &body)
    }

    fn slaac_up(now: u64) -> (Host6, Vec<Vec<u8>>) {
        let mut h = Host6::new(MAC, true);
        h.start(now, Mode6::Slaac);
        let mut out = Vec::new();
        assert!(drain(&mut h, now, &mut out).is_empty());
        assert_eq!(
            drain(&mut h, now + DAD_WAIT_MS, &mut out),
            alloc::vec![Event6::AddressUp {
                addr: link_local_of(MAC),
                global: false
            }]
        );
        (h, out)
    }

    #[test]
    fn slaac_from_dad_to_a_global_address() {
        let (mut h, mut out) = slaac_up(0);
        // The MLD report, the DAD probe from `::`, then a Router Solicitation.
        let (ip, m) = icmp_of(&out[1]);
        assert_eq!(ip.src, UNSPECIFIED);
        assert!(
            matches!(m, Icmp6::NeighbourSolicit { slla: None, target } if target == link_local_of(MAC))
        );
        assert_eq!(out.len(), 3);
        let (ip, m) = icmp_of(&out[2]);
        assert_eq!(
            (ip.src, ip.dst, m),
            (link_local_of(MAC), ALL_ROUTERS, Icmp6::RouterSolicit)
        );
        assert_eq!(h.config().locals.global, None);
        // An RA with a prefix, a router and an MTU.
        out.clear();
        let ev = feed(
            &mut h,
            2000,
            &ra(PFX, 86400, 14400, 1800, Some(1480)),
            &mut out,
        );
        assert_eq!(
            ev,
            Some(Event6::Router {
                addr: RTR,
                lifetime_s: 1800
            })
        );
        assert_eq!(h.mtu(), 1480);
        let want = with_iid(&PFX, eui64(MAC));
        assert_eq!(h.global_slot().unwrap().addr, want);
        // Not usable until DAD ends.
        assert_eq!(h.config().locals.global, None);
        let ev = drain(&mut h, 2000, &mut out);
        assert!(ev.is_empty());
        let ev = drain(&mut h, 3000, &mut out);
        assert_eq!(
            ev,
            alloc::vec![Event6::AddressUp {
                addr: want,
                global: true
            }]
        );
        let c = h.config();
        assert_eq!(
            (c.locals.global, c.onlink_len, c.router, c.mtu),
            (Some(want), 64, Some(RTR), 1480)
        );
        // Off-link peers go through the router (its MAC from the RA).
        let peer: Ip6 = [0x20, 1, 0xd, 0xb8, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        assert_eq!(h.next_hop(&peer), Some(RTR));
        assert_eq!(h.neighbour(&peer), Some(RMAC));
        // A second prefix is ignored.
        let mut other = PFX;
        other[5] = 2;
        assert_eq!(
            feed(&mut h, 4000, &ra(other, 100, 50, 1800, None), &mut out),
            Some(Event6::PrefixIgnored {
                prefix: other,
                len: 64
            })
        );
        // Router lifetime 0 removes the router.
        assert_eq!(
            feed(&mut h, 5000, &ra(PFX, 86400, 14400, 0, None), &mut out),
            Some(Event6::RouterGone { addr: RTR })
        );
        assert_eq!(h.next_hop(&peer), None);
    }

    #[test]
    fn the_two_hour_rule_and_expiry() {
        let (mut h, mut out) = slaac_up(0);
        feed(&mut h, 1000, &ra(PFX, 10_000, 5_000, 1800, None), &mut out);
        drain(&mut h, 2000, &mut out);
        drain(&mut h, 3000, &mut out);
        assert!(h.config().locals.global.is_some());
        // A short lifetime cannot cut a long remaining one below two hours.
        feed(&mut h, 4000, &ra(PFX, 10, 5, 1800, None), &mut out);
        assert_eq!(h.global_slot().unwrap().valid_until, 4000 + TWO_HOURS_MS);
        // At the end of the valid lifetime the address goes.
        let end = h.global_slot().unwrap().valid_until;
        let ev = drain(&mut h, end, &mut out);
        assert!(ev.contains(&Event6::AddressExpired {
            addr: with_iid(&PFX, eui64(MAC))
        }));
        assert_eq!(h.config().locals.global, None);
    }

    #[test]
    fn dad_detects_a_duplicate_and_the_address_is_never_used() {
        let mut h = Host6::new(MAC, true);
        h.start(0, Mode6::Slaac);
        let mut out = Vec::new();
        drain(&mut h, 0, &mut out);
        let ll = link_local_of(MAC);
        // Another node answers for it.
        let (w, body) = ipv6::na_parts(&ll, false, [9; 6]);
        let ev = feed(
            &mut h,
            500,
            &pkt(&RTR, &ALL_NODES, ICMP6_NA, w, &body),
            &mut out,
        );
        assert_eq!(ev, Some(Event6::Duplicate { addr: ll }));
        assert!(drain(&mut h, 5000, &mut out).is_empty());
        assert_eq!(h.config().locals, V6Locals::NONE);
        assert_eq!(h.stats.dad_duplicate, 1);
        // A simultaneous DAD probe also counts.
        let mut h = Host6::new(MAC, true);
        h.start(0, Mode6::Slaac);
        drain(&mut h, 0, &mut out);
        let sn = solicited_node(&ll);
        let ev = feed(
            &mut h,
            10,
            &pkt(
                &UNSPECIFIED,
                &sn,
                ICMP6_NS,
                [0; 4],
                &ipv6::ns_body(&ll, None),
            ),
            &mut out,
        );
        assert_eq!(ev, Some(Event6::Duplicate { addr: ll }));
    }

    #[test]
    fn solicitations_for_our_addresses_are_answered_and_dad_of_others_defended() {
        let (mut h, mut out) = slaac_up(0);
        let ll = link_local_of(MAC);
        out.clear();
        let sn = solicited_node(&ll);
        feed(
            &mut h,
            2000,
            &pkt(&RTR, &sn, ICMP6_NS, [0; 4], &ipv6::ns_body(&ll, Some(RMAC))),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][..6], &RMAC);
        let (ip, m) = icmp_of(&out[0]);
        assert_eq!((ip.src, ip.dst), (ll, RTR));
        assert!(matches!(
            m,
            Icmp6::NeighbourAdvert {
                solicited: true,
                tlla: Some(MAC),
                ..
            }
        ));
        // The neighbour was learned from its SLLA.
        assert_eq!(h.neighbour(&RTR), Some(RMAC));
        // DAD of our address by another node: defended to all nodes.
        out.clear();
        feed(
            &mut h,
            2001,
            &pkt(
                &UNSPECIFIED,
                &sn,
                ICMP6_NS,
                [0; 4],
                &ipv6::ns_body(&ll, None),
            ),
            &mut out,
        );
        let (ip, m) = icmp_of(&out[0]);
        assert_eq!(ip.dst, ALL_NODES);
        assert!(matches!(
            m,
            Icmp6::NeighbourAdvert {
                solicited: false,
                ..
            }
        ));
        // An NS for an address that is not ours: nothing.
        out.clear();
        let mut not_ours = ll;
        not_ours[15] ^= 1;
        feed(
            &mut h,
            2002,
            &pkt(
                &RTR,
                &solicited_node(&not_ours),
                ICMP6_NS,
                [0; 4],
                &ipv6::ns_body(&not_ours, None),
            ),
            &mut out,
        );
        assert!(out.is_empty());
        assert!(h.accepts_mac(&multicast_mac(&sn)));
        assert!(h.accepts_mac(&multicast_mac(&ALL_NODES)));
        assert!(!h.accepts_mac(&multicast_mac(&solicited_node(&not_ours))));
    }

    #[test]
    fn nd_answers_are_rate_limited() {
        let (mut h, mut out) = slaac_up(0);
        let ll = link_local_of(MAC);
        let sn = solicited_node(&ll);
        let ns = pkt(&RTR, &sn, ICMP6_NS, [0; 4], &ipv6::ns_body(&ll, Some(RMAC)));
        out.clear();
        for _ in 0..300 {
            feed(&mut h, 2000, &ns, &mut out);
        }
        assert_eq!(out.len(), ND_PER_SEC as usize);
        assert_eq!(h.stats.nd_limited, 200);
    }

    #[test]
    fn static_mode_ignores_ras_and_routes_by_its_gateway() {
        let addr: Ip6 = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
        let mut h = Host6::new(MAC, true);
        h.start(
            0,
            Mode6::Static {
                addr,
                prefix_len: 64,
                gateway: RTR,
            },
        );
        let mut out = Vec::new();
        drain(&mut h, 0, &mut out);
        let ev = drain(&mut h, 1000, &mut out);
        assert_eq!(ev.len(), 2, "{ev:?}");
        assert!(feed(&mut h, 1500, &ra(PFX, 100, 50, 1800, Some(1300)), &mut out).is_none());
        assert_eq!((h.stats.ra_ignored, h.mtu()), (1, 1500));
        let c = h.config();
        assert_eq!(
            (c.locals.global, c.onlink_len, c.router),
            (Some(addr), 64, Some(RTR))
        );
        // On-link by the prefix; the gateway's MAC is unknown until it speaks.
        let near: Ip6 = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20];
        assert_eq!(h.next_hop(&near), Some(near));
        let far: Ip6 = [0x20, 1, 0xd, 0xb8, 7, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20];
        assert_eq!(h.neighbour(&far), None);
        out.clear();
        h.solicit(1600, &far, &mut |f| out.push(f.to_vec()));
        h.solicit(1700, &far, &mut |f| out.push(f.to_vec()));
        assert_eq!(out.len(), 1, "one solicitation per second");
        let (ip, m) = icmp_of(&out[0]);
        assert_eq!(ip.dst, solicited_node(&RTR));
        assert!(matches!(m, Icmp6::NeighbourSolicit { target, .. } if target == RTR));
        // Its NA teaches the MAC.
        let (w, body) = ipv6::na_parts(&RTR, true, RMAC);
        feed(
            &mut h,
            1800,
            &pkt(&RTR, &link_local_of(MAC), ICMP6_NA, w, &body),
            &mut out,
        );
        assert_eq!(h.neighbour(&far), Some(RMAC));
    }

    #[test]
    fn a_worker_takes_the_owners_configuration() {
        let mut w = Host6::new(MAC, false);
        assert!(!w.enabled());
        w.start(0, Mode6::Slaac);
        assert!(!w.enabled(), "only the owner starts");
        let g: Ip6 = with_iid(&PFX, eui64(MAC));
        w.set_config(V6Config {
            locals: V6Locals {
                link_local: Some(link_local_of(MAC)),
                global: Some(g),
            },
            onlink_len: 64,
            router: Some(RTR),
            mtu: 1400,
        });
        assert!(w.enabled());
        assert_eq!(w.mtu(), 1400);
        let peer: Ip6 = [0x20, 1, 0xd, 0xb8, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        assert_eq!(w.neighbour(&peer), None);
        // A frame from the off-link peer arrives through the router.
        w.learn_from_frame(&peer, RMAC, 1);
        assert_eq!(w.neighbour(&peer), Some(RMAC));
        // A worker answers no ICMPv6.
        let mut out = Vec::new();
        let e = pkt(&RTR, &g, ipv6::ICMP6_ECHO_REQUEST, [0; 4], b"x");
        assert!(feed(&mut w, 2, &e, &mut out).is_none());
        assert!(out.is_empty());
    }

    #[test]
    fn echo_is_answered_from_a_usable_address_only() {
        let (mut h, mut out) = slaac_up(0);
        let ll = link_local_of(MAC);
        out.clear();
        let e = pkt(&RTR, &ll, ipv6::ICMP6_ECHO_REQUEST, [0, 1, 0, 2], b"ping");
        feed(&mut h, 2000, &e, &mut out);
        let (ip, m) = icmp_of(&out[0]);
        assert_eq!((ip.src, ip.dst), (ll, RTR));
        assert_eq!(
            m,
            Icmp6::Echo {
                request: false,
                ident: 1,
                seq: 2,
                data: b"ping"
            }
        );
        // To all nodes: no answer.
        out.clear();
        feed(
            &mut h,
            2000,
            &pkt(&RTR, &ALL_NODES, ipv6::ICMP6_ECHO_REQUEST, [0; 4], b"x"),
            &mut out,
        );
        assert!(out.is_empty());
    }
}
