//! One core's IPv4 interface (M14): Ethernet in and out, a small
//! neighbour cache, and, on the core that owns the NIC, ARP replies, ICMP
//! echo and the DHCP client. TCP segments are handed to the caller (which
//! owns the core's TCP stack) and wrapped again by [`Iface::send_tcp`].
//!
//! Replies never need ARP: the cache learns the sender's MAC from every
//! IPv4 frame received, and a server only answers peers that reached it.

use alloc::vec::Vec;

use crate::dhcp;
use crate::ipv4::{self, Arp, Echo, Ip, Mac, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

const NEIGHBOURS: usize = 32;
/// ICMP echo replies per second.
const ICMP_PER_SEC: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Dhcp(dhcp::Event),
    PingReply { from: Ip, rtt_ms: u64 },
}

/// What a received frame turned out to be.
pub enum Rx<'a> {
    /// A TCP segment for us: give it to the TCP stack.
    Tcp {
        src: Ip,
        seg: &'a [u8],
    },
    Event(Event),
    None,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub frames_in: u64,
    pub frames_out: u64,
    pub dropped: u64,
    pub arp_replies: u64,
    pub icmp_replies: u64,
    pub icmp_limited: u64,
    pub no_neighbour: u64,
}

pub struct Iface {
    mac: Mac,
    /// Owns the NIC: answers ARP and ICMP, runs DHCP.
    owner: bool,
    addr: Option<Ip>,
    prefix: u8,
    router: Option<Ip>,
    neighbours: [(Ip, Mac, u64); NEIGHBOURS],
    dhcp: Option<dhcp::Client>,
    ip_id: u16,
    icmp_tokens: u32,
    icmp_since: u64,
    ping: Option<(Ip, u16, u64)>,
    buf: Vec<u8>,
    pub stats: Stats,
}

impl Iface {
    /// An interface; `dhcp_xid` starts DHCP (owner only), otherwise the
    /// address comes from [`Iface::set_addr`].
    pub fn new(mac: Mac, owner: bool, dhcp_xid: Option<u32>, now_ms: u64) -> Self {
        Self {
            mac,
            owner,
            addr: None,
            prefix: 0,
            router: None,
            neighbours: [([0; 4], [0; 6], 0); NEIGHBOURS],
            dhcp: dhcp_xid
                .filter(|_| owner)
                .map(|x| dhcp::Client::new(mac, x, now_ms)),
            ip_id: 1,
            icmp_tokens: ICMP_PER_SEC,
            icmp_since: now_ms,
            ping: None,
            buf: Vec::with_capacity(1600),
            stats: Stats::default(),
        }
    }

    pub fn addr(&self) -> Option<Ip> {
        self.addr
    }

    pub fn router(&self) -> Option<Ip> {
        self.router
    }

    pub fn set_addr(&mut self, addr: Option<(Ip, u8)>, router: Option<Ip>) {
        self.addr = addr.map(|a| a.0);
        self.prefix = addr.map_or(0, |a| a.1);
        self.router = router;
    }

    fn same_subnet(&self, ip: Ip) -> bool {
        let Some(a) = self.addr else { return false };
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0);
        u32::from_be_bytes(a) & mask == u32::from_be_bytes(ip) & mask
    }

    fn learn(&mut self, ip: Ip, mac: Mac, now_ms: u64) {
        if ip == [0; 4] || mac == ipv4::BROADCAST_MAC {
            return;
        }
        if let Some(e) = self.neighbours.iter_mut().find(|e| e.0 == ip) {
            e.1 = mac;
            e.2 = now_ms;
            return;
        }
        // Replace the least recently seen entry.
        if let Some(e) = self.neighbours.iter_mut().min_by_key(|e| e.2) {
            *e = (ip, mac, now_ms);
        }
    }

    fn neighbour(&self, ip: Ip) -> Option<Mac> {
        let hop = if self.same_subnet(ip) {
            ip
        } else {
            self.router?
        };
        self.neighbours
            .iter()
            .find(|e| e.0 == hop && e.0 != [0; 4])
            .map(|e| e.1)
    }

    fn send_ip(
        &mut self,
        dst: Ip,
        dst_mac: Mac,
        proto: u8,
        body: impl FnOnce(&mut Vec<u8>, Ip),
        out: &mut impl FnMut(&[u8]),
    ) {
        let src = self.addr.unwrap_or([0; 4]);
        let mut buf = core::mem::take(&mut self.buf);
        buf.clear();
        ipv4::push_eth(&mut buf, dst_mac, self.mac, ipv4::ETHERTYPE_IPV4);
        let ip_at = buf.len();
        ipv4::push_ipv4(&mut buf, src, dst, proto, self.ip_id, 0);
        self.ip_id = self.ip_id.wrapping_add(1);
        body(&mut buf, src);
        // Fix the IPv4 total length and checksum now that the body is in.
        let total = (buf.len() - ip_at) as u16;
        if let Some(l) = buf.get_mut(ip_at + 2..ip_at + 4) {
            l.copy_from_slice(&total.to_be_bytes());
        }
        if let Some(c) = buf.get_mut(ip_at + 10..ip_at + 12) {
            c.copy_from_slice(&[0, 0]);
        }
        let c = ipv4::csum(0, buf.get(ip_at..ip_at + ipv4::IP_HDR).unwrap_or(&[]));
        if let Some(d) = buf.get_mut(ip_at + 10..ip_at + 12) {
            d.copy_from_slice(&c.to_be_bytes());
        }
        out(&buf);
        self.stats.frames_out += 1;
        self.buf = buf;
    }

    /// Wraps a TCP segment from the stack into a frame for `dst`.
    pub fn send_tcp(&mut self, dst: Ip, seg: &[u8], out: &mut impl FnMut(&[u8])) {
        let Some(mac) = self.neighbour(dst) else {
            self.stats.no_neighbour += 1;
            return;
        };
        self.send_ip(dst, mac, PROTO_TCP, |b, _| b.extend_from_slice(seg), out);
    }

    /// Handles one received frame.
    pub fn receive<'a>(
        &mut self,
        now_ms: u64,
        frame: &'a [u8],
        out: &mut impl FnMut(&[u8]),
    ) -> Rx<'a> {
        self.stats.frames_in += 1;
        let Some(eth) = ipv4::parse_eth(frame) else {
            self.stats.dropped += 1;
            return Rx::None;
        };
        if eth.dst != self.mac && eth.dst != ipv4::BROADCAST_MAC {
            self.stats.dropped += 1;
            return Rx::None;
        }
        match eth.ethertype {
            ipv4::ETHERTYPE_ARP => {
                if let Some(a) = ipv4::parse_arp(eth.payload) {
                    self.learn(a.spa, a.sha, now_ms);
                    if self.owner && a.op == 1 && Some(a.tpa) == self.addr {
                        let reply = Arp {
                            op: 2,
                            sha: self.mac,
                            spa: a.tpa,
                            tha: a.sha,
                            tpa: a.spa,
                        };
                        let mut buf = core::mem::take(&mut self.buf);
                        ipv4::emit_arp(&mut buf, self.mac, &reply);
                        out(&buf);
                        self.buf = buf;
                        self.stats.arp_replies += 1;
                        self.stats.frames_out += 1;
                    }
                }
                Rx::None
            }
            ipv4::ETHERTYPE_IPV4 => {
                let Ok(ip) = ipv4::parse_ipv4(eth.payload) else {
                    self.stats.dropped += 1;
                    return Rx::None;
                };
                let for_us = Some(ip.dst) == self.addr;
                if for_us {
                    self.learn(ip.src, eth.src, now_ms);
                }
                match ip.proto {
                    PROTO_TCP if for_us => Rx::Tcp {
                        src: ip.src,
                        seg: ip.payload,
                    },
                    PROTO_ICMP if for_us && self.owner => {
                        self.icmp(now_ms, ip.src, eth.src, ip.payload, out)
                    }
                    PROTO_UDP if self.owner => self.udp(now_ms, ip.src, ip.dst, ip.payload),
                    _ => {
                        self.stats.dropped += 1;
                        Rx::None
                    }
                }
            }
            _ => {
                self.stats.dropped += 1;
                Rx::None
            }
        }
    }

    fn icmp<'a>(
        &mut self,
        now_ms: u64,
        src: Ip,
        src_mac: Mac,
        p: &[u8],
        out: &mut impl FnMut(&[u8]),
    ) -> Rx<'a> {
        let Some(e) = ipv4::parse_icmp_echo(p) else {
            self.stats.dropped += 1;
            return Rx::None;
        };
        if !e.request {
            if let Some((dst, ident, sent)) = self.ping
                && dst == src
                && ident == e.ident
            {
                self.ping = None;
                return Rx::Event(Event::PingReply {
                    from: src,
                    rtt_ms: now_ms.saturating_sub(sent),
                });
            }
            return Rx::None;
        }
        if now_ms.saturating_sub(self.icmp_since) >= 1000 {
            self.icmp_tokens = ICMP_PER_SEC;
            self.icmp_since = now_ms;
        }
        if self.icmp_tokens == 0 {
            self.stats.icmp_limited += 1;
            return Rx::None;
        }
        self.icmp_tokens -= 1;
        let reply = Echo {
            request: false,
            ..e
        };
        self.send_ip(
            src,
            src_mac,
            PROTO_ICMP,
            |b, _| ipv4::push_icmp_echo(b, &reply),
            out,
        );
        self.stats.icmp_replies += 1;
        Rx::None
    }

    fn udp<'a>(&mut self, now_ms: u64, src: Ip, dst: Ip, p: &[u8]) -> Rx<'a> {
        let Some(u) = ipv4::parse_udp(src, dst, p) else {
            self.stats.dropped += 1;
            return Rx::None;
        };
        if u.dport != dhcp::CLIENT_PORT || u.sport != dhcp::SERVER_PORT {
            self.stats.dropped += 1;
            return Rx::None;
        }
        let ev = self.dhcp.as_mut().and_then(|d| d.input(now_ms, u.payload));
        self.dhcp_event(ev)
    }

    fn dhcp_event<'a>(&mut self, ev: Option<dhcp::Event>) -> Rx<'a> {
        match ev {
            Some(e @ (dhcp::Event::Bound(l) | dhcp::Event::Renewed(l))) => {
                self.set_addr(Some((l.addr, l.prefix)), l.router);
                Rx::Event(Event::Dhcp(e))
            }
            Some(dhcp::Event::Lost) => {
                self.set_addr(None, None);
                Rx::Event(Event::Dhcp(dhcp::Event::Lost))
            }
            None => Rx::None,
        }
    }

    /// Timers: DHCP retransmissions, renewals and expiry.
    pub fn poll(&mut self, now_ms: u64, out: &mut impl FnMut(&[u8])) -> Option<Event> {
        let (send, ev) = self.dhcp.as_mut().map_or((None, None), |d| d.poll(now_ms));
        if let Some(s) = send {
            self.send_ip(
                s.dst,
                ipv4::BROADCAST_MAC,
                PROTO_UDP,
                |b, src| {
                    ipv4::push_udp(
                        b,
                        src,
                        s.dst,
                        dhcp::CLIENT_PORT,
                        dhcp::SERVER_PORT,
                        &s.payload,
                    )
                },
                out,
            );
        }
        match self.dhcp_event(ev) {
            Rx::Event(e) => Some(e),
            _ => None,
        }
    }

    /// Asks for `ip`'s MAC (ARP request), e.g. the router before a ping.
    pub fn resolve(&mut self, ip: Ip, out: &mut impl FnMut(&[u8])) {
        let req = Arp {
            op: 1,
            sha: self.mac,
            spa: self.addr.unwrap_or([0; 4]),
            tha: [0; 6],
            tpa: ip,
        };
        let mut buf = core::mem::take(&mut self.buf);
        ipv4::emit_arp(&mut buf, self.mac, &req);
        out(&buf);
        self.buf = buf;
        self.stats.frames_out += 1;
    }

    /// Sends one ICMP echo request to `dst` (once its MAC is known).
    /// Returns false if the neighbour is not resolved yet.
    pub fn ping(&mut self, now_ms: u64, dst: Ip, ident: u16, out: &mut impl FnMut(&[u8])) -> bool {
        let Some(mac) = self.neighbour(dst) else {
            return false;
        };
        let e = Echo {
            request: true,
            ident,
            seq: 1,
            data: b"urMQTT ping",
        };
        self.send_ip(
            dst,
            mac,
            PROTO_ICMP,
            |b, _| ipv4::push_icmp_echo(b, &e),
            out,
        );
        self.ping = Some((dst, ident, now_ms));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const GW: Mac = [0x52, 0x55, 10, 0, 2, 2];

    fn frame(src_ip: Ip, dst_ip: Ip, proto: u8, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        ipv4::push_eth(&mut b, MAC, GW, ipv4::ETHERTYPE_IPV4);
        ipv4::push_ipv4(&mut b, src_ip, dst_ip, proto, 1, body.len());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn arp_icmp_tcp_and_neighbour_learning() {
        let mut i = Iface::new(MAC, true, None, 0);
        i.set_addr(Some(([10, 0, 2, 15], 24)), Some([10, 0, 2, 2]));
        let mut out: Vec<Vec<u8>> = Vec::new();
        // ARP request for us: answered, sender learned.
        let mut req = Vec::new();
        ipv4::emit_arp(
            &mut req,
            GW,
            &Arp {
                op: 1,
                sha: GW,
                spa: [10, 0, 2, 2],
                tha: [0; 6],
                tpa: [10, 0, 2, 15],
            },
        );
        assert!(matches!(
            i.receive(0, &req, &mut |f| out.push(f.to_vec())),
            Rx::None
        ));
        let a = ipv4::parse_arp(ipv4::parse_eth(&out[0]).unwrap().payload).unwrap();
        assert_eq!((a.op, a.sha, a.tpa), (2, MAC, [10, 0, 2, 2]));
        // ICMP echo request: answered.
        out.clear();
        let mut echo = Vec::new();
        ipv4::push_icmp_echo(
            &mut echo,
            &Echo {
                request: true,
                ident: 1,
                seq: 2,
                data: b"x",
            },
        );
        i.receive(
            1,
            &frame([10, 0, 2, 2], [10, 0, 2, 15], PROTO_ICMP, &echo),
            &mut |f| out.push(f.to_vec()),
        );
        let ip = ipv4::parse_ipv4(ipv4::parse_eth(&out[0]).unwrap().payload).unwrap();
        assert!(!ipv4::parse_icmp_echo(ip.payload).unwrap().request);
        // TCP for us is handed out; a reply to an off-subnet peer goes via
        // the learned router MAC.
        let f = frame([1, 2, 3, 4], [10, 0, 2, 15], PROTO_TCP, &[0; 20]);
        assert!(matches!(
            i.receive(2, &f, &mut |_| {}),
            Rx::Tcp {
                src: [1, 2, 3, 4],
                ..
            }
        ));
        out.clear();
        i.send_tcp([1, 2, 3, 4], &[0; 20], &mut |f| out.push(f.to_vec()));
        assert_eq!(ipv4::parse_eth(&out[0]).unwrap().dst, GW);
        // Not for us: dropped.
        let other = frame([10, 0, 2, 2], [10, 0, 2, 99], PROTO_TCP, &[0; 20]);
        assert!(matches!(i.receive(3, &other, &mut |_| {}), Rx::None));
    }

    #[test]
    fn icmp_is_rate_limited() {
        let mut i = Iface::new(MAC, true, None, 0);
        i.set_addr(Some(([10, 0, 2, 15], 24)), None);
        let mut echo = Vec::new();
        ipv4::push_icmp_echo(
            &mut echo,
            &Echo {
                request: true,
                ident: 1,
                seq: 2,
                data: b"x",
            },
        );
        let f = frame([10, 0, 2, 2], [10, 0, 2, 15], PROTO_ICMP, &echo);
        let mut n = 0;
        for _ in 0..500 {
            i.receive(0, &f, &mut |_| n += 1);
        }
        assert_eq!(n, ICMP_PER_SEC as usize);
        assert_eq!(i.stats.icmp_limited, 400);
    }
}
