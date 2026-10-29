//! DHCPv4 client (RFC 2131), sans-IO: DISCOVER → OFFER → REQUEST → ACK,
//! renewing at T1 and rebinding at T2. A lease that expires (or a NAK)
//! goes back to DISCOVER. One ISO serves many VMs, so DHCP is the default;
//! static addresses come from the build-time configuration instead.

use alloc::vec::Vec;

use crate::ipv4::{Ip, Mac};

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;
/// Retransmission of DISCOVER/REQUEST: 4 s, doubling to 64 s (§4.1).
const RETRY_MS: u64 = 4_000;
const RETRY_MAX_MS: u64 = 64_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub addr: Ip,
    pub prefix: u8,
    pub router: Option<Ip>,
    pub dns: Option<Ip>,
    pub server: Ip,
    pub lease_s: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Bound(Lease),
    /// Renewed or rebound (same or new parameters).
    Renewed(Lease),
    Lost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Selecting,
    Requesting { offer: Ip, server: Ip },
    Bound,
    Renewing,
    Rebinding,
}

pub struct Client {
    mac: Mac,
    xid: u32,
    state: State,
    next_tx_ms: u64,
    retry_ms: u64,
    lease: Option<Lease>,
    bound_at_ms: u64,
    t1_ms: u64,
    t2_ms: u64,
    expiry_ms: u64,
}

/// A message to send: UDP payload, destination (broadcast or server) and
/// our source address (0.0.0.0 until bound).
pub struct Send {
    pub payload: Vec<u8>,
    pub src: Ip,
    pub dst: Ip,
}

struct Reply {
    op: u8,
    xid: u32,
    yiaddr: Ip,
    msg: u8,
    mask: Option<Ip>,
    router: Option<Ip>,
    dns: Option<Ip>,
    server: Option<Ip>,
    lease: Option<u32>,
    t1: Option<u32>,
    t2: Option<u32>,
    chaddr: Mac,
}

fn parse(p: &[u8]) -> Option<Reply> {
    if p.get(236..240)? != MAGIC {
        return None;
    }
    let ip = |at: usize| -> Option<Ip> { p.get(at..at + 4)?.try_into().ok() };
    let mut r = Reply {
        op: *p.first()?,
        xid: u32::from_be_bytes(p.get(4..8)?.try_into().ok()?),
        yiaddr: ip(16)?,
        msg: 0,
        mask: None,
        router: None,
        dns: None,
        server: None,
        lease: None,
        t1: None,
        t2: None,
        chaddr: p.get(28..34)?.try_into().ok()?,
    };
    let mut i = 240;
    while let Some(&code) = p.get(i) {
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = usize::from(*p.get(i + 1)?);
        let v = p.get(i + 2..i + 2 + len)?;
        let v4 = || -> Option<[u8; 4]> { v.get(..4)?.try_into().ok() };
        let u32v = || v4().map(u32::from_be_bytes);
        match code {
            53 => r.msg = *v.first()?,
            1 => r.mask = v4(),
            3 => r.router = v4(),
            6 => r.dns = v4(),
            54 => r.server = v4(),
            51 => r.lease = u32v(),
            58 => r.t1 = u32v(),
            59 => r.t2 = u32v(),
            _ => {}
        }
        i += 2 + len;
    }
    Some(r)
}

fn prefix_of(mask: Ip) -> u8 {
    u32::from_be_bytes(mask).leading_ones() as u8
}

impl Client {
    pub fn new(mac: Mac, xid: u32, now_ms: u64) -> Self {
        Self {
            mac,
            xid,
            state: State::Selecting,
            next_tx_ms: now_ms,
            retry_ms: RETRY_MS,
            lease: None,
            bound_at_ms: 0,
            t1_ms: 0,
            t2_ms: 0,
            expiry_ms: 0,
        }
    }

    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }

    fn message(&self, kind: u8, ciaddr: Ip, requested: Option<Ip>, server: Option<Ip>) -> Vec<u8> {
        let mut m = Vec::with_capacity(300);
        m.extend_from_slice(&[1, 1, 6, 0]);
        m.extend_from_slice(&self.xid.to_be_bytes());
        m.extend_from_slice(&[0, 0]);
        // Broadcast replies while we have no address.
        m.extend_from_slice(&(if ciaddr == [0; 4] { 0x8000u16 } else { 0 }).to_be_bytes());
        m.extend_from_slice(&ciaddr);
        m.extend_from_slice(&[0; 12]);
        m.extend_from_slice(&self.mac);
        m.extend_from_slice(&[0; 10 + 64 + 128]);
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(&[53, 1, kind]);
        if let Some(r) = requested {
            m.extend_from_slice(&[50, 4]);
            m.extend_from_slice(&r);
        }
        if let Some(s) = server {
            m.extend_from_slice(&[54, 4]);
            m.extend_from_slice(&s);
        }
        m.extend_from_slice(&[55, 4, 1, 3, 6, 51]);
        m.extend_from_slice(&[12, 6]);
        m.extend_from_slice(b"urmqtt");
        m.push(255);
        m
    }

    /// Whatever must be sent now (initial and retransmitted messages,
    /// renewals) and lease expiry.
    pub fn poll(&mut self, now_ms: u64) -> (Option<Send>, Option<Event>) {
        let mut event = None;
        if self.lease.is_some() && now_ms >= self.expiry_ms {
            self.lease = None;
            self.state = State::Selecting;
            self.next_tx_ms = now_ms;
            self.retry_ms = RETRY_MS;
            self.xid = self.xid.wrapping_add(1);
            event = Some(Event::Lost);
        }
        match self.state {
            State::Bound if now_ms >= self.t1_ms => {
                self.state = State::Renewing;
                self.next_tx_ms = now_ms;
            }
            State::Renewing if now_ms >= self.t2_ms => {
                self.state = State::Rebinding;
                self.next_tx_ms = now_ms;
            }
            _ => {}
        }
        if now_ms < self.next_tx_ms || self.state == State::Bound {
            return (None, event);
        }
        let ours = self.lease.map_or([0; 4], |l| l.addr);
        let send = match self.state {
            State::Selecting => Send {
                payload: self.message(DISCOVER, [0; 4], None, None),
                src: [0; 4],
                dst: [255; 4],
            },
            State::Requesting { offer, server } => Send {
                payload: self.message(REQUEST, [0; 4], Some(offer), Some(server)),
                src: [0; 4],
                dst: [255; 4],
            },
            // Renew and rebind broadcast too (simpler, RFC-compliant).
            State::Renewing | State::Rebinding => Send {
                payload: self.message(REQUEST, ours, None, None),
                src: ours,
                dst: [255; 4],
            },
            State::Bound => return (None, event),
        };
        self.next_tx_ms = now_ms + self.retry_ms;
        self.retry_ms = (self.retry_ms * 2).min(RETRY_MAX_MS);
        (Some(send), event)
    }

    /// Handles a UDP payload from port 67.
    pub fn input(&mut self, now_ms: u64, p: &[u8]) -> Option<Event> {
        let r = parse(p)?;
        if r.op != 2 || r.xid != self.xid || r.chaddr != self.mac {
            return None;
        }
        match (self.state, r.msg) {
            (State::Selecting, OFFER) => {
                let server = r.server?;
                self.state = State::Requesting {
                    offer: r.yiaddr,
                    server,
                };
                self.next_tx_ms = now_ms;
                self.retry_ms = RETRY_MS;
                None
            }
            (State::Requesting { .. } | State::Renewing | State::Rebinding, ACK) => {
                let lease_s = r.lease.unwrap_or(3600).max(60);
                let lease = Lease {
                    addr: r.yiaddr,
                    prefix: r.mask.map_or(24, prefix_of),
                    router: r.router,
                    dns: r.dns,
                    server: r.server.unwrap_or([0; 4]),
                    lease_s,
                };
                let renewed = self.lease.is_some();
                self.lease = Some(lease);
                self.state = State::Bound;
                self.bound_at_ms = now_ms;
                let ms = u64::from(lease_s) * 1000;
                self.t1_ms = now_ms + r.t1.map_or(ms / 2, |t| u64::from(t) * 1000);
                self.t2_ms = now_ms + r.t2.map_or(ms * 7 / 8, |t| u64::from(t) * 1000);
                self.expiry_ms = now_ms + ms;
                self.retry_ms = RETRY_MS;
                Some(if renewed {
                    Event::Renewed(lease)
                } else {
                    Event::Bound(lease)
                })
            }
            (State::Requesting { .. } | State::Renewing | State::Rebinding, NAK) => {
                let had = self.lease.take().is_some();
                self.state = State::Selecting;
                self.next_tx_ms = now_ms;
                self.retry_ms = RETRY_MS;
                self.xid = self.xid.wrapping_add(1);
                had.then_some(Event::Lost)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny DHCP server answering like QEMU's slirp.
    fn reply(req: &[u8], msg: u8, lease: u32) -> Vec<u8> {
        let mut m = req.to_vec();
        m.truncate(240);
        m[0] = 2;
        m[16..20].copy_from_slice(&[10, 0, 2, 15]);
        m.extend_from_slice(&[
            53, 1, msg, 54, 4, 10, 0, 2, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 6, 4, 10, 0,
            2, 3,
        ]);
        m.extend_from_slice(&[51, 4]);
        m.extend_from_slice(&lease.to_be_bytes());
        m.push(255);
        m
    }

    #[test]
    fn discover_request_bound_renew_expire() {
        let mut c = Client::new([2; 6], 77, 0);
        let (s, _) = c.poll(0);
        let s = s.unwrap();
        assert_eq!((s.src, s.dst), ([0; 4], [255; 4]));
        assert!(c.poll(1).0.is_none(), "retransmission waits");
        assert!(c.input(10, &reply(&s.payload, OFFER, 3600)).is_none());
        let req = c.poll(10).0.unwrap();
        let ev = c.input(20, &reply(&req.payload, ACK, 3600)).unwrap();
        let Event::Bound(l) = ev else {
            panic!("{ev:?}")
        };
        assert_eq!(
            (l.addr, l.prefix, l.router, l.dns),
            ([10, 0, 2, 15], 24, Some([10, 0, 2, 2]), Some([10, 0, 2, 3]))
        );
        // Renewal at T1 (half the lease).
        assert!(c.poll(1_000_000).0.is_none());
        let renew = c.poll(1_800_020).0.unwrap();
        assert_eq!(renew.src, [10, 0, 2, 15]);
        assert!(matches!(
            c.input(1_800_030, &reply(&renew.payload, ACK, 3600)),
            Some(Event::Renewed(_))
        ));
        // No answer at all: the lease expires and discovery restarts.
        let (_, ev) = c.poll(1_800_030 + 3_600_001);
        assert_eq!(ev, Some(Event::Lost));
        assert!(c.lease().is_none());
        // Foreign transaction ids and MACs are ignored.
        let s = c
            .poll(9_000_000)
            .0
            .unwrap_or_else(|| c.poll(99_000_000).0.unwrap());
        let mut other = reply(&s.payload, OFFER, 60);
        other[4] ^= 1;
        assert!(c.input(9_000_001, &other).is_none());
    }
}
