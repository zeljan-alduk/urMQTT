//! Raw layer-2 transport over a QEMU `dgram` netdev and the three
//! TCP-exhaustion floods (SYN, ACK, RST). The tool is the guest's entire
//! network: it answers ARP and serves a fixed DHCP lease so the broker
//! comes up, then injects crafted segments and tallies what comes back.
//!
//! The expected outcome is checked in `scripts/smoke.sh` against the
//! kernel's own serial log (SYN cookies issued, no per-connection state,
//! flat memory, the challenge/RST rate cap); this side reports what it
//! sent and saw so a regression is visible from both ends.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::wire::{self, ACK, Ip, Mac, RST, SYN};

/// The gateway/DHCP-server address this tool owns (QEMU slirp's default, so
/// the dev configuration's syslog/statsd targets still resolve).
const HOST_IP: Ip = [10, 0, 2, 2];
const GUEST_IP: Ip = [10, 0, 2, 15];
const HOST_MAC: Mac = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const MASK: Ip = [255, 255, 255, 0];
/// Flood sources live on the guest's own /24 (10.0.2.50..229), so the guest
/// resolves each by ARP; the reader answers every in-subnet who-has with our
/// MAC, so the guest's replies come back to us to be counted.
const SRC_NET: Ip = [10, 0, 2, 0];
/// The guest's virtio-net MAC, fixed by `scripts/run-qemu.sh`.
const GUEST_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

pub struct Transport {
    sock: UdpSocket,
    /// Replies seen by the background reader, by TCP flag of interest.
    syn_acks: Arc<AtomicU64>,
    rsts: Arc<AtomicU64>,
    challenge_acks: Arc<AtomicU64>,
    leases: Arc<AtomicU64>,
    /// The MSS of the latest SYN-ACK, plus one (0: none seen).
    syn_ack_mss: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

/// A fixed DHCP reply (OFFER or ACK) built from the request, like QEMU's
/// slirp: yiaddr 10.0.2.15, mask /24, router/dns/server 10.0.2.2, and the
/// Interface MTU option (26) when `mtu` is set (NOW-19; slirp has none).
fn dhcp_reply(req: &[u8], msg_type: u8, mtu: Option<u16>) -> Option<Vec<u8>> {
    if req.len() < 240 || req.get(236..240) != Some(&[99, 130, 83, 99]) {
        return None;
    }
    let mut m = req[..240].to_vec();
    m[0] = 2; // BOOTREPLY
    m[16..20].copy_from_slice(&GUEST_IP); // yiaddr
    // siaddr: next server (us)
    m[20..24].copy_from_slice(&HOST_IP);
    m.extend_from_slice(&[53, 1, msg_type]);
    m.extend_from_slice(&[54, 4]);
    m.extend_from_slice(&HOST_IP); // server id
    m.extend_from_slice(&[51, 4, 0, 0, 14, 16]); // lease 3600 s
    m.extend_from_slice(&[1, 4]);
    m.extend_from_slice(&MASK);
    m.extend_from_slice(&[3, 4]);
    m.extend_from_slice(&HOST_IP); // router
    m.extend_from_slice(&[6, 4]);
    m.extend_from_slice(&HOST_IP); // dns
    if let Some(mtu) = mtu {
        m.extend_from_slice(&[26, 2]);
        m.extend_from_slice(&mtu.to_be_bytes());
    }
    m.push(255);
    Some(m)
}

impl Transport {
    /// Binds the datagram socket QEMU sends to and connects back to QEMU's
    /// local port, then starts the background reader that keeps the lease
    /// alive and tallies replies.
    pub fn bring_up(
        local: u16,
        remote: u16,
        timeout: Duration,
        dhcp_mtu: Option<u16>,
    ) -> Result<Self, String> {
        let sock = UdpSocket::bind(("127.0.0.1", remote)).map_err(|e| format!("bind: {e}"))?;
        sock.connect(("127.0.0.1", local))
            .map_err(|e| format!("connect: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let t = Transport {
            sock: sock.try_clone().map_err(|e| e.to_string())?,
            syn_acks: Arc::new(AtomicU64::new(0)),
            rsts: Arc::new(AtomicU64::new(0)),
            challenge_acks: Arc::new(AtomicU64::new(0)),
            leases: Arc::new(AtomicU64::new(0)),
            syn_ack_mss: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        t.spawn_reader(sock, dhcp_mtu);
        // The guest must have a lease (so the broker is reachable) before we
        // start; the reader records it and the guest MAC.
        let deadline = Instant::now() + timeout;
        while t.leases.load(Ordering::Relaxed) == 0 {
            if Instant::now() >= deadline {
                return Err("guest did not take a DHCP lease".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(t)
    }

    fn spawn_reader(&self, sock: UdpSocket, dhcp_mtu: Option<u16>) {
        let (syn_acks, rsts, chall, leases, stop) = (
            self.syn_acks.clone(),
            self.rsts.clone(),
            self.challenge_acks.clone(),
            self.leases.clone(),
            self.stop.clone(),
        );
        let mss_seen = self.syn_ack_mss.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::Relaxed) {
                let n = match sock.recv(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let Some(p) = wire::parse(&buf[..n]) else {
                    continue;
                };
                if let Some(a) = &p.arp {
                    // Claim the gateway and every flood source on the /24, so
                    // the guest's replies to a spoofed source reach us.
                    let ours = a.target_ip[..3] == SRC_NET[..3] && a.target_ip != GUEST_IP;
                    if a.is_request && ours {
                        let _ = sock.send(&wire::arp_reply(HOST_MAC, a.target_ip, a));
                    }
                    continue;
                }
                if p.proto == wire::PROTO_UDP && p.l4.1 == 67 {
                    // DHCP DISCOVER (1) → OFFER (2); REQUEST (3) → ACK (5).
                    let kind = p.payload.get(242).copied();
                    let reply = match kind {
                        Some(1) => dhcp_reply(&p.payload, 2, dhcp_mtu),
                        Some(3) => dhcp_reply(&p.payload, 5, dhcp_mtu),
                        _ => None,
                    };
                    if let Some(body) = reply {
                        let frame = wire::udp_frame(
                            HOST_MAC,
                            p.src_mac,
                            HOST_IP,
                            [255, 255, 255, 255],
                            67,
                            68,
                            &body,
                        );
                        let _ = sock.send(&frame);
                        if kind == Some(3) {
                            leases.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    continue;
                }
                if p.proto == wire::PROTO_TCP {
                    let flags = p.l4.4;
                    if flags & SYN != 0 && flags & ACK != 0 {
                        syn_acks.fetch_add(1, Ordering::Relaxed);
                        if let Some(m) = p.mss {
                            mss_seen.store(u64::from(m) + 1, Ordering::Relaxed);
                        }
                    } else if flags & RST != 0 {
                        rsts.fetch_add(1, Ordering::Relaxed);
                    } else if flags & ACK != 0 && p.payload.is_empty() {
                        chall.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    fn send(&self, frame: &[u8]) {
        let _ = self.sock.send(frame);
    }

    /// A flood of `count` segments to `port`, each with the given flags from
    /// a fresh off-subnet source and pseudo-random seq/ack/sport, paced to
    /// at most `pps` packets per second. Returns how many were sent.
    fn flood(&self, port: u16, flags: u8, mss: Option<u16>, count: u64, pps: u64) -> u64 {
        let gmac = GUEST_MAC;
        let mut rng = Rng::seeded();
        let start = Instant::now();
        for i in 0..count {
            let r = rng.next();
            let src_ip = [SRC_NET[0], SRC_NET[1], SRC_NET[2], 50 + (r as u8 % 180)];
            let sport = 1024 + (r >> 16) as u16 % 60000;
            let seq = rng.next();
            let ack = if flags & ACK != 0 { rng.next() } else { 0 };
            let frame = wire::tcp_frame(
                HOST_MAC,
                gmac,
                src_ip,
                GUEST_IP,
                sport,
                port,
                seq,
                ack,
                flags,
                64240,
                mss,
                &[],
            );
            self.send(&frame);
            if pps > 0 {
                let due = Duration::from_secs_f64((i + 1) as f64 / pps as f64);
                let elapsed = start.elapsed();
                if due > elapsed {
                    std::thread::sleep(due - elapsed);
                }
            }
        }
        count
    }

    pub fn syn_flood(&self, port: u16, count: u64, pps: u64) {
        let sent = self.flood(port, SYN, Some(1460), count, pps);
        // Let the last replies arrive.
        std::thread::sleep(Duration::from_millis(500));
        println!(
            "attack: syn-flood sent {sent} SYN(s) to :{port}, {} SYN-ACK(s) back",
            self.syn_acks.load(Ordering::Relaxed)
        );
    }

    pub fn ack_flood(&self, port: u16, count: u64, pps: u64) {
        let sent = self.flood(port, ACK, None, count, pps);
        std::thread::sleep(Duration::from_millis(500));
        println!(
            "attack: ack-flood sent {sent} ACK(s) to :{port}, {} RST(s) and {} challenge-ACK(s) back",
            self.rsts.load(Ordering::Relaxed),
            self.challenge_acks.load(Ordering::Relaxed)
        );
    }

    pub fn rst_flood(&self, port: u16, count: u64, pps: u64) {
        let sent = self.flood(port, RST, None, count, pps);
        std::thread::sleep(Duration::from_millis(500));
        println!(
            "attack: rst-flood sent {sent} RST(s) to :{port}, {} RST(s) back (expect 0)",
            self.rsts.load(Ordering::Relaxed)
        );
    }
}

impl Transport {
    /// NOW-19: one SYN announcing an MSS of 1460 (a peer on a 1500-byte
    /// network) from an on-link source; reports the MSS of the SYN-ACK, which
    /// must follow the MTU the guest uses (MTU - 40), not the peer's.
    pub fn mtu_probe(&self, port: u16) -> Result<(), String> {
        let frame = wire::tcp_frame(
            HOST_MAC,
            GUEST_MAC,
            [SRC_NET[0], SRC_NET[1], SRC_NET[2], 77],
            GUEST_IP,
            40_077,
            port,
            0x1234_5678,
            0,
            SYN,
            64240,
            Some(1460),
            &[],
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        // The broker may still be starting: send again until it answers.
        while self.syn_ack_mss.load(Ordering::Relaxed) == 0 {
            if Instant::now() >= deadline {
                return Err("mtu-probe: no SYN-ACK with an MSS".into());
            }
            self.send(&frame);
            std::thread::sleep(Duration::from_millis(500));
        }
        println!(
            "attack: mtu-probe: SYN mss 1460, SYN-ACK mss {}",
            self.syn_ack_mss.load(Ordering::Relaxed) - 1
        );
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A tiny xorshift64 PRNG: the floods need variety, not cryptographic
/// quality, and avoiding a `rand` dependency keeps the dev tool small.
struct Rng(u64);

impl Rng {
    fn seeded() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Rng(t | 1)
    }

    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 32) as u32
    }
}
