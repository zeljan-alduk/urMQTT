//! Network prototype on smoltcp (M7, PROMPT §5.1): DHCPv4, ARP, ICMP echo
//! and a TCP echo service on a dev-only port, all on the boot CPU with the
//! single virtio-net queue pair. Replaced by the own stack in M14.

use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, icmp, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
};
use urmqtt_arch_aarch64::{cpu, timer};
use urmqtt_log::{info, warn};
use urmqtt_virtio::net::{MTU_FRAME, VirtioNet};

use crate::devices::{self, KernelEnv};

/// TCP echo (RFC 862) port, dev builds only.
pub const ECHO_PORT: u16 = 7;
const ECHO_SOCKETS: usize = 4;
const ECHO_BUF: usize = 4096;
const PING_IDENT: u16 = 0x5155;
const PING_TIMEOUT_US: u64 = 2_000_000;

struct Phy {
    net: VirtioNet,
    rx: [u8; MTU_FRAME],
    tx: [u8; MTU_FRAME],
}

struct Rx<'a>(&'a [u8]);
struct Tx<'a> {
    net: &'a mut VirtioNet,
    buf: &'a mut [u8; MTU_FRAME],
}

impl phy::RxToken for Rx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let len = len.min(MTU_FRAME);
        let frame = self.buf.get_mut(..len).unwrap_or(&mut []);
        let r = f(frame);
        if let Err(e) = self.net.send(&KernelEnv, frame) {
            warn!("net: tx failed: {e:?}");
        }
        r
    }
}

impl phy::Device for Phy {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        let n = self.net.recv(&mut self.rx).ok().flatten()?;
        Some((
            Rx(self.rx.get(..n).unwrap_or(&[])),
            Tx {
                net: &mut self.net,
                buf: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Tx<'_>> {
        Some(Tx {
            net: &mut self.net,
            buf: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU_FRAME;
        caps.max_burst_size = Some(1);
        caps
    }
}

fn now() -> Instant {
    Instant::from_micros((timer::uptime_ns() / 1000) as i64)
}

struct Echo {
    handle: SocketHandle,
    served: u64,
}

/// Runs the network service on this CPU forever.
pub fn run(echo: bool) -> ! {
    let Some(net) = devices::DEVICES.lock().net.take() else {
        warn!("net: no network device, idling");
        loop {
            cpu::wfi();
        }
    };
    let mac = net.mac;
    let mut phy = Phy {
        net,
        rx: [0; MTU_FRAME],
        tx: [0; MTU_FRAME],
    };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = devices::RNG
        .lock()
        .as_mut()
        .map_or(0x5155_7155, urmqtt_tls::rng::Csprng::next_u64);
    let mut iface = Interface::new(config, &mut phy, now());
    let mut sockets = SocketSet::new(Vec::new());
    let dhcp = sockets.add(dhcpv4::Socket::new());

    let mut echoes: Vec<Echo> = Vec::new();
    if echo {
        for _ in 0..ECHO_SOCKETS {
            let s = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; ECHO_BUF]),
                tcp::SocketBuffer::new(vec![0; ECHO_BUF]),
            );
            echoes.push(Echo {
                handle: sockets.add(s),
                served: 0,
            });
        }
        info!("net: tcp echo service on port {ECHO_PORT} (dev only)");
    }
    let icmp = sockets.add(icmp::Socket::new(
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]),
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]),
    ));
    if sockets
        .get_mut::<icmp::Socket>(icmp)
        .bind(icmp::Endpoint::Ident(PING_IDENT))
        .is_err()
    {
        warn!("net: icmp bind failed");
    }

    let mut mqtt = Some(crate::mqtt_service::MqttService::new(&mut sockets));

    let mut router: Option<Ipv4Address> = None;
    let mut ping_sent: Option<Instant> = None;
    let mut ping_done = false;
    let mut buf = [0u8; ECHO_BUF];
    loop {
        let t = now();
        let activity = iface.poll(t, &mut phy, &mut sockets) != smoltcp::iface::PollResult::None;

        match sockets.get_mut::<dhcpv4::Socket>(dhcp).poll() {
            Some(dhcpv4::Event::Configured(c)) => {
                iface.update_ip_addrs(|a| {
                    a.clear();
                    let _ = a.push(IpCidr::Ipv4(c.address));
                });
                router = c.router;
                if let Some(r) = c.router {
                    let _ = iface.routes_mut().add_default_ipv4_route(r);
                } else {
                    iface.routes_mut().remove_default_ipv4_route();
                }
                info!(
                    "net: dhcp lease {} router {} dns {:?}",
                    c.address,
                    c.router.unwrap_or(Ipv4Address::UNSPECIFIED),
                    c.dns_servers.as_slice()
                );
            }
            Some(dhcpv4::Event::Deconfigured) => {
                // Also emitted once at start, before any lease.
                if iface.ipv4_addr().is_some() {
                    warn!("net: dhcp lease lost");
                }
                iface.update_ip_addrs(|a| a.clear());
                iface.routes_mut().remove_default_ipv4_route();
                router = None;
            }
            None => {}
        }

        // One ICMP echo to the router after the lease, as an IP-level check.
        if let (Some(r), None, false) = (router, ping_sent, ping_done) {
            let repr = Icmpv4Repr::EchoRequest {
                ident: PING_IDENT,
                seq_no: 1,
                data: b"urMQTT ping",
            };
            let sock = sockets.get_mut::<icmp::Socket>(icmp);
            if let Ok(out) = sock.send(repr.buffer_len(), IpAddress::Ipv4(r)) {
                let mut pkt = Icmpv4Packet::new_unchecked(out);
                repr.emit(&mut pkt, &ChecksumCapabilities::default());
                ping_sent = Some(t);
            }
        }
        if let (Some(sent), false) = (ping_sent, ping_done) {
            let sock = sockets.get_mut::<icmp::Socket>(icmp);
            if let Ok((payload, from)) = sock.recv() {
                let reply = Icmpv4Packet::new_checked(payload)
                    .ok()
                    .and_then(|p| Icmpv4Repr::parse(&p, &ChecksumCapabilities::default()).ok());
                if let Some(Icmpv4Repr::EchoReply {
                    ident: PING_IDENT, ..
                }) = reply
                {
                    info!(
                        "net: icmp echo reply from {from} in {} us",
                        (t - sent).total_micros()
                    );
                    ping_done = true;
                }
            } else if (t - sent).total_micros() > PING_TIMEOUT_US {
                warn!("net: no icmp echo reply from the router");
                ping_done = true;
            }
        }

        for e in &mut echoes {
            let s = sockets.get_mut::<tcp::Socket>(e.handle);
            if !s.is_open() {
                let _ = s.listen(ECHO_PORT);
            }
            if s.can_recv() && s.can_send() {
                let n = s.recv_slice(&mut buf).unwrap_or(0);
                if n > 0 {
                    let _ = s.send_slice(buf.get(..n).unwrap_or(&[]));
                    e.served += n as u64;
                }
            }
            // Peer finished sending and everything was echoed: close our side.
            if s.state() == tcp::State::CloseWait && s.send_queue() == 0 {
                info!("net: echo connection closed after {} byte(s)", e.served);
                e.served = 0;
                s.close();
            }
        }

        let mut activity = activity;
        if let Some(m) = mqtt.as_mut() {
            activity |= m.poll(&mut sockets, timer::uptime_ns() / 1_000_000);
            if activity {
                // Flush what the broker queued in this pass.
                iface.poll(now(), &mut phy, &mut sockets);
            }
        }

        if !activity {
            match iface.poll_delay(now(), &sockets) {
                Some(d) if d.total_micros() < 1000 => {}
                // No interrupt for RX (M7 polls): the 10 ms tick bounds the
                // wake-up latency.
                _ => cpu::wfi(),
            }
        }
    }
}
