//! Per-core network loops on smoltcp (M7 prototype, multicore in M13,
//! ADR-032). Replaced by the own TCP stack in M14.
//!
//! Core 0 owns the single virtio-net queue pair. It steers TCP frames for
//! the MQTT ports to their flow's core (Toeplitz hash), copies ARP replies
//! to every core, keeps everything else (DHCP, ICMP, the dev echo service)
//! and transmits the frames the other cores send back. Every data core runs
//! its own smoltcp interface with the same addresses, its own sockets and
//! its MQTT service; core 0 publishes the DHCP lease to the others.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, icmp, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
    Ipv4Cidr,
};
use urmqtt_arch_aarch64::spsc::{Consumer, Producer};
use urmqtt_arch_aarch64::{cpu, timer};
use urmqtt_config::CONFIG;
use urmqtt_log::{info, warn};
use urmqtt_net::Class;
use urmqtt_virtio::net::{MTU_FRAME, VirtioNet};

use crate::dataplane::{
    self, CoreMsg, DROPPED_FRAMES, FRAME_RING, Frame, Link, POOL_MAX, new_frame,
};
use crate::db::Restored;
use crate::devices;
use crate::mqtt_service::MqttService;

/// TCP echo (RFC 862) port, dev builds only.
pub const ECHO_PORT: u16 = 7;
const ECHO_SOCKETS: usize = 4;
const ECHO_BUF: usize = 4096;
const PING_IDENT: u16 = 0x5155;
const PING_TIMEOUT_US: u64 = 2_000_000;
/// Frames taken from the NIC per pass.
const RX_BURST: usize = 64;
/// Messages taken from each peer per pass.
const MSG_BURST: usize = 256;

/// A received frame owned by a smoltcp RX token; returned to `done`.
struct RxOwned<'a> {
    frame: Frame,
    done: &'a mut Vec<Frame>,
}

impl phy::RxToken for RxOwned<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        let r = f(self.frame.data.get(..self.frame.len).unwrap_or(&[]));
        if self.done.len() < POOL_MAX {
            self.done.push(self.frame);
        }
        r
    }
}

/// Core 0: transmits straight to the NIC.
struct NicTx<'a> {
    net: &'a mut VirtioNet,
    buf: &'a mut [u8; MTU_FRAME],
}

impl phy::TxToken for NicTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let len = len.min(MTU_FRAME);
        let frame = self.buf.get_mut(..len).unwrap_or(&mut []);
        let r = f(frame);
        // Kicked once per loop pass (`VirtioNet::flush`); a full TX ring
        // drops the frame (TCP retransmits, `tx_full` counts it).
        let _ = self.net.queue(frame);
        r
    }
}

/// Other cores: hand the frame to core 0 over the ring.
struct RingTx<'a> {
    tx: &'a mut Producer<'static, Frame, FRAME_RING>,
    pool: &'a mut Vec<Frame>,
    /// A frame went to core 0 since the last wake-up.
    sent: &'a mut bool,
}

impl phy::TxToken for RingTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let len = len.min(MTU_FRAME);
        let mut frame = self.pool.pop().unwrap_or_else(new_frame);
        frame.len = len;
        let r = f(frame.data.get_mut(..len).unwrap_or(&mut []));
        if self.tx.push(frame).is_err() {
            // Ring full: TCP retransmits.
            DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        *self.sent = true;
        r
    }
}

fn caps() -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ethernet;
    caps.max_transmission_unit = MTU_FRAME;
    caps.max_burst_size = Some(1);
    caps
}

/// Core 0's device: frames the dispatcher kept for this core.
struct NicPhy {
    net: VirtioNet,
    local: VecDeque<Frame>,
    done: Vec<Frame>,
    tx: [u8; MTU_FRAME],
}

impl phy::Device for NicPhy {
    type RxToken<'a> = RxOwned<'a>;
    type TxToken<'a> = NicTx<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(RxOwned<'_>, NicTx<'_>)> {
        let frame = self.local.pop_front()?;
        Some((
            RxOwned {
                frame,
                done: &mut self.done,
            },
            NicTx {
                net: &mut self.net,
                buf: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _t: Instant) -> Option<NicTx<'_>> {
        Some(NicTx {
            net: &mut self.net,
            buf: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        caps()
    }
}

/// Other cores' device: frames from core 0, frames back to core 0.
struct RingPhy {
    rx: Consumer<'static, Frame, FRAME_RING>,
    tx: Producer<'static, Frame, FRAME_RING>,
    pool: Vec<Frame>,
    done: Vec<Frame>,
    sent: bool,
}

impl phy::Device for RingPhy {
    type RxToken<'a> = RxOwned<'a>;
    type TxToken<'a> = RingTx<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(RxOwned<'_>, RingTx<'_>)> {
        let frame = self.rx.pop()?;
        Some((
            RxOwned {
                frame,
                done: &mut self.done,
            },
            RingTx {
                tx: &mut self.tx,
                pool: &mut self.pool,
                sent: &mut self.sent,
            },
        ))
    }

    fn transmit(&mut self, _t: Instant) -> Option<RingTx<'_>> {
        Some(RingTx {
            tx: &mut self.tx,
            pool: &mut self.pool,
            sent: &mut self.sent,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        caps()
    }
}

fn now() -> Instant {
    Instant::from_micros((timer::uptime_ns() / 1000) as i64)
}

fn is_mqtt_port(port: u16) -> bool {
    port == CONFIG.network.mqtt_tls_port || CONFIG.network.mqtt_plain_port == Some(port)
}

/// Core 0: moves frames from the NIC to their cores and frames from the
/// cores to the NIC. Returns whether anything moved.
fn dispatch(phy: &mut NicPhy, link: &mut Link, pool: &mut Vec<Frame>) -> bool {
    let n = link.n;
    let mut moved = false;
    let mut steered = false;
    for _ in 0..RX_BURST {
        let mut f = pool.pop().unwrap_or_else(new_frame);
        match phy.net.recv(&mut f.data) {
            Ok(Some(len)) => f.len = len,
            _ => {
                pool.push(f);
                break;
            }
        }
        moved = true;
        dataplane::DISPATCHED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match urmqtt_net::classify(f.data.get(..f.len).unwrap_or(&[])) {
            Class::Tcp {
                src,
                dst,
                sport,
                dport,
            } if n > 1 && is_mqtt_port(dport) => {
                let core = dataplane::core_of_flow(src, dst, sport, dport, n);
                if core == 0 {
                    phy.local.push_back(f);
                } else if let Some(tx) = link.steer.get_mut(core).and_then(Option::as_mut) {
                    match tx.push(f) {
                        Ok(()) => steered = true,
                        Err(f) => {
                            DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                            pool.push(f);
                        }
                    }
                }
            }
            Class::Arp { reply: true } => {
                // Every core's neighbour cache needs it.
                for core in 1..n {
                    let mut copy = pool.pop().unwrap_or_else(new_frame);
                    copy.len = f.len;
                    copy.data[..f.len].copy_from_slice(&f.data[..f.len]);
                    if let Some(tx) = link.steer.get_mut(core).and_then(Option::as_mut) {
                        match tx.push(copy) {
                            Ok(()) => steered = true,
                            Err(c) => pool.push(c),
                        }
                    }
                }
                phy.local.push_back(f);
            }
            _ => phy.local.push_back(f),
        }
    }
    // Wake only the cores that got frames.
    if steered {
        for core in 1..n {
            dataplane::wake(core);
        }
    }
    for rx in link.collect.iter_mut().flatten() {
        while let Some(f) = rx.pop() {
            moved = true;
            dataplane::DISPATCHED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if phy.net.queue(f.data.get(..f.len).unwrap_or(&[])).is_err() {
                DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            if pool.len() < POOL_MAX {
                pool.push(f);
            }
        }
    }
    phy.net.flush();
    moved
}

struct Echo {
    handle: SocketHandle,
    served: u64,
}

fn new_iface<D: phy::Device>(mac: [u8; 6], dev: &mut D) -> Interface {
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = devices::RNG
        .lock()
        .as_mut()
        .map_or(0x5155_7155, urmqtt_tls::rng::Csprng::next_u64)
        ^ (dataplane_seed_salt() << 32);
    Interface::new(config, dev, now())
}

fn dataplane_seed_salt() -> u64 {
    crate::smp::current() as u64
}

fn apply_ip(iface: &mut Interface, cidr: Option<Ipv4Cidr>, router: Option<Ipv4Address>) {
    iface.update_ip_addrs(|a| {
        a.clear();
        if let Some(c) = cidr {
            let _ = a.push(IpCidr::Ipv4(c));
        }
    });
    match router {
        Some(r) => {
            let _ = iface.routes_mut().add_default_ipv4_route(r);
        }
        None => {
            iface.routes_mut().remove_default_ipv4_route();
        }
    }
}

/// Handles the mesh messages for this core; IP configuration goes to the
/// interface, the rest to the MQTT service.
fn drain_mesh(link: &mut Link, mqtt: &mut MqttService, iface: &mut Interface, now_ms: u64) -> bool {
    let mut any = false;
    for peer in 0..link.n {
        for _ in 0..MSG_BURST {
            let Some(m) = link.recv(peer) else { break };
            any = true;
            match m {
                CoreMsg::IpConfig { cidr, router } => apply_ip(iface, cidr, router),
                other => mqtt.on_msg(peer, other, link, now_ms),
            }
        }
    }
    any
}

/// Runs data core `me`'s network loop forever.
pub fn run(me: usize, echo: bool, restored: Option<Arc<Restored>>) -> ! {
    let Some(mut link) = Link::take(me) else {
        warn!("net: core {me} has no data-plane rings, idling");
        loop {
            cpu::wfi();
        }
    };
    if me == 0 {
        run_core0(link, echo, restored)
    } else {
        let (Some(rx), Some(tx)) = (link.frames_in.take(), link.frames_out.take()) else {
            warn!("net: core {me} has no frame rings, idling");
            loop {
                cpu::wfi();
            }
        };
        let mac = MAC
            .load(core::sync::atomic::Ordering::Acquire)
            .to_be_bytes();
        let mac = [mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]];
        let mut phy = RingPhy {
            rx,
            tx,
            pool: Vec::new(),
            done: Vec::new(),
            sent: false,
        };
        let mut idle = dataplane::Idle::new();
        let mut iface = new_iface(mac, &mut phy);
        let mut sockets = SocketSet::new(Vec::new());
        let mut mqtt = MqttService::new(&mut sockets, restored.as_deref(), me, link.n);
        loop {
            let now_ms = timer::uptime_ns() / 1_000_000;
            let mut activity = drain_mesh(&mut link, &mut mqtt, &mut iface, now_ms);
            activity |=
                iface.poll(now(), &mut phy, &mut sockets) != smoltcp::iface::PollResult::None;
            activity |= mqtt.poll(&mut sockets, &mut link, now_ms);
            if activity {
                iface.poll(now(), &mut phy, &mut sockets);
            }
            phy.pool.append(&mut phy.done);
            phy.pool.truncate(POOL_MAX);
            if core::mem::take(&mut phy.sent) {
                dataplane::wake(0);
            }
            idle.pass(activity, || link.pending() || !phy.rx.is_empty());
        }
    }
}

/// The NIC's MAC for the other cores' interfaces (set by core 0).
static MAC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// State handed from the boot CPU to the other data cores.
static RESTORED: urmqtt_arch_aarch64::sync::SpinLock<Option<Arc<Restored>>> =
    urmqtt_arch_aarch64::sync::SpinLock::new(None);

/// Boot CPU, before the other data cores start: takes the NIC (core 0
/// owns it) and publishes the restored broker state for every shard.
pub fn prepare(restored: Option<Arc<Restored>>) {
    *RESTORED.lock() = restored;
    let Some(net) = devices::DEVICES.lock().net.take() else {
        return;
    };
    let m = net.mac;
    let packed = u64::from_be_bytes([0, 0, m[0], m[1], m[2], m[3], m[4], m[5]]);
    // Release: read by the other data cores when they start.
    MAC.store(packed, core::sync::atomic::Ordering::Release);
    *NIC.lock() = Some(net);
}

/// The restored state for core 0 (also kept for the other cores).
pub fn take_restored() -> Option<Arc<Restored>> {
    RESTORED.lock().clone()
}

/// Entry for data cores other than 0 (an SMP work item).
pub fn run_ap(me: usize) -> ! {
    let restored = RESTORED.lock().clone();
    run(me, false, restored)
}

static NIC: urmqtt_arch_aarch64::sync::SpinLock<Option<VirtioNet>> =
    urmqtt_arch_aarch64::sync::SpinLock::new(None);

fn run_core0(mut link: Link, echo: bool, restored: Option<Arc<Restored>>) -> ! {
    let Some(net) = NIC.lock().take() else {
        warn!("net: no network device, idling");
        loop {
            cpu::wfi();
        }
    };
    let mac = net.mac;
    let n = link.n;
    let mut phy = NicPhy {
        net,
        local: VecDeque::new(),
        done: Vec::new(),
        tx: [0; MTU_FRAME],
    };
    let mut pool: Vec<Frame> = Vec::new();
    if n > 1 {
        info!(
            "net: dispatcher mode: core 0 owns the single virtio-net queue pair and steers MQTT flows to {} worker core(s) (Toeplitz hash)",
            n - 1
        );
    }
    let mut iface = new_iface(mac, &mut phy);
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

    let mut mqtt = MqttService::new(&mut sockets, restored.as_deref(), 0, n);

    let mut idle = dataplane::Idle::new();
    let mut router: Option<Ipv4Address> = None;
    let mut ping_sent: Option<Instant> = None;
    let mut ping_done = false;
    let mut buf = [0u8; ECHO_BUF];
    loop {
        let t = now();
        let now_ms = timer::uptime_ns() / 1_000_000;
        let mut activity = dispatch(&mut phy, &mut link, &mut pool);
        activity |= drain_mesh(&mut link, &mut mqtt, &mut iface, now_ms);
        activity |= iface.poll(t, &mut phy, &mut sockets) != smoltcp::iface::PollResult::None;

        let lease = match sockets.get_mut::<dhcpv4::Socket>(dhcp).poll() {
            Some(dhcpv4::Event::Configured(c)) => {
                router = c.router;
                info!(
                    "net: dhcp lease {} router {} dns {:?}",
                    c.address,
                    c.router.unwrap_or(Ipv4Address::UNSPECIFIED),
                    c.dns_servers.as_slice()
                );
                Some((Some(c.address), c.router))
            }
            Some(dhcpv4::Event::Deconfigured) => {
                // Also emitted once at start, before any lease.
                if iface.ipv4_addr().is_some() {
                    warn!("net: dhcp lease lost");
                }
                router = None;
                Some((None, None))
            }
            None => None,
        };
        if let Some((cidr, r)) = lease {
            apply_ip(&mut iface, cidr, r);
            for core in 1..n {
                link.send(core, CoreMsg::IpConfig { cidr, router: r });
            }
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

        // One CPU: the DB worker runs here between iterations.
        crate::db::poll();
        activity |= mqtt.poll(&mut sockets, &mut link, now_ms);
        if activity {
            // Flush what the broker queued in this pass.
            iface.poll(now(), &mut phy, &mut sockets);
        }
        phy.net.flush();
        pool.append(&mut phy.done);
        pool.truncate(POOL_MAX);

        // The NIC is polled: while idle, the 10 ms tick bounds the receive
        // latency of the first packet; other cores wake us for their frames.
        let soon = iface
            .poll_delay(now(), &sockets)
            .is_some_and(|d| d.total_micros() < 1000);
        idle.pass(activity || soon, || {
            link.pending() || phy.net.rx_pending() || !phy.local.is_empty()
        });
    }
}
