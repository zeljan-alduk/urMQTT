//! Per-core network loops on the own stack (M14, ADR-033; multicore since
//! M13, ADR-032).
//!
//! Core 0 owns the single virtio-net queue pair. It steers TCP frames for
//! the MQTT ports to their flow's worker core (Toeplitz hash) and keeps
//! everything else: ARP, ICMP echo, DHCP and the dev echo port. It also
//! transmits the frames the workers send back. Every data core runs its
//! own `urmqtt-net` interface and `urmqtt-tcp` stack with the same
//! addresses; core 0 publishes the DHCP lease to the others.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use urmqtt_arch::{cpu, time};
use urmqtt_config::{CONFIG, NetworkMode};
use urmqtt_log::{info, warn};
use urmqtt_net::Class;
use urmqtt_net::dhcp;
use urmqtt_net::iface::{Event, Iface, Rx};
use urmqtt_tcp::{App, CloseReason, ConnId, Endpoint, TcpStack};
use urmqtt_virtio::net::{MTU_FRAME, VirtioNet};

use crate::dataplane::{self, CoreMsg, DROPPED_FRAMES, Frame, Link, POOL_MAX, new_frame};
use crate::db::Restored;
use crate::devices;
use crate::mqtt_service::{MAX_CONNS, MqttService, TcpEvents};

/// TCP echo (RFC 862) port, dev builds only.
pub const ECHO_PORT: u16 = 7;
const PING_IDENT: u16 = 0x5155;
const PING_TIMEOUT_MS: u64 = 2_000;
/// Frames taken from the NIC per pass.
const RX_BURST: usize = 64;
/// Messages taken from each peer per pass.
const MSG_BURST: usize = 256;

fn now_ms() -> u64 {
    time::uptime_ns() / 1_000_000
}

fn is_mqtt_port(port: u16) -> bool {
    port == CONFIG.network.mqtt_tls_port || CONFIG.network.mqtt_plain_port == Some(port)
}

fn ip_str(a: [u8; 4]) -> alloc::string::String {
    alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn new_tcp(addr: [u8; 4], ports: Vec<u16>) -> TcpStack {
    let mut key = [0u8; 16];
    // Fail closed (H0-W6): a zero cookie key would make ISNs predictable.
    // Boot refuses to get here without a generator, so this never fires.
    if urmqtt_tls::rng::fill_global(&mut key).is_err() {
        crate::boot::fatal("tcp: no random generator for the SYN-cookie key");
    }
    TcpStack::new(
        urmqtt_tcp::Config {
            local_addr: addr,
            ports,
            mss: 1460,
            rcv_wnd: 65535,
            max_conns: MAX_CONNS,
            tx_max: 64 * 1024,
            cookie_key: key,
            rst_per_sec: 200,
        },
        now_ms(),
    )
}

/// The SYN-cookie key is replaced every 10 minutes (H3, H0-W3); the old one
/// still validates the cookies it issued for their lifetime (128 s).
const COOKIE_ROTATE_MS: u64 = 600_000;

struct CookieRotation {
    next_ms: u64,
}

impl CookieRotation {
    fn new(now: u64) -> Self {
        Self {
            next_ms: now + COOKIE_ROTATE_MS,
        }
    }

    fn tick(&mut self, tcp: &mut TcpStack, now: u64) {
        if now < self.next_ms {
            return;
        }
        self.next_ms = now + COOKIE_ROTATE_MS;
        let mut key = [0u8; 16];
        // Fail closed as at boot: never a predictable key.
        if urmqtt_tls::rng::fill_global(&mut key).is_err() {
            crate::boot::fatal("tcp: no random generator for the SYN-cookie key");
        }
        tcp.rotate_cookie_key(key, now);
    }
}

/// The dev echo service (RFC 862) on core 0.
#[derive(Default)]
struct EchoSvc {
    /// Per connection: bytes to echo, bytes served, peer closed.
    conns: BTreeMap<ConnId, (Vec<u8>, u64, bool)>,
}

impl EchoSvc {
    fn pump(&mut self, tcp: &mut TcpStack) {
        for (&c, (pending, _, peer_closed)) in self.conns.iter_mut() {
            if !pending.is_empty() {
                let n = tcp.send(c, pending);
                pending.drain(..n);
            }
            if *peer_closed && pending.is_empty() {
                tcp.close(c);
            }
        }
    }
}

/// Core 0's TCP application: the echo port, then MQTT.
struct CoreApp<'a> {
    mqtt: TcpEvents<'a>,
    echo: Option<&'a mut EchoSvc>,
}

impl App for CoreApp<'_> {
    fn accept(&mut self, c: ConnId, port: u16, remote: Endpoint) -> bool {
        if port == ECHO_PORT
            && let Some(e) = self.echo.as_mut()
        {
            e.conns.insert(c, (Vec::new(), 0, false));
            return true;
        }
        self.mqtt.accept(c, port, remote)
    }

    fn data(&mut self, c: ConnId, data: &[u8]) {
        if let Some((p, served, _)) = self.echo.as_mut().and_then(|e| e.conns.get_mut(&c)) {
            p.extend_from_slice(data);
            *served += data.len() as u64;
            return;
        }
        self.mqtt.data(c, data);
    }

    fn peer_closed(&mut self, c: ConnId) {
        if let Some((_, _, closed)) = self.echo.as_mut().and_then(|e| e.conns.get_mut(&c)) {
            *closed = true;
            return;
        }
        self.mqtt.peer_closed(c);
    }

    fn closed(&mut self, c: ConnId, why: CloseReason) {
        if let Some((_, served, _)) = self.echo.as_mut().and_then(|e| e.conns.remove(&c)) {
            info!("net: echo connection closed after {served} byte(s)");
            return;
        }
        self.mqtt.closed(c, why);
    }
}

/// Handles the mesh messages for this core; IP configuration goes to the
/// interface and the TCP stack, the rest to the MQTT service.
fn drain_mesh(
    link: &mut Link,
    mqtt: &mut MqttService,
    iface: &mut Iface,
    tcp: &mut TcpStack,
    now: u64,
) -> bool {
    let mut any = false;
    for peer in 0..link.n {
        for _ in 0..MSG_BURST {
            let Some(m) = link.recv(peer) else { break };
            any = true;
            match m {
                CoreMsg::IpConfig { addr, router } => {
                    iface.set_addr(addr, router);
                    tcp.set_local_addr(addr.map_or([0; 4], |a| a.0));
                }
                other => mqtt.on_msg(peer, other, link, now),
            }
        }
    }
    any
}

/// The NIC's MAC for the other cores' interfaces (set by core 0).
static MAC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// State handed from the boot CPU to the other data cores.
static RESTORED: urmqtt_sync::sync::SpinLock<Option<Arc<Restored>>> =
    urmqtt_sync::sync::SpinLock::new(None);
static NIC: urmqtt_sync::sync::SpinLock<Option<VirtioNet>> = urmqtt_sync::sync::SpinLock::new(None);

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

fn mac() -> [u8; 6] {
    // Acquire: pairs with the Release in `prepare`.
    let m = MAC
        .load(core::sync::atomic::Ordering::Acquire)
        .to_be_bytes();
    [m[2], m[3], m[4], m[5], m[6], m[7]]
}

/// Runs data core `me`'s network loop forever.
pub fn run(me: usize, echo: bool, restored: Option<Arc<Restored>>) -> ! {
    let Some(link) = Link::take(me) else {
        warn!("net: core {me} has no data-plane rings, idling");
        loop {
            cpu::wait_for_interrupt();
        }
    };
    if me == 0 {
        run_core0(link, echo, restored)
    } else {
        run_worker(me, link, restored)
    }
}

fn run_worker(me: usize, mut link: Link, restored: Option<Arc<Restored>>) -> ! {
    let (Some(mut rx), Some(mut tx)) = (link.frames_in.take(), link.frames_out.take()) else {
        warn!("net: core {me} has no frame rings, idling");
        loop {
            cpu::wait_for_interrupt();
        }
    };
    let mut iface = Iface::new(mac(), false, None, now_ms());
    let mut mqtt = MqttService::new(restored.as_deref(), me, link.n);
    let mut tcp = new_tcp([0; 4], mqtt.ports());
    let mut pool: Vec<Frame> = Vec::new();
    let mut idle = dataplane::Idle::new();
    let mut cookies = CookieRotation::new(now_ms());
    loop {
        let now = now_ms();
        cookies.tick(&mut tcp, now);
        let mut activity = drain_mesh(&mut link, &mut mqtt, &mut iface, &mut tcp, now);
        let mut sent = false;
        let mut done: Vec<Frame> = Vec::new();
        {
            let mut emit = |f: &[u8]| {
                let mut frame = pool.pop().unwrap_or_else(new_frame);
                let n = f.len().min(MTU_FRAME);
                frame.len = n;
                if let (Some(d), Some(s)) = (frame.data.get_mut(..n), f.get(..n)) {
                    d.copy_from_slice(s);
                }
                if tx.push(frame).is_err() {
                    DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                sent = true;
            };
            for _ in 0..RX_BURST {
                let Some(f) = rx.pop() else { break };
                activity = true;
                if let Rx::Tcp { src, seg } =
                    iface.receive(now, f.data.get(..f.len).unwrap_or(&[]), &mut emit)
                {
                    let mut app = TcpEvents {
                        mqtt: &mut mqtt,
                        link: &mut link,
                        now_ms: now,
                    };
                    tcp.input(now, src, seg, &mut app, &mut |dst, s| {
                        iface.send_tcp(dst, s, &mut emit)
                    });
                }
                done.push(f);
            }
            activity |= mqtt.poll(&mut tcp, &mut link, now);
            for c in mqtt.take_aborts() {
                tcp.abort(c, &mut |dst, s| iface.send_tcp(dst, s, &mut emit));
            }
            {
                let mut app = TcpEvents {
                    mqtt: &mut mqtt,
                    link: &mut link,
                    now_ms: now,
                };
                tcp.poll(now, &mut app, &mut |dst, s| {
                    iface.send_tcp(dst, s, &mut emit)
                });
            }
            tcp.flush(now, &mut |dst, s| iface.send_tcp(dst, s, &mut emit));
        }
        link.flush();
        pool.append(&mut done);
        pool.truncate(POOL_MAX);
        if let Some(c) = dataplane::CONNECTIONS.get(me) {
            // Relaxed: statistics.
            c.store(
                tcp.connections() as u64,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        if sent {
            dataplane::wake(0);
        }
        idle.pass(activity || sent || tcp.has_pending(), || {
            link.pending() || !rx.is_empty()
        });
    }
}

/// Core 0: moves frames from the NIC to their cores (or keeps them) and
/// frames from the cores to the NIC.
fn dispatch(
    net: &mut VirtioNet,
    link: &mut Link,
    pool: &mut Vec<Frame>,
    local: &mut VecDeque<Frame>,
) -> bool {
    let n = link.n;
    let mut moved = false;
    let mut steered = false;
    for _ in 0..RX_BURST {
        let mut f = pool.pop().unwrap_or_else(new_frame);
        match net.recv(&mut f.data) {
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
                    local.push_back(f);
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
            _ => local.push_back(f),
        }
    }
    if steered {
        for core in 1..n {
            dataplane::wake(core);
        }
    }
    for rx in link.collect.iter_mut().flatten() {
        while let Some(f) = rx.pop() {
            moved = true;
            dataplane::DISPATCHED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if net.queue(f.data.get(..f.len).unwrap_or(&[])).is_err() {
                DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            if pool.len() < POOL_MAX {
                pool.push(f);
            }
        }
    }
    net.flush();
    moved
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ping {
    Waiting,
    Resolving { since: u64 },
    Sent { at: u64 },
    Done,
}

fn run_core0(mut link: Link, echo: bool, restored: Option<Arc<Restored>>) -> ! {
    let Some(mut net) = NIC.lock().take() else {
        // urMQTT drives virtio-net only (no SR-IOV/VFIO NICs): say exactly
        // what is there and what to change.
        for &(v, d) in crate::devices::OTHER_NICS.lock().iter() {
            urmqtt_log::error!(
                "net: network controller {v:04x}:{d:04x} ({}) has no driver; urMQTT needs virtio-net",
                crate::devices::nic_vendor(v)
            );
        }
        let hint = "net: no virtio-net NIC. Attach one (QEMU/KVM: virtio-net-pci; Oracle Cloud: import the \
                    image with launch mode PARAVIRTUALIZED; Hetzner: the default NIC)";
        if urmqtt_config::CONFIG.env == "dev" {
            warn!("{hint}; idling (dev)");
            loop {
                cpu::wait_for_interrupt();
            }
        }
        crate::boot::fatal(hint);
    };
    let n = link.n;
    let mac = net.mac;
    if n > 1 {
        info!(
            "net: dispatcher mode: core 0 owns the single virtio-net queue pair and steers MQTT flows to {} worker core(s) (Toeplitz hash)",
            n - 1
        );
    }
    let mut xid = [0u8; 4];
    // Fail closed (H0-W6), as for the cookie key.
    if urmqtt_tls::rng::fill_global(&mut xid).is_err() {
        crate::boot::fatal("dhcp: no random generator for the transaction id");
    }
    let mut iface = match CONFIG.network.mode {
        NetworkMode::Dhcp => Iface::new(mac, true, Some(u32::from_be_bytes(xid)), now_ms()),
        NetworkMode::Static { address, gateway } => {
            let mut i = Iface::new(mac, true, None, now_ms());
            i.set_addr(Some((address.addr, address.prefix_len)), Some(gateway));
            info!(
                "net: static address {}/{} gateway {}",
                ip_str(address.addr),
                address.prefix_len,
                ip_str(gateway)
            );
            for core in 1..n {
                link.send(
                    core,
                    CoreMsg::IpConfig {
                        addr: Some((address.addr, address.prefix_len)),
                        router: Some(gateway),
                    },
                );
            }
            i
        }
    };
    let mut mqtt = MqttService::new(restored.as_deref(), 0, n);
    let mut ports = if n == 1 { mqtt.ports() } else { Vec::new() };
    let mut echo_svc = echo.then(EchoSvc::default);
    if echo_svc.is_some() {
        ports.push(ECHO_PORT);
        info!("net: tcp echo service on port {ECHO_PORT} (dev only)");
    }
    let mut tcp = new_tcp(iface.addr().unwrap_or([0; 4]), ports);
    let mut pool: Vec<Frame> = Vec::new();
    let mut local: VecDeque<Frame> = VecDeque::new();
    let mut ping = Ping::Waiting;
    let mut idle = dataplane::Idle::new();
    let (mut mem_last, mut mem_conns) = (now_ms(), 0u64);
    dataplane::set_baseline();
    let mut ops = crate::ops::Ops::new(now_ms());
    let mut cookies = CookieRotation::new(now_ms());
    loop {
        let now = now_ms();
        cookies.tick(&mut tcp, now);
        if let Some(c) = dataplane::CONNECTIONS.first() {
            // Relaxed: statistics.
            c.store(
                tcp.connections() as u64,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        dataplane::mem_report(now, &mut mem_last, &mut mem_conns);
        let mut activity = dispatch(&mut net, &mut link, &mut pool, &mut local);
        activity |= drain_mesh(&mut link, &mut mqtt, &mut iface, &mut tcp, now);
        let mut events: Vec<Event> = Vec::new();
        {
            let mut emit = |f: &[u8]| {
                if net.queue(f).is_err() {
                    DROPPED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            };
            while let Some(f) = local.pop_front() {
                activity = true;
                match iface.receive(now, f.data.get(..f.len).unwrap_or(&[]), &mut emit) {
                    Rx::Tcp { src, seg } => {
                        let mut app = CoreApp {
                            mqtt: TcpEvents {
                                mqtt: &mut mqtt,
                                link: &mut link,
                                now_ms: now,
                            },
                            echo: echo_svc.as_mut(),
                        };
                        tcp.input(now, src, seg, &mut app, &mut |dst, s| {
                            iface.send_tcp(dst, s, &mut emit)
                        });
                    }
                    Rx::Event(e) => events.push(e),
                    Rx::None => {}
                }
                if pool.len() < POOL_MAX {
                    pool.push(f);
                }
            }
            if let Some(e) = iface.poll(now, &mut emit) {
                events.push(e);
            }
            ops.poll(&mut iface, now, &mut emit);
            for e in events {
                match e {
                    Event::Dhcp(dhcp::Event::Bound(l) | dhcp::Event::Renewed(l)) => {
                        info!(
                            "net: dhcp lease {}/{} router {} dns [{}]",
                            ip_str(l.addr),
                            l.prefix,
                            l.router.map_or_else(|| "none".into(), ip_str),
                            l.dns.map_or_else(alloc::string::String::new, ip_str)
                        );
                        tcp.set_local_addr(l.addr);
                        for core in 1..n {
                            link.send(
                                core,
                                CoreMsg::IpConfig {
                                    addr: Some((l.addr, l.prefix)),
                                    router: l.router,
                                },
                            );
                        }
                        if ping == Ping::Waiting
                            && let Some(r) = l.router
                        {
                            iface.resolve(r, &mut emit);
                            ping = Ping::Resolving { since: now };
                        }
                    }
                    Event::Dhcp(dhcp::Event::Lost) => {
                        warn!("net: dhcp lease lost");
                        tcp.set_local_addr([0; 4]);
                        for core in 1..n {
                            link.send(
                                core,
                                CoreMsg::IpConfig {
                                    addr: None,
                                    router: None,
                                },
                            );
                        }
                    }
                    Event::PingReply { from, rtt_ms } => {
                        info!(
                            "net: icmp echo reply from {} in {} us",
                            ip_str(from),
                            rtt_ms * 1000
                        );
                        ping = Ping::Done;
                    }
                }
            }
            // One ICMP echo to the router after the lease, as an IP-level check.
            match ping {
                Ping::Resolving { since } => {
                    if let Some(r) = iface.router()
                        && iface.ping(now, r, PING_IDENT, &mut emit)
                    {
                        ping = Ping::Sent { at: now };
                    } else if now.saturating_sub(since) > PING_TIMEOUT_MS {
                        warn!("net: router did not answer ARP");
                        ping = Ping::Done;
                    }
                }
                Ping::Sent { at } if now.saturating_sub(at) > PING_TIMEOUT_MS => {
                    warn!("net: no icmp echo reply from the router");
                    ping = Ping::Done;
                }
                _ => {}
            }

            // One CPU: the DB worker runs here between iterations.
            crate::db::poll();
            if let Some(e) = echo_svc.as_mut() {
                e.pump(&mut tcp);
            }
            activity |= mqtt.poll(&mut tcp, &mut link, now);
            for c in mqtt.take_aborts() {
                tcp.abort(c, &mut |dst, s| iface.send_tcp(dst, s, &mut emit));
            }
            {
                let mut app = CoreApp {
                    mqtt: TcpEvents {
                        mqtt: &mut mqtt,
                        link: &mut link,
                        now_ms: now,
                    },
                    echo: echo_svc.as_mut(),
                };
                tcp.poll(now, &mut app, &mut |dst, s| {
                    iface.send_tcp(dst, s, &mut emit)
                });
            }
            tcp.flush(now, &mut |dst, s| iface.send_tcp(dst, s, &mut emit));
        }
        link.flush();
        net.flush();
        // The NIC is polled: while idle, the 10 ms tick bounds the receive
        // latency of the first packet; other cores wake us for their frames.
        let busy = activity
            || tcp.has_pending()
            || matches!(ping, Ping::Resolving { .. } | Ping::Sent { .. });
        idle.pass(busy, || {
            link.pending() || net.rx_pending() || !local.is_empty()
        });
    }
}
