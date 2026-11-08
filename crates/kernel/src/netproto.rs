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
use urmqtt_tcp::{App, CloseReason, ConnId, Endpoint, TcpStack, mss_for_mtu};
use urmqtt_virtio::net::{MTU_FRAME, VirtioNet};
use urmqtt_virtio::wake::{Change, Mode, RxWake, Why};

use crate::dataplane::{self, CoreMsg, DropSite, Frame, Link, POOL_MAX, new_frame};
use crate::db::Restored;
use crate::devices;
use crate::mqtt_service::{MAX_CONNS, MqttService, TcpEvents};

/// TCP echo (RFC 862) port, dev builds only.
pub const ECHO_PORT: u16 = 7;
const PING_IDENT: u16 = 0x5155;
const PING_TIMEOUT_MS: u64 = 2_000;
/// Frames taken from the NIC per pass.
const RX_BURST: usize = 64;
/// Frames core 0 holds for a full NIC transmit queue before it stops taking
/// them from the workers (ADR-223).
const NIC_BACKLOG: usize = 4096;
/// Spare frame buffers a core keeps once it has been quiet for `POOL_IDLE_MS`
/// (a busy core keeps up to `POOL_MAX`): the pools do not hold megabytes of
/// heap on an idle broker (M16).
const POOL_IDLE: usize = 32;
/// How often the dispatcher polls the NIC while it sleeps and connections exist.
const NIC_POLL_NS: u64 = 200_000;
const POOL_IDLE_MS: u64 = 1_000;

/// What the NIC's MSI-X message targets (ADR-270's boot line): an LPI of
/// the GICv3 ITS (8192 and up) or a GICv2m SPI; a local APIC vector on x86.
#[cfg(target_arch = "aarch64")]
fn msi_name(intid: u32) -> &'static str {
    if intid >= 8192 {
        "GICv3 ITS LPI"
    } else {
        "GICv2m SPI"
    }
}
#[cfg(target_arch = "x86_64")]
fn msi_name(_intid: u32) -> &'static str {
    "local APIC vector"
}
/// Messages taken from each peer per pass.
const MSG_BURST: usize = 256;
/// A serving dispatcher handles frames for its own connections this long
/// (ns) before it looks at the NIC again (`cpu.dispatcher_serves`).
const LOCAL_SLICE_NS: u64 = 200_000;

fn now_ms() -> u64 {
    time::uptime_ns() / 1_000_000
}

fn is_mqtt_port(port: u16) -> bool {
    (CONFIG.network.mqtt_tls_port != 0 && port == CONFIG.network.mqtt_tls_port)
        || CONFIG.network.mqtt_plain_port == Some(port)
        || crate::plain::port() == Some(port)
        || crate::websocket::port() == Some(port)
}

fn ip_str(a: [u8; 4]) -> alloc::string::String {
    alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn new_tcp(addr: [u8; 4], ports: Vec<u16>, mtu: u16) -> TcpStack {
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
            // NOW-19: MTU - 40, at most 1460 (ADR-264).
            mss: mss_for_mtu(mtu),
            rcv_wnd: 65535,
            // 1 MiB with window scaling (shift 5) for peers that offer it
            // (ADR-222): a window must cover the bandwidth-delay product.
            rcv_wnd_scaled: 1 << 20,
            max_conns: MAX_CONNS,
            tx_max: 64 * 1024,
            tx_cap: 1 << 20,
            ooo_budget: 16 << 20,
            ooo_conn_max: 1 << 20,
            cookie_key: key,
            rst_per_sec: 200,
        },
        now_ms(),
    )
}

/// Where the MTU in use came from (NOW-19, ADR-264).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MtuSource {
    /// 1500: neither `network.mtu` nor DHCP option 26 said otherwise.
    Default,
    /// `network.mtu` (the only source with a static address; it also wins
    /// over what DHCP announces).
    Static,
    /// DHCP option 26.
    Dhcp,
}

impl MtuSource {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Static => "static",
            Self::Dhcp => "dhcp",
        }
    }
}

/// The MTU in use (low 16 bits) and its source (the next 8), for `$SYS` and
/// the info query; set by core 0. Relaxed: a statistic.
static MTU_IN_USE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(urmqtt_net::iface::DEFAULT_MTU as u32);

/// The link MTU the network path uses now, and where it came from.
pub fn mtu() -> (u16, MtuSource) {
    let v = MTU_IN_USE.load(core::sync::atomic::Ordering::Relaxed);
    let src = match v >> 16 {
        1 => MtuSource::Static,
        2 => MtuSource::Dhcp,
        _ => MtuSource::Default,
    };
    (v as u16, src)
}

/// `network.mtu` when set (the check refused anything outside 576..=9000).
fn configured_mtu() -> Option<u16> {
    CONFIG.network.mtu
}

/// The MTU to use: `network.mtu`, else what the lease announced (when sane),
/// else 1500, and its source.
fn choose_mtu(lease: Option<&dhcp::Lease>) -> (u16, MtuSource) {
    if let Some(m) = configured_mtu() {
        return (m, MtuSource::Static);
    }
    match lease.and_then(dhcp::Lease::mtu) {
        Some(m) => (m, MtuSource::Dhcp),
        None => (urmqtt_net::iface::DEFAULT_MTU, MtuSource::Default),
    }
}

/// Applies an MTU on core 0 (interface and TCP stack), logs it when it
/// changed, and returns the value in use (at most what the driver sends).
fn apply_mtu(
    iface: &mut Iface,
    tcp: &mut TcpStack,
    chosen: (u16, MtuSource),
    lease: Option<&dhcp::Lease>,
) -> u16 {
    let (want, src) = chosen;
    if let Some(l) = lease {
        match l.mtu_announced {
            Some(m) if l.mtu().is_none() => warn!(
                "net: dhcp announced mtu {m}, outside {}..={}: ignored",
                dhcp::MTU_MIN,
                dhcp::MTU_MAX
            ),
            Some(m) if src == MtuSource::Static && m != want => {
                info!("net: dhcp announced mtu {m}; network.mtu = {want} is used");
            }
            _ => {}
        }
    }
    let before = mtu();
    let used = iface.set_mtu(want);
    tcp.set_mss(mss_for_mtu(used));
    let packed = u32::from(used)
        | match src {
            MtuSource::Default => 0,
            MtuSource::Static => 1 << 16,
            MtuSource::Dhcp => 2 << 16,
        };
    let first = !MTU_LOGGED.swap(true, core::sync::atomic::Ordering::Relaxed);
    MTU_IN_USE.store(packed, core::sync::atomic::Ordering::Relaxed);
    if first || before != (used, src) {
        if used < want {
            info!(
                "net: mtu {used} ({}; {want} asked for, this driver sends at most {used}-byte packets)",
                src.name()
            );
        } else {
            info!("net: mtu {used} ({})", src.name());
        }
    }
    used
}

/// Whether the first `net: mtu` line was written (later ones only on a change).
static MTU_LOGGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Applies the configured static address and gateway on every core (mode
/// `static`, and the fallback of mode `auto`).
fn apply_static(
    iface: &mut Iface,
    tcp: &mut TcpStack,
    link: &mut Link,
    n: usize,
    address: urmqtt_config::Ipv4Cidr,
    gateway: [u8; 4],
) {
    iface.set_addr(Some((address.addr, address.prefix_len)), Some(gateway));
    tcp.set_local_addr(address.addr);
    info!(
        "net: static address {}/{} gateway {}",
        ip_str(address.addr),
        address.prefix_len,
        ip_str(gateway)
    );
    let mtu = apply_mtu(iface, tcp, choose_mtu(None), None);
    for core in 1..n {
        link.send(
            core,
            CoreMsg::IpConfig {
                addr: Some((address.addr, address.prefix_len)),
                router: Some(gateway),
                mtu,
            },
        );
    }
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

/// Logs the TCP stack's counters every 5 s while they move. This is the
/// kernel-side evidence for the H3 flood tests (`tools/attack`): SYN cookies
/// issued without per-connection state, the RST/challenge rate cap holding,
/// malformed and full-table segments refused.
struct TcpStatsLog {
    next_ms: u64,
    last: urmqtt_tcp::Stats,
}

impl TcpStatsLog {
    const EVERY_MS: u64 = 5_000;

    fn new(now: u64) -> Self {
        Self {
            next_ms: now + Self::EVERY_MS,
            last: urmqtt_tcp::Stats::default(),
        }
    }

    fn tick(&mut self, tcp: &TcpStack, now: u64) {
        if now < self.next_ms {
            return;
        }
        let (s, conns) = (&tcp.stats, tcp.connections());
        self.next_ms = now + Self::EVERY_MS;
        if s.segs_in == self.last.segs_in {
            self.last = *s;
            return;
        }
        let d = |a: u64, b: u64| a.saturating_sub(b);
        info!(
            "tcp: core {}: {} seg(s) in, cookies {} sent/{} ok/{} bad, {} table full, \
             {} SYN(s) dropped, {} refused by the app, {} repeat(s) of refused flows, \
             {} retransmission(s) ({} fast, {} timeouts), RST {} sent ({} rate-limited), {} bad seg(s), {} connection(s)",
            crate::smp::current(),
            d(s.segs_in, self.last.segs_in),
            d(s.cookies_sent, self.last.cookies_sent),
            d(s.cookies_ok, self.last.cookies_ok),
            d(s.cookies_bad, self.last.cookies_bad),
            d(s.refused_full, self.last.refused_full),
            d(s.syn_dropped, self.last.syn_dropped),
            d(s.refused_app, self.last.refused_app),
            d(s.refused_repeat, self.last.refused_repeat),
            d(s.retransmits, self.last.retransmits),
            d(s.fast_retransmits, self.last.fast_retransmits),
            d(s.timeouts, self.last.timeouts),
            d(s.rst_sent, self.last.rst_sent),
            d(s.rst_limited, self.last.rst_limited),
            d(s.bad_segments, self.last.bad_segments),
            conns,
        );
        // How the retransmissions came about (ADR-268): "timeouts" above are
        // connections given up; a retransmission timer that fired is counted
        // here. A line of its own: the one above is near the console's width.
        let retx = d(s.retransmits, self.last.retransmits);
        if retx > 0 {
            let fast = d(s.fast_retransmits, self.last.fast_retransmits);
            let timer = d(s.rto_fired, self.last.rto_fired);
            info!(
                "tcp: core {}: retransmissions: {} recoveries started, {} by the timer, {} segment(s) resent in recoveries",
                crate::smp::current(),
                fast,
                timer,
                retx.saturating_sub(timer),
            );
        }
        if s.ooo_buffered != self.last.ooo_buffered
            || s.ooo_dropped != self.last.ooo_dropped
            || s.scaled != self.last.scaled
        {
            info!(
                "tcp: core {}: {} out-of-order segment(s) kept, {} not kept, {} byte(s) held now; {} connection(s) with window scaling, {} with SACK",
                crate::smp::current(),
                d(s.ooo_buffered, self.last.ooo_buffered),
                d(s.ooo_dropped, self.last.ooo_dropped),
                s.ooo_bytes,
                d(s.scaled, self.last.scaled),
                d(s.sack_neg, self.last.sack_neg),
            );
        }
        // Where the busiest sender's rate is decided (ADR-266): what it has in
        // flight against its congestion window and the peer's.
        if let Some(f) = tcp.busiest_sender() {
            info!(
                "tcp: core {}: busiest sender: {} KiB queued, {} KiB in flight, cwnd {} KiB, ssthresh {} KiB, peer window {} KiB, srtt {} ms, rto {} ms{}",
                crate::smp::current(),
                f.queued >> 10,
                f.in_flight >> 10,
                f.cwnd >> 10,
                f.ssthresh.min(1 << 30) >> 10,
                f.peer_window >> 10,
                f.srtt_ms,
                f.rto_ms,
                if f.recovering {
                    ", in loss recovery"
                } else {
                    ""
                }
            );
        }
        self.last = *s;
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
    fn syn_ok(&mut self, port: u16, remote: [u8; 4]) -> bool {
        port == ECHO_PORT && self.echo.is_some() || self.mqtt.syn_ok(port, remote)
    }

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
                CoreMsg::IpConfig { addr, router, mtu } => {
                    iface.set_addr(addr, router);
                    tcp.set_local_addr(addr.map_or([0; 4], |a| a.0));
                    let mtu = iface.set_mtu(mtu);
                    tcp.set_mss(mss_for_mtu(mtu));
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
/// The NIC's receive interrupt (its SPI or vector) and the dispatcher's
/// wake-up mode, handed over with the NIC (ADR-270).
static NIC_WAKE: urmqtt_sync::sync::SpinLock<(Option<u32>, Mode)> =
    urmqtt_sync::sync::SpinLock::new((None, Mode::Polling(Why::NoMsix)));

/// Boot CPU, before the other data cores start: takes the NIC (core 0
/// owns it) and publishes the restored broker state for every shard.
pub fn prepare(restored: Option<Arc<Restored>>) {
    *RESTORED.lock() = restored;
    let (net, spi, wake) = {
        let mut devs = devices::DEVICES.lock();
        (devs.net.take(), devs.net_msix_spi, devs.net_wake)
    };
    let Some(net) = net else {
        return;
    };
    *NIC_WAKE.lock() = (spi, wake);
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
    // Until core 0 says otherwise (its IpConfig carries the MTU in use).
    let first_mtu = iface.set_mtu(choose_mtu(None).0);
    let mut tcp = new_tcp([0; 4], mqtt.ports(), first_mtu);
    let mut pool: Vec<Frame> = Vec::new();
    let mut idle = dataplane::Idle::new();
    let mut cookies = CookieRotation::new(now_ms());
    let mut tcpstats = TcpStatsLog::new(now_ms());
    let mut last_busy_ms = now_ms();
    loop {
        let now = now_ms();
        cookies.tick(&mut tcp, now);
        tcpstats.tick(&tcp, now);
        let t = time::uptime_ns();
        let mut activity = drain_mesh(&mut link, &mut mqtt, &mut iface, &mut tcp, now);
        idle.prof.mesh += time::uptime_ns() - t;
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
                    dataplane::drop_frame(DropSite::WorkerTx);
                }
                sent = true;
            };
            for _ in 0..RX_BURST {
                let Some(f) = rx.pop() else { break };
                activity = true;
                let t = time::uptime_ns();
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
                idle.prof.rx += time::uptime_ns() - t;
                done.push(f);
            }
            let t = time::uptime_ns();
            activity |= mqtt.poll(&mut tcp, &mut link, now);
            idle.prof.poll += time::uptime_ns() - t;
            let t = time::uptime_ns();
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
            idle.prof.tcp += time::uptime_ns() - t;
        }
        link.flush();
        pool.append(&mut done);
        pool.truncate(POOL_MAX);
        if activity || sent {
            last_busy_ms = now;
        } else if now.saturating_sub(last_busy_ms) > POOL_IDLE_MS {
            // Quiet: give the spare frame buffers back to the heap.
            pool.truncate(POOL_IDLE);
        }
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
    nic_q: &mut VecDeque<Frame>,
) -> bool {
    let n = link.n;
    let mut moved = false;
    let mut steered = false;
    dataplane::note_rx_ring(net.rx_queued());
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
                            dataplane::drop_frame(DropSite::Steer);
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
    // Frames from the workers go to the NIC. A full transmit queue is a
    // reason to wait, not to drop: they stay here (up to NIC_BACKLOG) and
    // leave as the device frees descriptors; beyond that the rings fill and
    // the worker drops (counted). A dropped data frame costs the peer a round
    // trip or more to recover (PERF, ADR-223).
    while let Some(f) = nic_q.front() {
        if net.queue(f.data.get(..f.len).unwrap_or(&[])).is_err() {
            break;
        }
        moved = true;
        if let Some(f) = nic_q.pop_front()
            && pool.len() < POOL_MAX
        {
            pool.push(f);
        }
    }
    for rx in link.collect.iter_mut().flatten() {
        while nic_q.len() < NIC_BACKLOG {
            let Some(f) = rx.pop() else { break };
            moved = true;
            dataplane::DISPATCHED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if nic_q.is_empty() && net.queue(f.data.get(..f.len).unwrap_or(&[])).is_ok() {
                if pool.len() < POOL_MAX {
                    pool.push(f);
                }
            } else {
                nic_q.push_back(f);
                dataplane::note_nic_backlog(nic_q.len());
            }
        }
    }
    // Still waiting for descriptors: keep this core polling.
    moved |= !nic_q.is_empty();
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
                    image with launch mode PARAVIRTUALIZED; Hetzner: the default NIC; a VPS panel: the VirtIO \
                    network adapter)";
        if urmqtt_config::CONFIG.dev() {
            warn!("{hint}; idling (dev)");
            loop {
                cpu::wait_for_interrupt();
            }
        }
        crate::boot::fatal(hint);
    };
    let n = link.n;
    let mac = net.mac;
    info!(
        "net: virtio-net with {} receive and {} transmit descriptor(s)",
        net.rx_size, net.tx_size
    );
    let (irq_spi, mode) = *NIC_WAKE.lock();
    let mut wake = RxWake::new(mode);
    // When the NIC last moved a frame (ADR-270's hold before arming).
    let mut last_traffic_ns = 0u64;
    match (mode, irq_spi) {
        (Mode::Interrupt, Some(spi)) => {
            // Routed to this core (0), which owns the NIC; the queue keeps
            // it suppressed except while this core sleeps.
            crate::irq::enable_spi(spi, 0);
            info!(
                "net: receive wake-up: interrupt (MSI-X via {} {spi}, to core 0), on probation until {} frames have \
                 woken this core by it; polling only within {} ms of NIC traffic once verified",
                msi_name(spi),
                urmqtt_virtio::wake::VERIFY_HITS,
                urmqtt_virtio::wake::HOLD_NS / 1_000_000
            );
        }
        _ => {
            let why = if let Mode::Polling(w) = mode {
                w
            } else {
                Why::NoVector
            };
            wake = RxWake::new(Mode::Polling(why));
            info!(
                "net: receive wake-up: polling every {} us while connections exist ({})",
                NIC_POLL_NS / 1000,
                why.text()
            );
        }
    }
    // Relaxed: statistics.
    dataplane::RX_RING_SIZE.store(
        u64::from(net.rx_size),
        core::sync::atomic::Ordering::Relaxed,
    );
    if n > 1 {
        info!(
            "net: dispatcher mode: core 0 owns the single virtio-net queue pair and steers MQTT flows to {} worker core(s) (Toeplitz hash){}",
            dataplane::workers(n).len(),
            if dataplane::dispatcher_serves() {
                ", core 0 among them (cpu.dispatcher_serves)"
            } else {
                ""
            }
        );
    }
    let mut xid = [0u8; 4];
    // Fail closed (H0-W6), as for the cookie key.
    if urmqtt_tls::rng::fill_global(&mut xid).is_err() {
        crate::boot::fatal("dhcp: no random generator for the transaction id");
    }
    let mut iface = match CONFIG.network.mode {
        NetworkMode::Dhcp | NetworkMode::Auto { .. } => {
            Iface::new(mac, true, Some(u32::from_be_bytes(xid)), now_ms())
        }
        NetworkMode::Static { .. } => Iface::new(mac, true, None, now_ms()),
    };
    // mode = "auto": DHCP first, the static settings when no lease arrives in
    // time or when the lease is lost.
    let auto_static = match CONFIG.network.mode {
        NetworkMode::Auto {
            address,
            gateway,
            dhcp_timeout_s,
        } => Some((
            address,
            gateway,
            now_ms() + u64::from(dhcp_timeout_s) * 1000,
        )),
        _ => None,
    };
    let mut auto_pending = auto_static.is_some();
    let mut mqtt = MqttService::new(restored.as_deref(), 0, n);
    let serves = n == 1 || dataplane::dispatcher_serves();
    let mut ports = if serves { mqtt.ports() } else { Vec::new() };
    let mut echo_svc = echo.then(EchoSvc::default);
    if echo_svc.is_some() {
        ports.push(ECHO_PORT);
        info!("net: tcp echo service on port {ECHO_PORT} (dev only)");
    }
    let first_mtu = iface.set_mtu(choose_mtu(None).0);
    let mut tcp = new_tcp(iface.addr().unwrap_or([0; 4]), ports, first_mtu);
    // mode = "static": the address, gateway and MTU now, on every core.
    if let NetworkMode::Static { address, gateway } = CONFIG.network.mode {
        apply_static(&mut iface, &mut tcp, &mut link, n, address, gateway);
    }
    let mut pool: Vec<Frame> = Vec::new();
    let mut local: VecDeque<Frame> = VecDeque::new();
    let mut nic_q: VecDeque<Frame> = VecDeque::new();
    let mut ping = Ping::Waiting;
    let mut idle = dataplane::Idle::new();
    let (mut mem_last, mut mem_conns) = (now_ms(), 0u64);
    dataplane::set_baseline();
    let mut last_busy_ms = now_ms();
    let mut ops = crate::ops::Ops::new(now_ms());
    let mut sntp = crate::time_sync::TimeSync::new(now_ms());
    let mut cookies = CookieRotation::new(now_ms());
    let mut tcpstats = TcpStatsLog::new(now_ms());
    loop {
        let now = now_ms();
        cookies.tick(&mut tcp, now);
        tcpstats.tick(&tcp, now);
        if let Some(c) = dataplane::CONNECTIONS.first() {
            // Relaxed: statistics.
            c.store(
                tcp.connections() as u64,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        dataplane::mem_report(now, &mut mem_last, &mut mem_conns);
        let t = time::uptime_ns();
        let mut activity = dispatch(&mut net, &mut link, &mut pool, &mut local, &mut nic_q);
        if activity {
            last_traffic_ns = time::uptime_ns();
        }
        idle.prof.disp += time::uptime_ns() - t;
        let t = time::uptime_ns();
        activity |= drain_mesh(&mut link, &mut mqtt, &mut iface, &mut tcp, now);
        idle.prof.mesh += time::uptime_ns() - t;
        let mut events: Vec<Event> = Vec::new();
        {
            let mut emit = |f: &[u8]| {
                if net.queue(f).is_err() {
                    dataplane::drop_frame(DropSite::NicTxLocal);
                }
            };
            let slice = time::uptime_ns();
            while let Some(f) = local.pop_front() {
                activity = true;
                let t = time::uptime_ns();
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
                    Rx::Udp {
                        src,
                        sport,
                        dport,
                        payload,
                    } => sntp.input(now, src, sport, dport, payload),
                    Rx::Event(e) => events.push(e),
                    Rx::None => {}
                }
                let t1 = time::uptime_ns();
                idle.prof.rx += t1 - t;
                if pool.len() < POOL_MAX {
                    pool.push(f);
                }
                // A dispatcher that also serves connections goes back to the
                // NIC after a slice: its work is cut between frames (one
                // TLS step, up to a few ms, cannot be cut).
                if serves && t1 - slice > LOCAL_SLICE_NS {
                    break;
                }
            }
            if let Some(e) = iface.poll(now, &mut emit) {
                events.push(e);
            }
            ops.poll(&mut iface, now, &mut emit);
            sntp.poll(&mut iface, now, &mut emit);
            if auto_pending
                && let Some((address, gateway, deadline)) = auto_static
                && iface.addr().is_none()
                && now >= deadline
            {
                warn!("net: no dhcp lease in time, falling back to the static settings");
                auto_pending = false;
                apply_static(&mut iface, &mut tcp, &mut link, n, address, gateway);
            }
            for e in events {
                match e {
                    Event::Dhcp(dhcp::Event::Bound(l) | dhcp::Event::Renewed(l)) => {
                        auto_pending = false;
                        info!(
                            "net: dhcp lease {}/{} router {} dns [{}]",
                            ip_str(l.addr),
                            l.prefix,
                            l.router.map_or_else(|| "none".into(), ip_str),
                            l.dns.map_or_else(alloc::string::String::new, ip_str)
                        );
                        tcp.set_local_addr(l.addr);
                        let mtu = apply_mtu(&mut iface, &mut tcp, choose_mtu(Some(&l)), Some(&l));
                        for core in 1..n {
                            link.send(
                                core,
                                CoreMsg::IpConfig {
                                    addr: Some((l.addr, l.prefix)),
                                    router: l.router,
                                    mtu,
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
                        if let Some((address, gateway, _)) = auto_static {
                            warn!("net: using the static settings");
                            apply_static(&mut iface, &mut tcp, &mut link, n, address, gateway);
                        } else {
                            tcp.set_local_addr([0; 4]);
                            for core in 1..n {
                                link.send(
                                    core,
                                    CoreMsg::IpConfig {
                                        addr: None,
                                        router: None,
                                        // The MTU stays until the next lease.
                                        mtu: iface.mtu(),
                                    },
                                );
                            }
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
            let t = time::uptime_ns();
            activity |= mqtt.poll(&mut tcp, &mut link, now);
            idle.prof.poll += time::uptime_ns() - t;
            let t = time::uptime_ns();
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
            idle.prof.tcp += time::uptime_ns() - t;
        }
        link.flush();
        net.flush();
        // The NIC is polled: while idle, the 10 ms tick bounds the receive
        // latency of the first packet; other cores wake us for their frames.
        let busy = activity
            || tcp.has_pending()
            || matches!(ping, Ping::Resolving { .. } | Ping::Sent { .. });
        if busy {
            last_busy_ms = now;
        } else if now.saturating_sub(last_busy_ms) > POOL_IDLE_MS {
            pool.truncate(POOL_IDLE);
        }
        // Polling mode, with connections on the workers: come back to the NIC
        // often enough that a frame never waits for the 10 ms tick (ADR-224).
        // Interrupt mode: the same while the NIC moved a frame in the last
        // 2 ms, then the receive interrupt ends the sleep (ADR-270).
        let conns: u64 = dataplane::CONNECTIONS
            .iter()
            .map(|c| c.load(core::sync::atomic::Ordering::Relaxed))
            .sum();
        let plan = wake.plan(
            conns > 0,
            time::uptime_ns().saturating_sub(last_traffic_ns),
            NIC_POLL_NS,
        );
        idle.poll_wake(plan.poll_ns);
        let irq = plan.arm;
        if irq {
            wake.armed(devices::net_irqs());
        }
        let slept = idle.pass_armed(
            busy,
            |on| {
                if !irq {
                    false
                } else if on {
                    net.rx_irq_arm()
                } else {
                    net.rx_irq_disarm();
                    false
                }
            },
            || link.pending() || net.rx_pending() || !local.is_empty(),
        );
        let (irqs_now, waiting) = (devices::net_irqs(), net.rx_pending());
        if slept && irq {
            // Relaxed: statistics.
            dataplane::NIC_ARMED_SLEEPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if waiting && irqs_now == wake.irqs_at_arm() {
                dataplane::NIC_MISSED_WAKES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
        let change = if slept && irq {
            wake.after_sleep(irqs_now, waiting)
        } else {
            Change::None
        };
        match change {
            Change::Verified => info!(
                "net: receive interrupt verified: {} frames woke core 0 by it ({} ms after boot); no polling while the NIC is quiet",
                urmqtt_virtio::wake::VERIFY_HITS,
                time::uptime_ns() / 1_000_000
            ),
            Change::FellBack => warn!(
                "net: receive wake-up: {} frames waited after sleeps without the receive interrupt; \
                 polling every {} us while connections exist from now on ({})",
                urmqtt_virtio::wake::MISSES_BEFORE_POLLING,
                NIC_POLL_NS / 1000,
                Why::Silent.text()
            ),
            Change::None => {}
        }
    }
}
