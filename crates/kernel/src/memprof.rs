//! `test=dp-bench` in a `memprof` build (dev only, PERF, ADR-200): where the
//! server side of a handshake, of TLS records and of a publish fan-out
//! spends its time in `memcpy`, `memmove` and `memset`, and what the
//! assembly of ADR-200 saves.
//!
//! The build defines the three symbols itself (`no-mem-symbols`). Each one
//! calls either the production code (`urmqtt_arch::mem`) or the code that
//! compiler_builtins ran before ADR-200 (`mem::baseline`, three `rep`
//! instructions per call), and, inside a "server window" of core 0, counts
//! the call in a size bucket and times it with two `rdtsc`. The benchmark's
//! TLS client (rustls) and the harness stay out of the numbers. Every phase
//! runs four times in one boot, so that a noisy host hits both alike: the
//! new code timed, the old code timed (only the windows are timed: the
//! share has no counting overhead in its denominator), then both again with
//! the counters on. Everything is in memory on one core.
//!
//! The feature is off in every image that is built for use; nothing here is
//! reachable without `--features memprof`.

#![allow(
    unsafe_code,
    suspicious_runtime_symbol_definitions,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]

use alloc::vec::Vec;
use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use urmqtt_arch::{cpu, time};
use urmqtt_broker::Broker;
use urmqtt_log::{error, info};
use urmqtt_tls::Event;
use urmqtt_tls::client::{ClientSetup, TlsClient};

/// Size buckets: bucket `b` holds sizes in `(2^(b-1), 2^b]`; 0 holds 0 and 1.
const NB: usize = 19;
const OPS: [&str; 3] = ["copy", "move", "set"];
const IMPS: [&str; 2] = ["new", "old"];

struct Cell {
    calls: AtomicU64,
    bytes: AtomicU64,
    cycles: AtomicU64,
}
/// `[implementation][operation][size bucket]`; implementation 0 is the new
/// code, 1 the old.
static CELLS: [[[Cell; NB]; 3]; 2] = [const {
    [const {
        [const {
            Cell {
                calls: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                cycles: AtomicU64::new(0),
            }
        }; NB]
    }; 3]
}; 2];

/// Counting is on (inside a server window of core 0).
static ON: AtomicBool = AtomicBool::new(false);
/// The old code runs.
static OLD: AtomicBool = AtomicBool::new(false);
/// `rdtsc` pair overhead, cycles.
static OVH: AtomicU64 = AtomicU64::new(0);

fn bucket(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        ((usize::BITS - (n - 1).leading_zeros()) as usize).min(NB - 1)
    }
}

#[inline(always)]
fn counting() -> bool {
    ON.load(Relaxed) && crate::smp::current() == 0
}

#[inline(always)]
fn record(op: usize, n: usize, cyc: u64) {
    let c = &CELLS[usize::from(OLD.load(Relaxed))][op][bucket(n)];
    c.calls.fetch_add(1, Relaxed);
    c.bytes.fetch_add(n as u64, Relaxed);
    c.cycles
        .fetch_add(cyc.saturating_sub(OVH.load(Relaxed)), Relaxed);
}

#[inline(always)]
// SAFETY: the contract of `memcpy`/`memmove` (valid `dest`/`src` for `n` bytes); the only callers
// are the shims below, which pass their own arguments unchanged. `memprof` builds only (dev).
unsafe fn do_copy(dest: *mut u8, src: *const u8, n: usize) {
    unsafe {
        if OLD.load(Relaxed) {
            urmqtt_arch::mem::baseline::copy(dest, src, n);
        } else {
            urmqtt_arch::mem::copy(dest, src, n);
        }
    }
}

#[inline(always)]
// SAFETY: the contract of `memset` (`dest` valid for `n` bytes); the only callers are the `memset`
// shim below, which passes its own arguments unchanged. `memprof` builds only (dev).
unsafe fn do_set(dest: *mut u8, c: i32, n: usize) {
    unsafe {
        if OLD.load(Relaxed) {
            urmqtt_arch::mem::baseline::set(dest, c, n);
        } else {
            urmqtt_arch::mem::set(dest, c, n);
        }
    }
}

/// # Safety
/// The C contract of `memcpy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if counting() {
            let t0 = _rdtsc();
            do_copy(dest, src, n);
            record(0, n, _rdtsc() - t0);
        } else {
            do_copy(dest, src, n);
        }
    }
    dest
}

/// # Safety
/// The C contract of `memmove`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if counting() {
            let t0 = _rdtsc();
            do_copy(dest, src, n);
            record(1, n, _rdtsc() - t0);
        } else {
            do_copy(dest, src, n);
        }
    }
    dest
}

/// # Safety
/// The C contract of `memset`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: core::ffi::c_int, n: usize) -> *mut u8 {
    unsafe {
        if counting() {
            let t0 = _rdtsc();
            do_set(s, c, n);
            record(2, n, _rdtsc() - t0);
        } else {
            do_set(s, c, n);
        }
    }
    s
}

// ------------------------------------------------------------- the harness

/// Cycles spent inside server windows, per implementation.
static SRV: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// The counting passes: the shims count.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Runs `f` as server work: its cycles are summed, and in a counting pass
/// its mem calls are counted.
#[inline(always)]
fn srv<T>(f: impl FnOnce() -> T) -> T {
    ON.store(ARMED.load(Relaxed), Relaxed);
    // SAFETY: `rdtsc` reads the time-stamp counter; always allowed in ring 0, touches no memory.
    let t0 = unsafe { _rdtsc() };
    let r = f();
    let dt = unsafe { _rdtsc() }.saturating_sub(t0 + OVH.load(Relaxed));
    ON.store(false, Relaxed);
    SRV[usize::from(OLD.load(Relaxed))].fetch_add(dt, Relaxed);
    r
}

fn reset_imp(imp: usize) {
    SRV[imp].store(0, Relaxed);
    for c in CELLS[imp].iter().flatten() {
        c.calls.store(0, Relaxed);
        c.bytes.store(0, Relaxed);
        c.cycles.store(0, Relaxed);
    }
}

/// Calls, bytes and cycles per operation and size bucket of one implementation.
type Snap = [[[u64; 3]; NB]; 3];

fn snapshot(imp: usize) -> Snap {
    let mut s = [[[0u64; 3]; NB]; 3];
    for (o, row) in s.iter_mut().enumerate() {
        for (b, v) in row.iter_mut().enumerate() {
            let c = &CELLS[imp][o][b];
            *v = [
                c.calls.load(Relaxed),
                c.bytes.load(Relaxed),
                c.cycles.load(Relaxed),
            ];
        }
    }
    s
}

/// Rounds of a phase; the host is shared and noisy, so the best (least
/// server time) of the rounds is what is reported, per implementation.
const ROUNDS: u64 = 15;
/// How often a phase's closure runs: per round, new and old, timed and counted.
const PASSES: u64 = ROUNDS * 4;

/// Runs `f` [`PASSES`] times and prints the best round of each
/// implementation.
fn phase(tag: &str, iters: u64, hz: u64, mut f: impl FnMut()) {
    let mut base = [u64::MAX; 2];
    let mut best = [u64::MAX; 2];
    let mut snaps = [[[[0u64; 3]; NB]; 3]; 2];
    for _ in 0..ROUNDS {
        for armed in [false, true] {
            ARMED.store(armed, Relaxed);
            for imp in 0..2 {
                OLD.store(imp == 1, Relaxed);
                reset_imp(imp);
                f();
                let t = SRV[imp].load(Relaxed);
                if !armed {
                    base[imp] = base[imp].min(t);
                } else if t < best[imp] {
                    best[imp] = t;
                    snaps[imp] = snapshot(imp);
                }
            }
        }
    }
    ARMED.store(false, Relaxed);
    OLD.store(false, Relaxed);
    report(tag, iters, hz, base, &snaps);
    pause();
}

/// Time to read the screen (a VPS has no serial port); none under `smoke`.
static PAUSE_MS: AtomicU64 = AtomicU64::new(0);

fn pause() {
    let end = time::uptime_ns() + PAUSE_MS.load(Relaxed) * 1_000_000;
    while time::uptime_ns() < end {
        core::hint::spin_loop();
    }
}

fn report(tag: &str, iters: u64, hz: u64, base: [u64; 2], snaps: &[Snap; 2]) {
    let it = iters as f64;
    let us = |c: f64| c * 1e6 / hz as f64;
    for imp in 0..2 {
        let mem: u64 = snaps[imp].iter().flatten().map(|v| v[2]).sum();
        let calls: u64 = snaps[imp].iter().flatten().map(|v| v[0]).sum();
        info!(
            "memprof {tag} [{}]: server {:.0} cyc = {:.2} us/iter; mem* {:.0} cyc = {:.2} us in {:.1} calls = {:.1}%",
            IMPS[imp],
            base[imp] as f64 / it,
            us(base[imp] as f64 / it),
            mem as f64 / it,
            us(mem as f64 / it),
            calls as f64 / it,
            mem as f64 * 100.0 / base[imp].max(1) as f64,
        );
    }
    info!(
        "memprof {tag}: new/old server time = {:.3} (a saving of {:.1}%)",
        base[0] as f64 / base[1].max(1) as f64,
        100.0 - base[0] as f64 * 100.0 / base[1].max(1) as f64
    );
    for b in 0..NB {
        let mut line = alloc::string::String::new();
        for (o, name) in OPS.iter().enumerate() {
            let (old, new) = (snaps[1][o][b], snaps[0][o][b]);
            if old[0] == 0 {
                continue;
            }
            use core::fmt::Write;
            let _ = write!(
                line,
                " {name} {:.1}/it {:.0}B old {:.0}c new {:.0}c |",
                old[0] as f64 / it,
                old[1] as f64 / it,
                old[2] as f64 / old[0] as f64,
                new[2] as f64 / new[0].max(1) as f64,
            );
        }
        if !line.is_empty() {
            let ub = if b == 0 { 1 } else { 1usize << b };
            info!("mp <={ub:>5}{line}");
        }
    }
}

const CONNECT: [u8; 24] = [
    0x10, 22, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 10, b'd', b'e', b'v', b'i', b'c',
    b'e', b'-', b'0', b'0', b'1',
];

/// One handshake with CONNECT/CONNACK, server side counted.
fn handshake_once(
    server: &urmqtt_tls::TlsServer,
    cli: &TlsClient,
    broker: &mut Broker,
    now_ms: u64,
) -> Result<(), &'static str> {
    let mut c = cli.connect().map_err(|_| "client connect")?;
    let mut s = srv(|| server.accept()).map_err(|_| "server accept")?;
    c.send(&CONNECT);
    let (mut to_s, mut to_c, mut app_s, mut app_c) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.input(&[], &mut to_s, &mut app_c)
        .map_err(|_| "client hello")?;
    let mut conn = None;
    for _ in 0..16 {
        if !to_s.is_empty() {
            let data = core::mem::take(&mut to_s);
            let ev = srv(|| s.input(&data, &mut to_c, &mut app_s)).map_err(|_| "server")?;
            if let Event::Established { identity, .. } = ev {
                let k = srv(|| broker.open(now_ms)).ok_or("broker full")?;
                srv(|| broker.set_identity(k, &identity, false));
                conn = Some(k);
            }
            if let Some(k) = conn
                && !app_s.is_empty()
            {
                srv(|| {
                    broker.input(k, &app_s, now_ms);
                });
                app_s.clear();
                let out = broker.output(k).to_vec();
                srv(|| broker.consumed(k, out.len()));
                srv(|| s.send(&out, &mut to_c)).map_err(|_| "server send")?;
            }
        }
        if !to_c.is_empty() {
            let data = core::mem::take(&mut to_c);
            c.input(&data, &mut to_s, &mut app_c)
                .map_err(|_| "client")?;
        }
        if app_c.len() >= 4 {
            break;
        }
    }
    let k = conn.ok_or("no session")?;
    srv(|| {
        broker.closed(k, now_ms);
        broker.drain_persist().for_each(drop);
    });
    if app_c.get(..4) != Some(&[0x20, 2, 0, 0][..]) {
        return Err("no CONNACK");
    }
    Ok(())
}

fn varint(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

fn connect_pkt(id: &str) -> Vec<u8> {
    let mut v = alloc::vec![0x10];
    varint(&mut v, 10 + 2 + id.len());
    v.extend_from_slice(&[0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60]);
    v.extend_from_slice(&(id.len() as u16).to_be_bytes());
    v.extend_from_slice(id.as_bytes());
    v
}

fn subscribe_pkt(filter: &str) -> Vec<u8> {
    let mut v = alloc::vec![0x82];
    varint(&mut v, 2 + 2 + filter.len() + 1);
    v.extend_from_slice(&[0, 1]);
    v.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    v.extend_from_slice(filter.as_bytes());
    v.push(0);
    v
}

fn publish_pkt(topic: &str, payload: usize) -> Vec<u8> {
    let mut v = alloc::vec![0x30];
    varint(&mut v, 2 + topic.len() + payload);
    v.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    v.extend_from_slice(topic.as_bytes());
    v.resize(v.len() + payload, 0x5a);
    v
}

fn drain_out(broker: &mut Broker, k: urmqtt_broker::ConnId) -> usize {
    let n = broker.output(k).len();
    broker.consumed(k, n);
    n
}

fn fanout(subs: usize, payload: usize, msgs: u64, hz: u64) {
    let mut cfg = crate::mqtt_service::broker_config(subs + 8, false);
    // The identities of this test are services: they may share a filter.
    cfg.acl.service_ids = &["sub-*", "pub-*"];
    // No publish rate limit: it would drop the load this test measures.
    cfg.rate_tokens = u32::MAX / 2;
    cfg.rate_period_ms = 1;
    let mut broker = Broker::new(cfg);
    let open = |id: &str, filter: Option<&str>, broker: &mut Broker| {
        let k = broker.open(1).expect("broker full");
        broker.set_identity(k, id, false);
        broker.input(k, &connect_pkt(id), 1);
        if let Some(f) = filter {
            broker.input(k, &subscribe_pkt(f), 1);
        }
        drain_out(broker, k);
        k
    };
    let mut ks = Vec::new();
    for i in 0..subs {
        ks.push(open(
            &alloc::format!("sub-{i}"),
            Some("fleet/#"),
            &mut broker,
        ));
    }
    let pubk = open("pub-0", None, &mut broker);
    let pkt = publish_pkt("fleet/x/telemetry", payload);
    let mut delivered = 0usize;
    let mut round = 0u64;
    phase(
        &alloc::format!("fanout {subs} subs x {payload} B"),
        msgs,
        hz,
        || {
            for _ in 0..msgs {
                round += 1;
                srv(|| broker.input(pubk, &pkt, 2 + round));
                broker.drain_routes().for_each(drop);
                broker.drain_shared().for_each(drop);
                broker.drain_persist().for_each(drop);
                for &k in &ks {
                    delivered += srv(|| drain_out(&mut broker, k));
                }
                drain_out(&mut broker, pubk);
            }
        },
    );
    let want = subs * PASSES as usize * msgs as usize * pkt.len();
    if delivered != want {
        error!("memprof: fan-out delivered {delivered} bytes, expected {want}");
    }
}

fn records(server: &urmqtt_tls::TlsServer, cli: &TlsClient, hz: u64) -> Result<(), &'static str> {
    let mut c = cli.connect().map_err(|_| "client connect")?;
    let mut s = server.accept().map_err(|_| "server accept")?;
    let (mut to_s, mut to_c, mut app_s, mut app_c) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.input(&[], &mut to_s, &mut app_c)
        .map_err(|_| "client hello")?;
    let mut est = false;
    for _ in 0..16 {
        if !to_s.is_empty() {
            let data = core::mem::take(&mut to_s);
            if let Event::Established { .. } = s
                .input(&data, &mut to_c, &mut app_s)
                .map_err(|_| "server")?
            {
                est = true;
            }
        }
        if !to_c.is_empty() {
            let data = core::mem::take(&mut to_c);
            c.input(&data, &mut to_s, &mut app_c)
                .map_err(|_| "client")?;
        }
        if est && to_s.is_empty() && to_c.is_empty() {
            break;
        }
    }
    if !est {
        return Err("not established");
    }
    let mut bad = false;
    for (size, rounds) in [(64usize, 4000u64), (256, 3000), (1024, 2000), (4096, 800)] {
        let payload = alloc::vec![0xa5u8; size];
        phase(
            &alloc::format!("tls record {size} B (1 rx + 1 tx)"),
            rounds,
            hz,
            || {
                for _ in 0..rounds {
                    c.send(&payload);
                    if c.input(&[], &mut to_s, &mut app_c).is_err() {
                        bad = true;
                        return;
                    }
                    let data = core::mem::take(&mut to_s);
                    if srv(|| s.input(&data, &mut to_c, &mut app_s)).is_err() || app_s.len() != size
                    {
                        bad = true;
                        return;
                    }
                    app_s.clear();
                    if srv(|| s.send(&payload, &mut to_c)).is_err() {
                        bad = true;
                        return;
                    }
                    let data = core::mem::take(&mut to_c);
                    if c.input(&data, &mut to_s, &mut app_c).is_err() {
                        bad = true;
                        return;
                    }
                    app_c.clear();
                }
            },
        );
    }
    if bad {
        Err("record exchange failed")
    } else {
        Ok(())
    }
}

/// Core 0 runs everything.
pub fn run(smoke: bool) -> ! {
    PAUSE_MS.store(if smoke { 0 } else { 9_000 }, Relaxed);
    let ovh = (0..2000)
        .map(|_| {
            // SAFETY: `rdtsc` reads the time-stamp counter; always allowed in ring 0, touches no memory.
            let a = unsafe { _rdtsc() };
            let b = unsafe { _rdtsc() };
            b - a
        })
        .min()
        .unwrap_or(0);
    OVH.store(ovh, Relaxed);
    // SAFETY: `rdtsc` reads the time-stamp counter; always allowed in ring 0, touches no memory.
    let (t0, n0) = (unsafe { _rdtsc() }, time::uptime_ns());
    while time::uptime_ns() < n0 + 100_000_000 {
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    let hz = (unsafe { _rdtsc() } - t0) * 10;
    info!(
        "memprof: rdtsc pair overhead {ovh} cycles, tsc {} MHz",
        hz / 1_000_000
    );

    let server = crate::mqtt_service::tls_server_for_bench();
    let cli = TlsClient::new(&ClientSetup {
        ca_pem: urmqtt_config::CONFIG
            .trust
            .operational
            .first()
            .copied()
            .unwrap_or_default(),
        cert_pem: urmqtt_config::SELFTEST_CLIENT_CERT_PEM,
        key_pem: urmqtt_config::SELFTEST_CLIENT_KEY_PEM,
    });
    let (Some(server), Ok(cli)) = (server, cli) else {
        error!("memprof: TLS setup failed");
        cpu::halt();
    };
    let mut broker = Broker::new(crate::mqtt_service::broker_config(1024, false));

    // Handshakes (warm-up first: caches, lazily built tables).
    for i in 0..20 {
        let _ = handshake_once(&server, &cli, &mut broker, i);
    }
    let n = 150u64;
    let mut fails = 0u32;
    let mut now = 100;
    phase("handshake (mTLS + CONNECT)", n, hz, || {
        for _ in 0..n {
            now += 1;
            if handshake_once(&server, &cli, &mut broker, now).is_err() {
                fails += 1;
            }
        }
    });
    if fails > 0 {
        error!("memprof: {fails} handshakes failed");
    }
    if let Err(e) = records(&server, &cli, hz) {
        error!("memprof: records: {e}");
    }
    for (subs, payload) in [
        (1usize, 64usize),
        (1, 1024),
        (16, 64),
        (16, 1024),
        (128, 256),
    ] {
        let msgs = if subs >= 128 { 300 } else { 1500 };
        fanout(subs, payload, msgs, hz);
    }
    info!("memprof: done");
    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if smoke {
        crate::power::off();
    }
    loop {
        cpu::wait_for_interrupt();
    }
}
