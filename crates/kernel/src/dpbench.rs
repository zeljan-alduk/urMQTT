//! In-guest data-plane benchmark (`test=dp-bench`, M13, ADR-032).
//!
//! Every worker core runs full TLS 1.3 handshakes with a client
//! certificate, then CONNECT/CONNACK through its own broker shard, against
//! an in-memory client on the same core. Phases use 1, 2, 4, … worker
//! cores at once. Nothing is shared between the cores but the heap's global
//! lock (behind the per-CPU caches), so the aggregate rate shows how the
//! shared-nothing data plane scales, independent of the host's network
//! path (QEMU user networking is single-threaded).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use urmqtt_arch_aarch64::{cpu, timer};
use urmqtt_broker::Broker;
use urmqtt_log::{error, info};
use urmqtt_tls::Event;
use urmqtt_tls::client::{ClientSetup, TlsClient};

use crate::smp::MAX_CPUS;

const PHASE_NS: u64 = 3_000_000_000;

/// Phase number (0: not started) and how many workers take part.
static PHASE: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static DEADLINE_NS: AtomicU64 = AtomicU64::new(0);
static DONE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static FAILED: AtomicU64 = AtomicU64::new(0);

const CONNECT: [u8; 24] = [
    0x10, 22, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 10, b'd', b'e', b'v', b'i', b'c',
    b'e', b'-', b'0', b'0', b'1',
];

/// One handshake + CONNECT/CONNACK + close, all in memory.
fn one(
    srv: &urmqtt_tls::TlsServer,
    cli: &TlsClient,
    broker: &mut Broker,
    now_ms: u64,
) -> Result<(), &'static str> {
    let mut c = cli.connect().map_err(|_| "client connect")?;
    let mut s = srv.accept().map_err(|_| "server accept")?;
    c.send(&CONNECT);
    let (mut to_s, mut to_c, mut app_s, mut app_c) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.input(&[], &mut to_s, &mut app_c)
        .map_err(|_| "client hello")?;
    let mut conn = None;
    for _ in 0..16 {
        if !to_s.is_empty() {
            let data = core::mem::take(&mut to_s);
            if let Event::Established { identity, .. } = s
                .input(&data, &mut to_c, &mut app_s)
                .map_err(|_| "server")?
            {
                let k = broker.open(now_ms).ok_or("broker full")?;
                broker.set_identity(k, &identity);
                conn = Some(k);
            }
            if let Some(k) = conn
                && !app_s.is_empty()
            {
                broker.input(k, &app_s, now_ms);
                app_s.clear();
                let out = broker.output(k).to_vec();
                broker.consumed(k, out.len());
                s.send(&out, &mut to_c).map_err(|_| "server send")?;
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
    broker.closed(k, now_ms);
    broker.drain_persist().for_each(drop);
    if app_c.get(..4) != Some(&[0x20, 2, 0, 0][..]) {
        return Err("no CONNACK");
    }
    Ok(())
}

/// A worker core's loop: runs whenever its phase includes it.
pub fn worker(me: usize) -> ! {
    let srv = crate::mqtt_service::tls_server_for_bench();
    let cli = TlsClient::new(&ClientSetup {
        ca_pem: urmqtt_config::CA_PEM,
        cert_pem: urmqtt_config::SELFTEST_CLIENT_CERT_PEM,
        key_pem: urmqtt_config::SELFTEST_CLIENT_KEY_PEM,
    });
    let (Some(srv), Ok(cli)) = (srv, cli) else {
        error!("dp-bench: core {me}: TLS setup failed");
        cpu::halt();
    };
    let mut broker = Broker::new(crate::mqtt_service::broker_config(1024, false));
    let mut seen = 0;
    loop {
        // Acquire: pairs with the coordinator's Release of the phase.
        let phase = PHASE.load(Ordering::Acquire);
        if phase == seen {
            core::hint::spin_loop();
            continue;
        }
        seen = phase;
        if me > ACTIVE.load(Ordering::Relaxed) {
            continue;
        }
        let deadline = DEADLINE_NS.load(Ordering::Relaxed);
        let mut n = 0u64;
        while timer::uptime_ns() < deadline {
            match one(&srv, &cli, &mut broker, timer::uptime_ns() / 1_000_000) {
                Ok(()) => n += 1,
                Err(e) => {
                    if FAILED.fetch_add(1, Ordering::Relaxed) < 3 {
                        error!("dp-bench: core {me}: {e}");
                    }
                }
            }
        }
        // Release: the count is read by the coordinator after the phase.
        DONE[me].store(n, Ordering::Release);
    }
}

/// Core 0: runs the phases over workers `1..=workers` and reports.
pub fn run(workers: usize, smoke: bool) -> ! {
    for c in 1..=workers {
        crate::smp::start_dp_bench(c);
    }
    // Let the workers build their TLS state.
    let t = timer::uptime_ns() + 200_000_000;
    while timer::uptime_ns() < t {
        core::hint::spin_loop();
    }
    let mut results: Vec<(usize, u64)> = Vec::new();
    let mut k = 1;
    while k <= workers {
        for d in DONE.iter() {
            d.store(0, Ordering::Relaxed);
        }
        ACTIVE.store(k, Ordering::Relaxed);
        DEADLINE_NS.store(timer::uptime_ns() + PHASE_NS, Ordering::Relaxed);
        // Release: publishes ACTIVE and DEADLINE with the new phase.
        PHASE.fetch_add(1, Ordering::Release);
        let end = timer::uptime_ns() + PHASE_NS + 300_000_000;
        while timer::uptime_ns() < end {
            core::hint::spin_loop();
        }
        // Acquire: pairs with the workers' Release of their counts.
        let total: u64 = (1..=k).map(|c| DONE[c].load(Ordering::Acquire)).sum();
        let per_s = total * 1_000_000_000 / PHASE_NS;
        info!(
            "dp-bench: {k} worker core(s): {per_s} handshakes/s (full TLS 1.3 + mTLS + CONNECT/CONNACK, client and server in the guest)"
        );
        results.push((k, per_s));
        k = if k == workers {
            k + 1
        } else {
            (k * 2).min(workers)
        };
    }
    let base = results.first().map_or(1, |r| r.1.max(1));
    for (k, r) in &results {
        info!(
            "dp-bench: scaling {k} core(s): {:.2}x of 1 core ({:.0}% of linear)",
            *r as f64 / base as f64,
            *r as f64 * 100.0 / (base * *k as u64) as f64
        );
    }
    info!(
        "dp-bench: done, {} failure(s)",
        FAILED.load(Ordering::Relaxed)
    );
    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if smoke {
        crate::power::off();
    }
    loop {
        cpu::wfi();
    }
}
