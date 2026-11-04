//! `cargo run --release -p urmqtt-tls --features stage-profile --example
//! handshake_profile`: the server's CPU time in one full TLS 1.3 + mutual-TLS
//! handshake, stage by stage (PERF).
//!
//! A stock rustls client (our provider, resumption off, so every handshake
//! is a full one) connects to `TlsServer` with the dev certificates
//! (`make certs`); only the server's `input` calls are timed. Two cases:
//! a returning device (its certificate's signature is in the verification
//! memo, as on every reconnect) and a device's first contact (memo cleared
//! before each handshake). Each case runs `ROUNDS` rounds of `PER_ROUND`
//! handshakes; the table gives the median round, microseconds per
//! handshake, and the calls per handshake. Allocations are counted while the
//! server runs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use urmqtt_tls::rng::{EntropyPool, Source};
use urmqtt_tls::stages::{self, Report, Stage};
use urmqtt_tls::{Event, IdentityField, RevocationList, ServerSetup, TicketKeys, TlsServer};

struct Counting;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if COUNT.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
        }
        // SAFETY: the caller's contract is passed on.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if COUNT.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(n as u64, Ordering::Relaxed);
        }
        // SAFETY: as above.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const ROUNDS: usize = 9;
const PER_ROUND: usize = 200;

fn dev() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev")
}

fn uptime() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
}

fn server() -> TlsServer {
    let d = dev();
    let ca = std::fs::read(d.join("ca.pem")).expect("deploy/dev/ca.pem (make certs)");
    let cert = std::fs::read(d.join("server.pem")).expect("server.pem");
    let key = std::fs::read(d.join("server.key")).expect("server.key");
    TlsServer::new(&ServerSetup {
        operational_ca_pems: &[&ca],
        bootstrap_ca_pems: &[],
        cert_pem: &cert,
        key_pem: &key,
        identity_field: IdentityField::Cn,
        resumption: true,
        revocations: Arc::new(RevocationList::from_hex(&[])),
        tickets: Arc::new(TicketKeys::new(urmqtt_tls::ticket::INTERVAL_S, uptime)),
    })
    .expect("server")
}

fn client_config() -> Arc<ClientConfig> {
    let d = dev();
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(d.join("ca.pem")).expect("ca") {
        roots.add(c.expect("ca")).expect("ca");
    }
    let chain: Vec<_> = CertificateDer::pem_file_iter(d.join("devices/device-001.pem"))
        .expect("device")
        .map(|c| c.expect("device"))
        .collect();
    let key = PrivateKeyDer::from_pem_file(d.join("devices/device-001.key")).expect("key");
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(urmqtt_tls::provider::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("client cert");
    cfg.resumption = Resumption::disabled();
    Arc::new(cfg)
}

/// One full handshake; the server's part is armed.
fn handshake(srv: &TlsServer, cfg: &Arc<ClientConfig>) {
    let mut client = ClientConnection::new(cfg.clone(), ServerName::try_from("localhost").unwrap())
        .expect("client");
    let mut session = stages::armed(|| srv.accept()).expect("accept");
    let mut app = Vec::new();
    let mut established = false;
    for _ in 0..20 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).expect("write");
        }
        let mut s2c = Vec::new();
        if !c2s.is_empty() {
            COUNT.store(true, Ordering::Relaxed);
            let ev = stages::armed(|| session.input(&c2s, &mut s2c, &mut app)).expect("server");
            COUNT.store(false, Ordering::Relaxed);
            established |= matches!(ev, Event::Established { resumed: false, .. });
        }
        if s2c.is_empty() && c2s.is_empty() {
            break;
        }
        let mut rd = &s2c[..];
        while !rd.is_empty() {
            client.read_tls(&mut rd).expect("read");
            client.process_new_packets().expect("client");
        }
    }
    assert!(established, "the handshake did not complete");
}

struct Round {
    r: Report,
    allocs: u64,
    bytes: u64,
}

fn round(srv: &TlsServer, cfg: &Arc<ClientConfig>, first_contact: bool) -> Round {
    let _ = stages::take();
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    for _ in 0..PER_ROUND {
        if first_contact {
            urmqtt_tls::provider::clear_verify_memo();
        }
        handshake(srv, cfg);
    }
    Round {
        r: stages::take(),
        allocs: ALLOCS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn report(title: &str, rounds: &[Round]) {
    let n = PER_ROUND as f64;
    let us =
        |f: &dyn Fn(&Round) -> u64| median(rounds.iter().map(|r| f(r) as f64 / n / 1e3).collect());
    let total = us(&|r| r.r.total_ns);
    println!("\n{title} ({ROUNDS} rounds x {PER_ROUND} handshakes, median round)");
    println!("| stage | us / handshake | % | calls / handshake |");
    println!("|---|---|---|---|");
    for (i, s) in Stage::ALL.iter().enumerate() {
        let v = us(&|r| r.r.ns[i]);
        let calls = rounds[0].r.calls[i] as f64 / n;
        if calls == 0.0 {
            continue;
        }
        println!(
            "| {} | {v:.2} | {:.1} | {calls:.1} |",
            s.name(),
            100.0 * v / total
        );
    }
    let rest = us(&|r| r.r.rest_ns());
    println!(
        "| rest: rustls state machine, encoding, copies, allocation | {rest:.2} | {:.1} | |",
        100.0 * rest / total
    );
    println!("| **total (server)** | **{total:.2}** | 100 | |");
    let allocs = median(rounds.iter().map(|r| r.allocs as f64 / n).collect());
    let bytes = median(rounds.iter().map(|r| r.bytes as f64 / n).collect());
    println!(
        "allocations per handshake: {allocs:.0} ({:.1} KiB requested)",
        bytes / 1024.0
    );
}

fn main() {
    let mut p = EntropyPool::new();
    p.add(Source::Rndr, &[42u8; 64]);
    urmqtt_tls::rng::install(p.finish().expect("rng"));
    urmqtt_tls::set_clock(|| {
        Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
        )
    });
    println!("ecc backend: {}", urmqtt_tls::provider::ecc_backend());
    let srv = server();
    let cfg = client_config();
    for _ in 0..50 {
        handshake(&srv, &cfg);
    }
    let mut returning = Vec::new();
    let mut first = Vec::new();
    // Interleaved, so drift affects both cases alike.
    for _ in 0..ROUNDS {
        returning.push(round(&srv, &cfg, false));
        first.push(round(&srv, &cfg, true));
    }
    report(
        "Returning device (certificate signature in the memo)",
        &returning,
    );
    report("First contact (memo cleared before each handshake)", &first);
}
