//! Regression tests for the traffic-secret capture (ADR-340; CRYPTO-1 and
//! CRYPTO-2 of the v0.6.0 security review).
//!
//! Until v0.6.0 the server captured each handshake's application traffic
//! secrets in one global table keyed by the ClientHello random. A handshake
//! abandoned after the server's flight (the peer needs no certificate for
//! that) left its entry behind, because a dropped session freed nothing.
//! After 4096 such handshakes every new handshake shared one slot, and any
//! two that overlapped evicted each other: the first failed with "traffic
//! secrets not captured", broker-wide, until reboot. The random was also read
//! from the raw first record, so a ClientHello fragmented over several
//! records (RFC 8446 §5.1) never completed. Each session now has its own
//! capture, dropped with the session.
//!
//! Uses the dev certificates from `make certs`; skipped if they are missing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use urmqtt_tls::rng::{EntropyPool, Source};
use urmqtt_tls::{
    Event, IdentityField, RevocationList, ServerSetup, TicketKeys, TlsError, TlsServer, TlsSession,
};

fn dev() -> Option<PathBuf> {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev");
    d.join("ca.pem").exists().then_some(d)
}

fn setup() {
    if !urmqtt_tls::rng::is_installed() {
        let mut p = EntropyPool::new();
        p.add(Source::Rndr, &[42u8; 64]);
        urmqtt_tls::rng::install(p.finish().unwrap());
    }
    urmqtt_tls::set_clock(|| {
        Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    });
}

fn server(d: &Path) -> TlsServer {
    let ca = std::fs::read(d.join("ca.pem")).unwrap();
    let cert = std::fs::read(d.join("server.pem")).unwrap();
    let key = std::fs::read(d.join("server.key")).unwrap();
    TlsServer::new(&ServerSetup {
        operational_ca_pems: &[&ca],
        bootstrap_ca_pems: &[],
        cert_pem: &cert,
        key_pem: &key,
        identity_field: IdentityField::Cn,
        resumption: false,
        revocations: Arc::new(RevocationList::from_hex(&[])),
        tickets: Arc::new(TicketKeys::new(3600, || 0)),
    })
    .unwrap()
}

fn client_cfg(d: &Path, with_cert: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(d.join("ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let b = ClientConfig::builder_with_provider(Arc::new(urmqtt_tls::provider::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    Arc::new(if with_cert {
        let chain: Vec<_> = CertificateDer::pem_file_iter(d.join("devices/device-001.pem"))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let key = PrivateKeyDer::from_pem_file(d.join("devices/device-001.key")).unwrap();
        b.with_client_auth_cert(chain, key).unwrap()
    } else {
        // A peer without any certificate gets as far as the server flight.
        b.with_no_client_auth()
    })
}

fn c2s(c: &mut ClientConnection) -> Vec<u8> {
    let mut v = Vec::new();
    while c.wants_write() {
        c.write_tls(&mut v).unwrap();
    }
    v
}

fn feed(c: &mut ClientConnection, s2c: &[u8]) {
    let mut rd = s2c;
    while !rd.is_empty() {
        c.read_tls(&mut rd).unwrap();
        c.process_new_packets().unwrap();
    }
}

/// ClientHello in, server flight out: rustls has now logged both application
/// traffic secrets.
fn first_flight(srv: &TlsServer, cfg: &Arc<ClientConfig>) -> (ClientConnection, TlsSession) {
    let mut c =
        ClientConnection::new(cfg.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = srv.accept().unwrap();
    let ch = c2s(&mut c);
    let (mut out, mut app) = (Vec::new(), Vec::new());
    assert_eq!(s.input(&ch, &mut out, &mut app).unwrap(), Event::None);
    assert!(!out.is_empty(), "server flight");
    feed(&mut c, &out);
    (c, s)
}

/// The client's second flight (Certificate, CertificateVerify, Finished).
fn finish(c: &mut ClientConnection, s: &mut TlsSession) -> Result<Event, TlsError> {
    let fl = c2s(c);
    let (mut out, mut app) = (Vec::new(), Vec::new());
    s.input(&fl, &mut out, &mut app)
}

/// Two devices whose handshakes overlap: A's server flight, then B's, then
/// A's and B's Finished.
fn overlapping(
    srv: &TlsServer,
    dev_cfg: &Arc<ClientConfig>,
) -> (Result<Event, TlsError>, Result<Event, TlsError>) {
    let (mut ca, mut sa) = first_flight(srv, dev_cfg);
    let (mut cb, mut sb) = first_flight(srv, dev_cfg);
    (finish(&mut ca, &mut sa), finish(&mut cb, &mut sb))
}

fn established(r: &Result<Event, TlsError>) -> bool {
    matches!(r, Ok(Event::Established { identity, .. }) if identity == "device-001")
}

/// CRYPTO-1: more abandoned handshakes than the former table held (4096),
/// each dropped right after the server flight (what the kernel does on a TCP
/// close, reset or handshake timeout), then overlapping device handshakes and
/// a stranger's ClientHello inside a device's handshake window: all succeed.
/// Before the fix the first of each overlapping pair failed with "traffic
/// secrets not captured".
#[test]
fn abandoned_handshakes_do_not_break_later_overlapping_ones() {
    let Some(d) = dev() else {
        return eprintln!("no dev certs, run make certs");
    };
    setup();
    let srv = server(&d);
    let dev_cfg = client_cfg(&d, true);
    let stranger = client_cfg(&d, false);

    let (a, b) = overlapping(&srv, &dev_cfg);
    assert!(established(&a) && established(&b), "control: {a:?} {b:?}");

    for _ in 0..4097 {
        let (_c, _s) = first_flight(&srv, &stranger);
    }

    for round in 0..3 {
        let (a, b) = overlapping(&srv, &dev_cfg);
        assert!(established(&a), "round {round}: A = {a:?}");
        assert!(established(&b), "round {round}: B = {b:?}");
    }
    let (mut cv, mut sv) = first_flight(&srv, &dev_cfg);
    let (_c, _s) = first_flight(&srv, &stranger);
    let r = finish(&mut cv, &mut sv);
    assert!(established(&r), "victim: {r:?}");
}

/// CRYPTO-2: a ClientHello fragmented over two records completes wherever
/// the split falls (RFC 8446 §5.1). Before the fix every split that left
/// fewer than 38 body bytes in the first record failed at the very end.
#[test]
fn a_fragmented_client_hello_completes() {
    let Some(d) = dev() else {
        return eprintln!("no dev certs, run make certs");
    };
    setup();
    let srv = server(&d);
    let dev_cfg = client_cfg(&d, true);
    for split in [1usize, 6, 20, 37, 38, 100] {
        let mut c =
            ClientConnection::new(dev_cfg.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut s = srv.accept().unwrap();
        let ch = c2s(&mut c);
        assert_eq!(ch[0], 22);
        let body = &ch[5..];
        assert_eq!(body.len(), u16::from_be_bytes([ch[3], ch[4]]) as usize);
        let mut wire = Vec::new();
        for part in [&body[..split], &body[split..]] {
            wire.extend_from_slice(&[22, 3, 1]);
            wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
            wire.extend_from_slice(part);
        }
        let (mut out, mut app) = (Vec::new(), Vec::new());
        assert_eq!(
            s.input(&wire, &mut out, &mut app),
            Ok(Event::None),
            "split {split}"
        );
        feed(&mut c, &out);
        let r = finish(&mut c, &mut s);
        assert!(established(&r), "split at {split}: {r:?}");
    }
}

/// The first bytes still decide "not TLS" early, now after 6 bytes instead
/// of 43: anything that is not a handshake record carrying a ClientHello.
#[test]
fn not_a_client_hello_is_refused_after_six_bytes() {
    let Some(d) = dev() else {
        return eprintln!("no dev certs, run make certs");
    };
    setup();
    let srv = server(&d);
    for bad in [
        &[0x10, 12, 0, 4, b'M', b'Q'][..],
        &[23, 3, 3, 0, 10, 1],
        &[22, 2, 0, 0, 10, 1],
        &[22, 3, 1, 0, 10, 2],
    ] {
        let mut s = srv.accept().unwrap();
        let (mut out, mut app) = (Vec::new(), Vec::new());
        assert_eq!(
            s.input(&bad[..5], &mut out, &mut app),
            Ok(Event::None),
            "{bad:?}: undecided at 5 bytes"
        );
        assert_eq!(
            s.input(&bad[5..], &mut out, &mut app),
            Err(TlsError::NotTls),
            "{bad:?}"
        );
    }
}
