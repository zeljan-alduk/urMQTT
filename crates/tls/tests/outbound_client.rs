//! NEXT-7 (ADR-317): the kernel's outbound TLS client against our own
//! server-only TLS server. The client verifies the server's chain against
//! the configured anchors only, and its name (DNS or IP SAN); it offers no
//! certificate. Uses the dev certificates from `make certs`; skipped if they
//! are missing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use urmqtt_tls::client::{ClientSession, MAX_PENDING_HANDSHAKE, MAX_PENDING_IN, TlsClient};
use urmqtt_tls::rng::{EntropyPool, Source};
use urmqtt_tls::{
    Event, IdentityField, RevocationList, ServerSetup, TicketKeys, TlsError, TlsServer, TlsSession,
};

fn dev() -> Option<PathBuf> {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev");
    d.join("ca.pem").exists().then_some(d)
}

fn setup_globals() {
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

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

fn uptime() -> u64 {
    0
}

fn sink(d: &Path) -> TlsServer {
    let ca = read(&d.join("ca.pem"));
    let cert = read(&d.join("server.pem"));
    let key = read(&d.join("server.key"));
    TlsServer::new_server_only(&ServerSetup {
        operational_ca_pems: &[&ca],
        bootstrap_ca_pems: &[],
        cert_pem: &cert,
        key_pem: &key,
        identity_field: IdentityField::Cn,
        resumption: false,
        revocations: Arc::new(RevocationList::from_hex(&[])),
        tickets: Arc::new(TicketKeys::new(urmqtt_tls::ticket::INTERVAL_S, uptime)),
    })
    .unwrap()
}

/// Runs the handshake; returns the server's application bytes, or the
/// first error of either side (client errors first).
fn handshake(c: &mut ClientSession, s: &mut TlsSession) -> Result<Vec<u8>, (bool, TlsError)> {
    let (mut to_s, mut to_c, mut app_s, mut app_c) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.input(&[], &mut to_s, &mut app_c).map_err(|e| (true, e))?;
    for _ in 0..10 {
        if !to_s.is_empty() {
            let data = std::mem::take(&mut to_s);
            match s.input(&data, &mut to_c, &mut app_s) {
                Ok(Event::Established { .. }) => panic!("the sink saw a client identity"),
                Ok(_) => {}
                Err(e) => return Err((false, e)),
            }
        }
        if !to_c.is_empty() {
            let data = std::mem::take(&mut to_c);
            c.input(&data, &mut to_s, &mut app_c)
                .map_err(|e| (true, e))?;
        }
        if to_s.is_empty() && to_c.is_empty() {
            break;
        }
    }
    Ok(app_s)
}

#[test]
fn verified_by_name_and_by_ip_san_data_flows_and_close_notify_ends_it() {
    let Some(d) = dev() else {
        return eprintln!("no dev certs, run make certs");
    };
    setup_globals();
    let srv = sink(&d);
    let ca = read(&d.join("ca.pem"));
    let cli = TlsClient::verifying(&[&ca]).unwrap();
    for name in ["localhost", "urmqtt.local", "127.0.0.1"] {
        let mut c = cli.connect_to(name).unwrap();
        let mut s = srv.accept().unwrap();
        // Data written before the handshake waits for it.
        let mut early = Vec::new();
        c.write(b"<14>1 early", &mut early).unwrap();
        assert!(early.is_empty());
        assert_eq!(c.pending(), 11);
        handshake(&mut c, &mut s).unwrap();
        assert!(c.is_established() && s.is_established(), "{name}");
        // The queued line went out with the client's Finished.
        let mut tx = Vec::new();
        c.write(b" and more", &mut tx).unwrap();
        assert!(!tx.is_empty());
        let (mut to_c, mut app) = (Vec::new(), Vec::new());
        s.input(&tx, &mut to_c, &mut app).unwrap();
        assert!(app.ends_with(b" and more"), "{name}: {app:?}");
        // close: a close_notify, then nothing more is taken.
        let mut tx = Vec::new();
        c.close(&mut tx).unwrap();
        assert!(c.is_closed());
        assert!(!tx.is_empty());
        let mut more = Vec::new();
        c.write(b"late", &mut more).unwrap();
        assert!(more.is_empty());
        assert_eq!(c.pending(), 0);
    }
}

#[test]
fn a_wrong_name_or_an_unknown_issuer_fails_the_handshake() {
    let Some(d) = dev() else { return };
    setup_globals();
    let srv = sink(&d);
    let ca = read(&d.join("ca.pem"));
    let other_ca = read(&d.join("ca-2.pem"));
    for (anchors, name, why) in [
        (&ca, "example.com", "not valid for name"),
        (&ca, "10.0.2.2", "not valid for name"),
        (&other_ca, "localhost", "UnknownIssuer"),
    ] {
        let cli = TlsClient::verifying(&[anchors]).unwrap();
        let mut c = cli.connect_to(name).unwrap();
        let mut s = srv.accept().unwrap();
        match handshake(&mut c, &mut s) {
            Err((true, TlsError::Handshake(m))) => assert!(m.contains(why), "{name}: {m}"),
            other => panic!("{name}: {other:?}"),
        }
        assert!(!c.is_established());
    }
}

#[test]
fn configuration_errors_are_refused() {
    setup_globals();
    assert!(matches!(
        TlsClient::verifying(&[]),
        Err(TlsError::Config("no trust anchor"))
    ));
    assert!(matches!(
        TlsClient::verifying(&[b"not a pem"]),
        Err(TlsError::Config("no trust anchor"))
    ));
    let Some(d) = dev() else { return };
    let ca = read(&d.join("ca.pem"));
    let cli = TlsClient::verifying(&[&ca]).unwrap();
    assert!(cli.connect_to("not a name!").is_err());
    assert!(cli.connect_to("").is_err());
}

#[test]
fn a_peer_that_is_not_tls_is_cut_off() {
    let Some(d) = dev() else { return };
    setup_globals();
    let ca = read(&d.join("ca.pem"));
    let cli = TlsClient::verifying(&[&ca]).unwrap();
    // Plain text instead of a ServerHello.
    let mut c = cli.connect_to("localhost").unwrap();
    let (mut tx, mut app) = (Vec::new(), Vec::new());
    c.input(&[], &mut tx, &mut app).unwrap();
    assert!(!tx.is_empty(), "a ClientHello");
    assert!(
        c.input(b"HTTP/1.1 400 Bad Request\r\n\r\n", &mut tx, &mut app)
            .is_err()
    );
    // A record header that announces more than a record may hold.
    let mut c = cli.connect_to("localhost").unwrap();
    c.input(&[], &mut tx, &mut app).unwrap();
    let mut huge = vec![22u8, 3, 3, 0xff, 0xff];
    huge.extend(std::iter::repeat_n(0u8, MAX_PENDING_IN));
    assert!(c.input(&huge, &mut tx, &mut app).is_err());
    // Trickled bytes of a plausible record are held, up to the bound.
    let mut c = cli.connect_to("localhost").unwrap();
    c.input(&[], &mut tx, &mut app).unwrap();
    let r = c.input(&[22, 3, 3, 0x40, 0x00], &mut tx, &mut app);
    assert!(r.is_ok(), "{r:?}");
    let mut res = Ok(());
    for _ in 0..(MAX_PENDING_HANDSHAKE / 1024 + 2) {
        res = c.input(&[0u8; 1024], &mut tx, &mut app);
        if res.is_err() {
            break;
        }
    }
    assert!(res.is_err(), "the pending bytes are bounded");
}
