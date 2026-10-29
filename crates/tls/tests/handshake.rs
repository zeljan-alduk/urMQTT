//! Full TLS 1.3 + mTLS interop: a stock rustls client (with our provider)
//! against our sans-IO server and in-house record layer. Uses the dev
//! certificates from `make certs`; skipped if they are missing.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use urmqtt_tls::rng::{EntropyPool, Source};
use urmqtt_tls::{Event, IdentityField, ServerSetup, TlsError, TlsServer, TlsSession};

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

fn server(d: &Path, field: IdentityField, revoked: &[&str]) -> TlsServer {
    let ca = read(&d.join("ca.pem"));
    let cert = read(&d.join("server.pem"));
    let key = read(&d.join("server.key"));
    TlsServer::new(&ServerSetup {
        ca_pem: &ca,
        cert_pem: &cert,
        key_pem: &key,
        identity_field: field,
        resumption: true,
        revoked_hex: revoked,
        version: "test",
    })
    .unwrap()
}

fn client_config(d: &Path, cert: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(d.join("ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let chain: Vec<_> = CertificateDer::pem_file_iter(d.join(format!("{cert}.pem")))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_file(d.join(format!("{cert}.key"))).unwrap();
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(urmqtt_tls::provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .unwrap(),
    )
}

/// Pumps bytes between client and server until neither makes progress.
/// Returns server events and application bytes the server received.
fn pump(
    client: &mut ClientConnection,
    server: &mut TlsSession,
    app: &mut Vec<u8>,
) -> Result<Vec<Event>, TlsError> {
    let mut events = Vec::new();
    for _ in 0..50 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).unwrap();
        }
        let mut s2c = Vec::new();
        if !c2s.is_empty() {
            let ev = server.input(&c2s, &mut s2c, app)?;
            if ev != Event::None {
                events.push(ev);
            }
        }
        if s2c.is_empty() && c2s.is_empty() {
            break;
        }
        let mut rd = &s2c[..];
        while !rd.is_empty() {
            client.read_tls(&mut rd).unwrap();
            if let Err(e) = client.process_new_packets() {
                return Err(TlsError::Handshake(format!("client: {e}")));
            }
        }
    }
    Ok(events)
}

fn connect(
    srv: &TlsServer,
    cfg: Arc<ClientConfig>,
) -> (ClientConnection, TlsSession, Result<Vec<Event>, TlsError>) {
    let mut client =
        ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut session = srv.accept().unwrap();
    let mut app = Vec::new();
    let r = pump(&mut client, &mut session, &mut app);
    (client, session, r)
}

#[test]
fn mtls_handshake_app_data_key_update_and_resumption() {
    let Some(d) = dev() else {
        return eprintln!("no dev certs, run make certs");
    };
    setup_globals();
    let srv = server(&d, IdentityField::Cn, &[]);
    let cfg = client_config(&d, "devices/device-001");
    let (mut client, mut session, r) = connect(&srv, cfg.clone());
    let events = r.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, Event::Established { identity, resumed: false, .. } if identity == "device-001")),
        "{events:?}"
    );
    assert!(session.is_established());

    // Client -> server through our record layer.
    let mut app = Vec::new();
    client.writer().write_all(&[0x10u8; 5000]).unwrap();
    pump(&mut client, &mut session, &mut app).unwrap();
    assert_eq!(app, vec![0x10u8; 5000]);

    // Server -> client.
    let mut tx = Vec::new();
    session.send(b"hello from urMQTT", &mut tx).unwrap();
    let mut rd = &tx[..];
    client.read_tls(&mut rd).unwrap();
    client.process_new_packets().unwrap();
    let mut got = [0u8; 17];
    client.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hello from urMQTT");

    // Client-initiated KeyUpdate (requesting ours), then more data both ways.
    client.refresh_traffic_keys().unwrap();
    client.writer().write_all(b"after key update").unwrap();
    let mut app = Vec::new();
    let mut c2s = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut c2s).unwrap();
    }
    let mut s2c = Vec::new();
    session.input(&c2s, &mut s2c, &mut app).unwrap();
    assert_eq!(app, b"after key update");
    assert!(!s2c.is_empty(), "our KeyUpdate response");
    session.send(b"new keys", &mut s2c).unwrap();
    let mut rd = &s2c[..];
    while !rd.is_empty() {
        client.read_tls(&mut rd).unwrap();
        client.process_new_packets().unwrap();
    }
    let mut got = [0u8; 8];
    client.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"new keys");

    // A second connection resumes with the ticket and keeps the identity.
    let (_, _, r) = connect(&srv, cfg);
    let events = r.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, Event::Established { identity, resumed: true, .. } if identity == "device-001")),
        "{events:?}"
    );
}

#[test]
fn rogue_expired_and_revoked_are_rejected() {
    let Some(d) = dev() else { return };
    setup_globals();
    let srv = server(&d, IdentityField::Cn, &[]);
    let (_, _, r) = connect(&srv, client_config(&d, "negative/rogue-device"));
    assert!(r.is_err(), "rogue CA must fail: {r:?}");
    let (_, _, r) = connect(&srv, client_config(&d, "negative/expired-device"));
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.to_lowercase().contains("expired"), "{e}");
    // Revoke device-002 by serial.
    let der = CertificateDer::from_pem_file(d.join("devices/device-002.pem")).unwrap();
    let serial: String = urmqtt_tls::identity::serial(&der)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let srv = server(&d, IdentityField::Cn, &[&serial]);
    let (_, _, r) = connect(&srv, client_config(&d, "devices/device-002"));
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.to_lowercase().contains("revoked"), "{e}");
    // Other devices still work.
    let (_, _, r) = connect(&srv, client_config(&d, "devices/device-003"));
    assert!(r.is_ok());
}

#[test]
fn identity_from_san_uri() {
    let Some(d) = dev() else { return };
    setup_globals();
    let srv = server(&d, IdentityField::SanUri, &[]);
    let (_, _, r) = connect(&srv, client_config(&d, "devices/device-003"));
    assert!(
        r.unwrap()
            .iter()
            .any(|e| matches!(e, Event::Established { identity, .. } if identity == "device-003"))
    );
}

#[test]
fn garbage_is_not_tls() {
    let Some(d) = dev() else { return };
    setup_globals();
    let srv = server(&d, IdentityField::Cn, &[]);
    let mut s = srv.accept().unwrap();
    let r = s.input(
        &[
            0x10, 12, 0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        &mut Vec::new(),
        &mut Vec::new(),
    );
    assert_eq!(r, Err(TlsError::NotTls), "plain MQTT on the TLS port");
}

/// Our own sans-IO client (used by in-kernel self-tests) against our
/// server, entirely in memory.
#[test]
fn own_client_against_own_server() {
    let Some(d) = dev() else { return };
    setup_globals();
    let srv = server(&d, IdentityField::Cn, &[]);
    let (ca, cert, key) = (
        read(&d.join("ca.pem")),
        read(&d.join("devices/device-001.pem")),
        read(&d.join("devices/device-001.key")),
    );
    let cli = urmqtt_tls::client::TlsClient::new(&urmqtt_tls::client::ClientSetup {
        ca_pem: &ca,
        cert_pem: &cert,
        key_pem: &key,
    })
    .unwrap();
    for _ in 0..3 {
        let mut c = cli.connect().unwrap();
        let mut s = srv.accept().unwrap();
        c.send(b"hello");
        let (mut to_s, mut to_c, mut app_s, mut app_c) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        c.input(&[], &mut to_s, &mut app_c).unwrap();
        let mut ident = None;
        for _ in 0..10 {
            if !to_s.is_empty() {
                let data = std::mem::take(&mut to_s);
                if let Event::Established { identity, .. } =
                    s.input(&data, &mut to_c, &mut app_s).unwrap()
                {
                    ident = Some(identity);
                }
            }
            if !to_c.is_empty() {
                let data = std::mem::take(&mut to_c);
                c.input(&data, &mut to_s, &mut app_c).unwrap();
            }
            if app_s == b"hello" {
                break;
            }
        }
        assert_eq!(ident.as_deref(), Some("device-001"));
        assert_eq!(app_s, b"hello");
        s.send(b"world", &mut to_c).unwrap();
        let data = std::mem::take(&mut to_c);
        c.input(&data, &mut to_s, &mut app_c).unwrap();
        assert!(app_c.ends_with(b"world"), "{app_c:?}");
        assert!(c.is_established());
    }
}
