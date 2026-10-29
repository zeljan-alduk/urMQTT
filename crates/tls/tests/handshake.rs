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
use urmqtt_tls::{
    CertRole, Event, IdentityField, RevocationList, ServerSetup, TlsError, TlsServer, TlsSession,
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

fn server(d: &Path, field: IdentityField, revoked: &[&str]) -> TlsServer {
    let ca = read(&d.join("ca.pem"));
    let cert = read(&d.join("server.pem"));
    let key = read(&d.join("server.key"));
    TlsServer::new(&ServerSetup {
        operational_ca_pems: &[&ca],
        bootstrap_ca_pems: &[],
        cert_pem: &cert,
        key_pem: &key,
        identity_field: field,
        resumption: true,
        revocations: Arc::new(RevocationList::from_hex(revoked)),
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

/// A ticket issued before a revocation must not resume afterwards: the new
/// image may carry the same version (M16).
#[test]
fn revoked_device_cannot_resume() {
    let Some(d) = dev() else { return };
    setup_globals();
    let cfg = client_config(&d, "devices/device-002");
    let (_, _, r) = connect(&server(&d, IdentityField::Cn, &[]), cfg.clone());
    assert!(r.is_ok());
    let der = CertificateDer::from_pem_file(d.join("devices/device-002.pem")).unwrap();
    let serial: String = urmqtt_tls::identity::serial(&der)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let srv = server(&d, IdentityField::Cn, &[&serial]);
    let (_, _, r) = connect(&srv, cfg);
    let e = format!("{:?}", r.unwrap_err());
    assert!(
        e.contains("resumed session of a revoked certificate"),
        "{e}"
    );
}

fn server_with(
    d: &Path,
    operational: &[&str],
    bootstrap: &[&str],
    revocations: Arc<RevocationList>,
) -> TlsServer {
    let ops: Vec<Vec<u8>> = operational.iter().map(|f| read(&d.join(f))).collect();
    let boots: Vec<Vec<u8>> = bootstrap.iter().map(|f| read(&d.join(f))).collect();
    let ops: Vec<&[u8]> = ops.iter().map(Vec::as_slice).collect();
    let boots: Vec<&[u8]> = boots.iter().map(Vec::as_slice).collect();
    let cert = read(&d.join("server.pem"));
    let key = read(&d.join("server.key"));
    TlsServer::new(&ServerSetup {
        operational_ca_pems: &ops,
        bootstrap_ca_pems: &boots,
        cert_pem: &cert,
        key_pem: &key,
        identity_field: IdentityField::Cn,
        resumption: true,
        revocations,
        version: "test",
    })
    .unwrap()
}

/// The client trusts the server's CA; its own certificate may come from
/// any CA.
fn client_for(d: &Path, cert: &str) -> Arc<ClientConfig> {
    client_config(d, cert)
}

fn established(r: &Result<Vec<Event>, TlsError>) -> Option<(String, CertRole, u64, bool)> {
    r.as_ref().ok()?.iter().find_map(|e| match e {
        Event::Established {
            identity,
            role,
            serial_tag,
            resumed,
            ..
        } => Some((identity.clone(), *role, *serial_tag, *resumed)),
        _ => None,
    })
}

fn serial_of(d: &Path, cert: &str) -> Vec<u8> {
    let der = CertificateDer::from_pem_file(d.join(format!("{cert}.pem"))).unwrap();
    urmqtt_tls::identity::serial(&der).unwrap()
}

fn has(d: &Path, f: &str) -> bool {
    d.join(f).exists()
}

/// H1: a serial revoked at runtime is refused at the next full handshake
/// and at the next resumption, on the same server.
#[test]
fn runtime_revocation_applies_to_handshakes_and_resumption() {
    let Some(d) = dev() else { return };
    setup_globals();
    let list = Arc::new(RevocationList::new(Vec::new()));
    let srv = server_with(&d, &["ca.pem"], &[], list.clone());
    let cfg = client_for(&d, "devices/device-003");
    let (_, _, r) = connect(&srv, cfg.clone());
    let (_, _, tag, _) = established(&r).expect("first handshake");
    let serial = serial_of(&d, "devices/device-003");
    assert_eq!(tag, urmqtt_tls::serial_tag(&serial));
    // A leading zero (DER sign byte) does not change the tag.
    let mut padded = vec![0u8];
    padded.extend_from_slice(&serial);
    assert_eq!(tag, urmqtt_tls::serial_tag(&padded));

    list.replace(vec![serial]);
    // The client still holds a ticket: resumption must fail too.
    let (_, _, r) = connect(&srv, cfg);
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.contains("revoked"), "{e}");
    let (_, _, r) = connect(&srv, client_for(&d, "devices/device-003"));
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.to_lowercase().contains("revoked"), "{e}");

    list.replace(Vec::new());
    let (_, _, r) = connect(&srv, client_for(&d, "devices/device-003"));
    assert!(established(&r).is_some(), "unrevoked again: {r:?}");
}

/// H1: two operational CAs (rotation with overlap) and a bootstrap CA.
/// Each chain gets its role; a CA that is not configured is refused.
#[test]
fn trust_roles_and_ca_rotation() {
    let Some(d) = dev() else { return };
    if !has(&d, "ca-2.pem") || !has(&d, "ca-bootstrap.pem") {
        return;
    }
    setup_globals();
    let none = || Arc::new(RevocationList::new(Vec::new()));
    let srv = server_with(&d, &["ca.pem", "ca-2.pem"], &["ca-bootstrap.pem"], none());
    for (cert, id, role) in [
        ("devices/device-001", "device-001", CertRole::Operational),
        ("devices/device-005", "device-005", CertRole::Operational),
        ("bootstrap/device-006", "device-006", CertRole::Bootstrap),
    ] {
        let cfg = client_for(&d, cert);
        let (_, _, r) = connect(&srv, cfg.clone());
        let got = established(&r).unwrap_or_else(|| panic!("{cert}: {r:?}"));
        assert_eq!((got.0.as_str(), got.1, got.3), (id, role, false), "{cert}");
        // A resumed session keeps the role.
        let (_, _, r) = connect(&srv, cfg);
        let got = established(&r).unwrap_or_else(|| panic!("{cert} resumed: {r:?}"));
        assert_eq!((got.1, got.3), (role, true), "{cert} resumed");
    }
    // After the rotation the old CA is gone: its devices are refused, also
    // with a ticket from before.
    let rotated = server_with(&d, &["ca-2.pem"], &[], none());
    let (_, _, r) = connect(&rotated, client_for(&d, "devices/device-001"));
    assert!(r.is_err(), "removed CA still accepted");
    // Same ticket key (same server key and version): the ticket itself
    // would be accepted, so this checks that resumption re-verifies.
    let with_ticket = client_for(&d, "devices/device-001");
    let (_, _, r) = connect(&srv, with_ticket.clone());
    assert!(established(&r).is_some());
    let (_, _, r) = connect(&rotated, with_ticket);
    assert!(
        r.is_err(),
        "resumed with a ticket after its CA was removed: {r:?}"
    );
    let (_, _, r) = connect(&rotated, client_for(&d, "devices/device-005"));
    assert!(established(&r).is_some(), "{r:?}");
    // Without a bootstrap role the bootstrap identity is unknown.
    let ops_only = server_with(&d, &["ca.pem"], &[], none());
    let (_, _, r) = connect(&ops_only, client_for(&d, "bootstrap/device-006"));
    assert!(r.is_err(), "bootstrap accepted without a bootstrap anchor");
}
