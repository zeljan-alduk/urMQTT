//! NEXT-7 (ADR-317): without a wall clock the outbound client cannot check
//! the server certificate's validity, and the handshake fails (fail closed).
//! Its own test binary: the clock is a process-wide setting.

use std::path::PathBuf;
use std::sync::Arc;

use urmqtt_tls::client::TlsClient;
use urmqtt_tls::rng::{EntropyPool, Source};
use urmqtt_tls::{IdentityField, RevocationList, ServerSetup, TicketKeys, TlsServer};

#[test]
fn no_wall_clock_no_connection() {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev");
    if !d.join("ca.pem").exists() {
        return eprintln!("no dev certs, run make certs");
    }
    let mut p = EntropyPool::new();
    p.add(Source::Rndr, &[7u8; 64]);
    urmqtt_tls::rng::install(p.finish().unwrap());
    urmqtt_tls::set_clock(|| None);
    let read = |f: &str| std::fs::read(d.join(f)).unwrap();
    let (ca, cert, key) = (read("ca.pem"), read("server.pem"), read("server.key"));
    let srv = TlsServer::new_server_only(&ServerSetup {
        operational_ca_pems: &[&ca],
        bootstrap_ca_pems: &[],
        cert_pem: &cert,
        key_pem: &key,
        identity_field: IdentityField::Cn,
        resumption: false,
        revocations: Arc::new(RevocationList::from_hex(&[])),
        tickets: Arc::new(TicketKeys::new(urmqtt_tls::ticket::INTERVAL_S, || 0)),
    })
    .unwrap();
    let cli = TlsClient::verifying(&[&ca]).unwrap();
    let mut c = cli.connect_to("localhost").unwrap();
    let mut s = srv.accept().unwrap();
    let (mut to_s, mut to_c, mut app) = (Vec::new(), Vec::new(), Vec::new());
    let mut failed = false;
    if c.input(&[], &mut to_s, &mut app).is_err() {
        failed = true;
    }
    for _ in 0..10 {
        if failed {
            break;
        }
        if !to_s.is_empty() {
            let data = std::mem::take(&mut to_s);
            let _ = s.input(&data, &mut to_c, &mut app);
        }
        if !to_c.is_empty() {
            let data = std::mem::take(&mut to_c);
            failed = c.input(&data, &mut to_s, &mut app).is_err();
        }
    }
    assert!(failed, "the handshake must fail without a clock");
    assert!(!c.is_established());
}
