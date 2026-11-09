//! NEXT-7 (ADR-317): a collector whose certificate chain does not fit one
//! TLS record. rustls joins a handshake message that spans records in the
//! caller's buffer, so the client must hold the whole Certificate message
//! (up to 64 KiB) while the handshake runs; the bound on unfinished input
//! must not refuse it. Uses the dev certificates; skipped without them.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use urmqtt_tls::client::{MAX_PENDING_HANDSHAKE, MAX_PENDING_IN, TlsClient};
use urmqtt_tls::rng::{EntropyPool, Source};

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

/// Runs a handshake between our client and a rustls server whose chain is
/// the server certificate plus `pad` unrelated CA certificates; returns the
/// client's result and the largest unfinished input it had to hold.
fn run(pad: usize) -> (Result<(), urmqtt_tls::TlsError>, usize) {
    let d = dev().unwrap();
    let ca = std::fs::read(d.join("ca.pem")).unwrap();
    let mut chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(d.join("server.pem"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    let extra = CertificateDer::from_pem_file(d.join("ca-2.pem")).unwrap();
    chain.extend(std::iter::repeat_n(extra, pad));
    let key = PrivateKeyDer::from_pem_file(d.join("server.key")).unwrap();
    let cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(urmqtt_tls::provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    let mut srv = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
    let cli = TlsClient::verifying(&[&ca]).unwrap();
    let mut c = cli.connect_to("localhost").unwrap();
    let (mut to_s, mut app) = (Vec::new(), Vec::new());
    c.input(&[], &mut to_s, &mut app).unwrap();
    let mut most = 0;
    for _ in 0..10 {
        if !to_s.is_empty() {
            srv.read_tls(&mut &to_s[..]).unwrap();
            to_s.clear();
            srv.process_new_packets().unwrap();
        }
        let mut to_c = Vec::new();
        while srv.wants_write() {
            srv.write_tls(&mut to_c).unwrap();
        }
        if to_c.is_empty() && to_s.is_empty() {
            break;
        }
        // As TCP would deliver it: a segment at a time.
        for seg in to_c.chunks(1448) {
            if let Err(e) = c.input(seg, &mut to_s, &mut app) {
                return (Err(e), most);
            }
            most = most.max(c.pending_input());
        }
    }
    assert!(c.is_established());
    (Ok(()), most)
}

#[test]
fn a_chain_larger_than_one_record_is_accepted() {
    if dev().is_none() {
        return eprintln!("no dev certs, run make certs");
    }
    setup_globals();
    let (r, _) = run(0);
    r.unwrap();
    // About 40 KiB of certificates: three records' worth.
    let (r, most) = run(60);
    assert!(r.is_ok(), "{r:?}");
    assert!(most > MAX_PENDING_IN, "held {most}");
    // Close to rustls' 64 KiB limit for one handshake message.
    let (r, most) = run(135);
    assert!(r.is_ok(), "{r:?}");
    assert!(most <= MAX_PENDING_HANDSHAKE, "held {most}");
}
