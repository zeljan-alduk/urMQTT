//! The outbound TLS client (NEXT-7, ADR-317): what a collector or any peer
//! the broker connects to sends back. After the ClientHello, the input is
//! cut into pieces (the first byte of each piece says its length) and fed to
//! the session as the server's bytes. It must never panic, never report a
//! handshake done (no input can produce a certificate from the fuzz CA), and
//! keep what it holds of an unfinished record bounded.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use urmqtt_tls::client::TlsClient;
use urmqtt_tls::rng::{EntropyPool, Source};

/// A CA nobody has the key of (generated once, the key thrown away).
const FUZZ_CA: &[u8] = include_bytes!("tls_client_ca.pem");

fn client() -> &'static TlsClient {
    static C: OnceLock<TlsClient> = OnceLock::new();
    C.get_or_init(|| {
        if !urmqtt_tls::rng::is_installed() {
            let mut p = EntropyPool::new();
            p.add(Source::Rndr, &[0x42; 64]);
            urmqtt_tls::rng::install(p.finish().expect("entropy"));
        }
        // 2027-01-15: inside the fuzz CA's validity.
        urmqtt_tls::set_clock(|| Some(1_800_000_000));
        TlsClient::verifying(&[FUZZ_CA]).expect("the fuzz CA parses")
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, mut rest)) = data.split_first() else {
        return;
    };
    let name = match which % 3 {
        0 => "logsink.test",
        1 => "10.0.2.2",
        _ => "localhost",
    };
    let Ok(mut s) = client().connect_to(name) else {
        return;
    };
    let (mut tx, mut app) = (Vec::new(), Vec::new());
    if s.input(&[], &mut tx, &mut app).is_err() || tx.is_empty() {
        panic!("no ClientHello");
    }
    // Data written before the handshake must wait for it.
    let mut early = Vec::new();
    let _ = s.write(b"<14>1 - - - - - early", &mut early);
    assert!(early.is_empty(), "application data before the handshake");
    while let Some((&len, body)) = rest.split_first() {
        let n = usize::from(len).max(1).min(body.len());
        let (piece, tail) = body.split_at(n);
        rest = tail;
        let before = tx.len();
        let r = s.input(piece, &mut tx, &mut app);
        assert!(
            !s.is_established(),
            "a handshake completed without the fuzz CA's key"
        );
        assert!(app.is_empty(), "application data before the handshake");
        // What the client answers is bounded by what it is sent (alerts).
        assert!(tx.len() - before <= 4096);
        if r.is_err() || s.is_closed() {
            break;
        }
    }
});
