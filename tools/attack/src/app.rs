//! Application-level adversarial clients over the usernet port forward:
//! slowloris at three stages, fragmented TLS records, maximum-size packets,
//! topic and subscription explosion, keepalive abuse, and many identities
//! from one address. Each prints what it did; the broker's bounded response
//! is checked from its serial log in `scripts/smoke.sh`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// One simulated device identity: client id and its TLS configuration.
pub type Identity = (String, Arc<ClientConfig>);

/// `n` device identities issued from the dev CA in `certs_dir`, each with a
/// distinct key and client id, so no two take over each other's session.
pub fn identities(certs_dir: &str, n: usize, prefix: &str) -> Result<Vec<Identity>, String> {
    let read = |f: &str| {
        std::fs::read_to_string(format!("{certs_dir}/{f}")).map_err(|e| format!("{f}: {e}"))
    };
    let ca_pem = read("ca.pem")?;
    let ca_key = rcgen::KeyPair::from_pem(&read("ca.key")?).map_err(|e| format!("ca.key: {e}"))?;
    let issuer =
        rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).map_err(|e| format!("ca.pem: {e}"))?;
    let mut roots = RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(ca_pem.as_bytes()) {
        let c: CertificateDer<'static> = c.map_err(|e| format!("ca.pem: {e}"))?;
        roots.add(c).map_err(|e| format!("ca.pem: {e}"))?;
    }
    let roots = Arc::new(roots);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let id = format!("{prefix}-{i:05}");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| e.to_string())?;
        let mut p =
            rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        p.distinguished_name
            .push(rcgen::DnType::CommonName, id.clone());
        p.subject_alt_names = vec![rcgen::SanType::URI(
            format!("urn:urmqtt:device:{id}")
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        )];
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        p.serial_number = Some(rcgen::SerialNumber::from(
            (i as u64 + 1).to_be_bytes().to_vec(),
        ));
        let cert = p.signed_by(&key, &issuer).map_err(|e| e.to_string())?;
        let mut cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .map_err(|e| e.to_string())?;
        cfg.resumption = rustls::client::Resumption::disabled();
        out.push((id, Arc::new(cfg)));
    }
    Ok(out)
}

fn varint(len: usize) -> Vec<u8> {
    let mut len = len;
    let mut v = Vec::new();
    loop {
        let mut b = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            b |= 0x80;
        }
        v.push(b);
        if len == 0 {
            break;
        }
    }
    v
}

fn connect_packet(client_id: &str, keepalive: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0x02];
    body.extend_from_slice(&keepalive.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut p = vec![0x10];
    p.extend_from_slice(&varint(body.len()));
    p.extend_from_slice(&body);
    p
}

fn publish_packet(topic: &str, payload: &[u8], retain: bool) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + topic.len() + payload.len());
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(payload);
    let mut p = vec![0x30 | u8::from(retain)];
    p.extend_from_slice(&varint(body.len()));
    p.extend_from_slice(&body);
    p
}

fn subscribe_packet(packet_id: u16, filters: &[String]) -> Vec<u8> {
    let mut body = packet_id.to_be_bytes().to_vec();
    for f in filters {
        body.extend_from_slice(&(f.len() as u16).to_be_bytes());
        body.extend_from_slice(f.as_bytes());
        body.push(1); // QoS 1
    }
    let mut p = vec![0x82];
    p.extend_from_slice(&varint(body.len()));
    p.extend_from_slice(&body);
    p
}

fn tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let s = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    Ok(s)
}

/// A full TLS 1.3 handshake and MQTT CONNECT/CONNACK.
fn open(host: &str, port: u16, id: &Identity, keepalive: u16) -> Result<Tls, String> {
    let sock = tcp(host, port)?;
    let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(id.1.clone(), name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(&connect_packet(&id.0, keepalive))
        .map_err(|e| format!("connect: {e}"))?;
    let mut ack = [0u8; 4];
    tls.read_exact(&mut ack)
        .map_err(|e| format!("connack: {e}"))?;
    if ack[0] != 0x20 || ack[3] != 0 {
        return Err(format!("CONNACK refused: {ack:02x?}"));
    }
    Ok(tls)
}

/// Slowloris: open `clients` connections that each reach `stage` and then
/// stall, holding them for `duration`. The broker's per-IP in-flight cap
/// refuses the excess and the handshake timeout reaps the rest; since every
/// connection here shares one source address, that cap is what bounds them.
pub fn slowloris(
    stage: &str,
    host: &str,
    tls_port: u16,
    certs: &str,
    clients: usize,
    duration: u64,
) -> Result<(), String> {
    let mut held: Vec<Box<dyn std::any::Any>> = Vec::new();
    let mut opened = 0usize;
    for i in 0..clients {
        let r = match stage {
            // TCP only: connect and send nothing.
            "tcp" => tcp(host, tls_port).map(|s| Box::new(s) as Box<dyn std::any::Any>),
            // A partial TLS record: a handshake header promising 512 bytes,
            // of which only 4 arrive, so the server buffers and waits.
            "tls" => tcp(host, tls_port).and_then(|mut s| {
                s.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00])
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(s) as Box<dyn std::any::Any>)
            }),
            // Full TLS, then a CONNECT fixed header promising more bytes
            // that never come.
            "mqtt" => {
                let id = identities(certs, 1, &format!("slow-{i}"))?.pop().unwrap();
                let sock = tcp(host, tls_port)?;
                let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
                let conn = ClientConnection::new(id.1.clone(), name).map_err(|e| e.to_string())?;
                let mut tls = StreamOwned::new(conn, sock);
                // 0x10 CONNECT, remaining length 20, but send only 2 bytes.
                match tls.write_all(&[0x10, 20, 0x00, 0x04]) {
                    Ok(()) => Ok(Box::new(tls) as Box<dyn std::any::Any>),
                    Err(e) => Err(e.to_string()),
                }
            }
            other => return Err(format!("unknown slowloris stage {other}")),
        };
        // Refused connections are the expected outcome past the per-IP
        // in-flight cap; keep going.
        if let Ok(h) = r {
            held.push(h);
            opened += 1;
        }
    }
    println!(
        "attack: slowloris-{stage} opened {opened} of {clients} stalled connection(s), \
         {} refused by admission",
        clients - opened
    );
    std::thread::sleep(Duration::from_secs(duration));
    drop(held);
    Ok(())
}

/// Fragmented records: a full session whose TLS flights and MQTT CONNECT
/// reach the socket in tiny chunks with a gap between each, so every TLS
/// record is split across many TCP segments. The broker must reassemble
/// records without buffering without bound, and the CONNECT must still
/// complete well inside the handshake timeout.
pub fn half_records(host: &str, tls_port: u16, certs: &str) -> Result<(), String> {
    let id = identities(certs, 1, "halfrec")?.pop().unwrap();
    let mut sock = tcp(host, tls_port)?;
    let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(id.1.clone(), name).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 8192];
    loop {
        while conn.wants_write() {
            let mut rec = Vec::new();
            conn.write_tls(&mut rec).map_err(|e| e.to_string())?;
            dribble(&mut sock, &rec)?;
        }
        if !conn.is_handshaking() {
            break;
        }
        let n = sock.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("server closed during handshake".into());
        }
        conn.read_tls(&mut &buf[..n]).map_err(|e| e.to_string())?;
        conn.process_new_packets().map_err(|e| e.to_string())?;
    }
    // A CONNECT, also fragmented.
    conn.writer()
        .write_all(&connect_packet(&id.0, 60))
        .map_err(|e| e.to_string())?;
    while conn.wants_write() {
        let mut rec = Vec::new();
        conn.write_tls(&mut rec).map_err(|e| e.to_string())?;
        dribble(&mut sock, &rec)?;
    }
    // Read the CONNACK, re-reading TLS until the reader yields it or a
    // deadline passes (a fragmented session can need several records).
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ack = Vec::new();
    while ack.len() < 4 && Instant::now() < deadline {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                conn.read_tls(&mut &buf[..n]).map_err(|e| e.to_string())?;
                conn.process_new_packets().map_err(|e| e.to_string())?;
                let mut tmp = [0u8; 64];
                if let Ok(m) = conn.reader().read(&mut tmp) {
                    ack.extend_from_slice(&tmp[..m]);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    if ack.len() >= 4 && ack[0] == 0x20 && ack[3] == 0 {
        println!("attack: half-records CONNECT completed in fragments, CONNACK ok");
    } else {
        println!("attack: half-records CONNACK not received ({} byte(s): {ack:02x?})", ack.len());
    }
    Ok(())
}

/// Writes `bytes` to the socket in small chunks, flushing with a short gap
/// between each so TCP delivers them as separate segments.
fn dribble(sock: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    for chunk in bytes.chunks(4) {
        sock.write_all(chunk).map_err(|e| format!("write: {e}"))?;
        sock.flush().ok();
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

/// Maximum-size packets: PUBLISH packets at exactly the configured limit,
/// then one over it, as fast as allowed. The broker enforces the packet
/// size and the per-device publish rate.
pub fn max_packets(
    host: &str,
    tls_port: u16,
    certs: &str,
    max_packet: usize,
    count: u64,
) -> Result<(), String> {
    let id = identities(certs, 1, "maxpkt")?.pop().unwrap();
    let mut tls = open(host, tls_port, &id, 0)?;
    // A topic within the device's own ACL tree; fill the rest with payload.
    let topic = format!("devices/{}/telemetry/x", id.0);
    let overhead = 1 + 4 + 2 + topic.len(); // worst-case fixed header + topic
    let payload = vec![b'A'; max_packet.saturating_sub(overhead)];
    let pkt = publish_packet(&topic, &payload, false);
    let mut sent = 0u64;
    for _ in 0..count {
        if tls.write_all(&pkt).is_err() {
            break;
        }
        sent += 1;
    }
    tls.flush().ok();
    // One packet well past the limit: the broker must close the connection
    // with a protocol error rather than buffer it without bound.
    let big = publish_packet(&topic, &vec![b'B'; max_packet * 2], false);
    let _ = tls.write_all(&big).and_then(|()| tls.flush());
    tls.sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let mut sink = [0u8; 1024];
    let closed = matches!(tls.read(&mut sink), Ok(0) | Err(_));
    println!(
        "attack: max-packets sent {sent} packet(s) of ~{max_packet} B; oversize packet {}",
        if closed {
            "closed the connection"
        } else {
            "was accepted (unexpected)"
        }
    );
    Ok(())
}

/// Topic explosion: one client retains a message on each of many distinct
/// topics. The retained store is bounded per identity, so beyond that bound
/// the broker delivers but does not retain, and the trie must not grow
/// without bound. Publishes are paced just under the device's publish rate
/// (`pace_ms`), so they are not simply dropped by the rate limiter — the
/// point is the retained/trie bound, not the rate bound.
pub fn topic_flood(
    host: &str,
    tls_port: u16,
    certs: &str,
    topics: u64,
    pace_ms: u64,
) -> Result<(), String> {
    let id = identities(certs, 1, "topics")?.pop().unwrap();
    let mut tls = open(host, tls_port, &id, 0)?;
    let mut sent = 0u64;
    for i in 0..topics {
        let topic = format!("devices/{}/telemetry/t{i}", id.0);
        if tls
            .write_all(&publish_packet(&topic, b"x", true))
            .and_then(|()| tls.flush())
            .is_err()
        {
            break;
        }
        sent += 1;
        if pace_ms > 0 {
            std::thread::sleep(Duration::from_millis(pace_ms));
        }
    }
    println!("attack: topic-flood retained {sent} distinct topic(s) from one identity");
    Ok(())
}

/// Subscription explosion: one SUBSCRIBE with far more filters than
/// `max_subscriptions_per_session`. The broker caps the session.
pub fn sub_flood(host: &str, tls_port: u16, certs: &str, filters_n: u64) -> Result<(), String> {
    let id = identities(certs, 1, "subs")?.pop().unwrap();
    let mut tls = open(host, tls_port, &id, 0)?;
    let filters: Vec<String> = (0..filters_n)
        .map(|i| format!("devices/{}/cmd/c{i}", id.0))
        .collect();
    tls.write_all(&subscribe_packet(1, &filters))
        .map_err(|e| format!("subscribe: {e}"))?;
    tls.flush().ok();
    let mut ack = [0u8; 2];
    let closed = tls.read_exact(&mut ack).is_err();
    println!(
        "attack: sub-flood sent SUBSCRIBE with {filters_n} filter(s); server {}",
        if closed {
            "closed the session".to_string()
        } else {
            format!("replied (first bytes {ack:02x?})")
        }
    );
    Ok(())
}

/// Keepalive abuse: connect with a tiny keepalive and flood PINGREQ. The
/// broker answers bounded work, never queues without limit.
pub fn keepalive_abuse(host: &str, tls_port: u16, certs: &str, pings: u64) -> Result<(), String> {
    let id = identities(certs, 1, "ka")?.pop().unwrap();
    let mut tls = open(host, tls_port, &id, 1)?;
    let mut sent = 0u64;
    for _ in 0..pings {
        if tls.write_all(&[0xc0, 0x00]).is_err() {
            break;
        }
        sent += 1;
    }
    tls.flush().ok();
    // Drain whatever PINGRESPs come back within a short window.
    tls.sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let mut sink = [0u8; 4096];
    let mut got = 0usize;
    while let Ok(n) = tls.sock.read(&mut sink) {
        if n == 0 {
            break;
        }
        got += n;
    }
    println!("attack: keepalive-abuse sent {sent} PINGREQ(s), {got} byte(s) back");
    Ok(())
}

/// Many identities from one address: distinct client certificates all
/// connecting from this host. The per-IP in-flight cap and admission bound
/// the concurrency; this reports how many completed.
pub fn many_identities(host: &str, tls_port: u16, certs: &str, n: usize) -> Result<(), String> {
    let ids = identities(certs, n, "ident")?;
    let start = Instant::now();
    let mut ok = 0u64;
    let mut refused = 0u64;
    let mut held = Vec::new();
    for id in &ids {
        match open(host, tls_port, id, 30) {
            Ok(tls) => {
                ok += 1;
                held.push(tls);
            }
            Err(_) => refused += 1,
        }
    }
    println!(
        "attack: identities {ok} connected, {refused} refused, from one address in {} ms",
        start.elapsed().as_millis()
    );
    Ok(())
}
