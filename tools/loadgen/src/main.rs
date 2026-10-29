//! Host-side load generator for urMQTT (PROMPT §10).
//!
//! Device certificates are generated on the fly from the dev CA
//! (`deploy/dev/ca.pem` + `ca.key`), one identity per simulated device, so
//! no two simulated devices take over each other's session.
//!
//! Modes:
//! - `handshake`: every worker loops TCP connect → full TLS 1.3 handshake
//!   with a client certificate (no resumption) → CONNECT/CONNACK →
//!   DISCONNECT → close. Reports completed connections per second.
//! - `hold`: opens `--clients` connections, keeps them alive with PINGREQ,
//!   optionally publishes QoS 0 every `--publish-ms`, until `--duration`.
//!
//! ```text
//! urmqtt-loadgen handshake --port 18883 --threads 64 --duration 10
//! urmqtt-loadgen hold --port 18883 --clients 500 --duration 30 --publish-ms 1000
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

struct Opts {
    mode: String,
    host: String,
    port: u16,
    certs: String,
    threads: usize,
    clients: usize,
    duration: u64,
    publish_ms: u64,
    prefix: String,
}

fn parse() -> Result<Opts, String> {
    let mut a = std::env::args().skip(1);
    let mode = a
        .next()
        .ok_or("usage: urmqtt-loadgen handshake|hold [options]")?;
    let mut o = Opts {
        mode,
        host: "127.0.0.1".into(),
        port: 8883,
        certs: "deploy/dev".into(),
        threads: 32,
        clients: 64,
        duration: 10,
        publish_ms: 0,
        prefix: "bench".into(),
    };
    while let Some(k) = a.next() {
        let v = a.next().ok_or(format!("{k} needs a value"))?;
        let num = |v: &str| v.parse::<u64>().map_err(|e| format!("{k}: {e}"));
        match k.as_str() {
            "--host" => o.host = v,
            "--port" => o.port = num(&v)? as u16,
            "--certs" => o.certs = v,
            "--threads" => o.threads = num(&v)? as usize,
            "--clients" => o.clients = num(&v)? as usize,
            "--duration" => o.duration = num(&v)?,
            "--publish-ms" => o.publish_ms = num(&v)?,
            "--prefix" => o.prefix = v,
            _ => return Err(format!("unknown option {k}")),
        }
    }
    Ok(o)
}

/// One TLS client configuration per simulated device identity.
fn identities(o: &Opts, n: usize) -> Result<Vec<(String, Arc<ClientConfig>)>, String> {
    let read = |f: &str| {
        std::fs::read_to_string(format!("{}/{f}", o.certs)).map_err(|e| format!("{f}: {e}"))
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
        let id = format!("{}-{i:05}", o.prefix);
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
        // Every connection is a full handshake.
        cfg.resumption = rustls::client::Resumption::disabled();
        out.push((id, Arc::new(cfg)));
    }
    Ok(out)
}

fn connect_packet(client_id: &str, keepalive: u16) -> Vec<u8> {
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0x02];
    body.extend_from_slice(&keepalive.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    let mut p = vec![0x10];
    let mut len = body.len();
    loop {
        let mut b = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            b |= 0x80;
        }
        p.push(b);
        if len == 0 {
            break;
        }
    }
    p.extend_from_slice(&body);
    p
}

fn publish_packet(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x30, (2 + topic.len() + payload.len()) as u8];
    p.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    p.extend_from_slice(topic.as_bytes());
    p.extend_from_slice(payload);
    p
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// TCP + TLS + CONNECT/CONNACK.
fn open(o: &Opts, id: &str, cfg: &Arc<ClientConfig>) -> Result<Tls, String> {
    let tcp = TcpStream::connect((o.host.as_str(), o.port)).map_err(|e| format!("connect: {e}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(cfg.clone(), name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(&connect_packet(id, 60))
        .map_err(|e| format!("tls/connect: {e}"))?;
    let mut ack = [0u8; 4];
    tls.read_exact(&mut ack)
        .map_err(|e| format!("connack: {e}"))?;
    if ack[0] != 0x20 || ack[3] != 0 {
        return Err(format!("CONNACK refused: {ack:02x?}"));
    }
    Ok(tls)
}

fn close(mut tls: Tls) {
    let _ = tls.write_all(&[0xe0, 0x00]);
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(std::net::Shutdown::Write);
    // Wait for the server's FIN on the TCP socket itself (rustls would keep
    // waiting for more records), so the server's session has ended before
    // this identity connects again.
    tls.sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut sink = [0u8; 4096];
    while matches!(tls.sock.read(&mut sink), Ok(n) if n > 0) {}
}

fn handshake(o: &Opts) -> Result<(), String> {
    let ids = Arc::new(identities(o, o.threads)?);
    let done = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let lat_us = Arc::new(AtomicU64::new(0));
    eprintln!(
        "loadgen: {} worker(s), {} identities, {} s",
        o.threads,
        ids.len(),
        o.duration
    );
    let start = Instant::now();
    let workers: Vec<_> = (0..o.threads)
        .map(|t| {
            let (ids, done, errors, stop, lat) = (
                ids.clone(),
                done.clone(),
                errors.clone(),
                stop.clone(),
                lat_us.clone(),
            );
            let o = Opts {
                mode: String::new(),
                host: o.host.clone(),
                certs: String::new(),
                prefix: String::new(),
                ..*o
            };
            std::thread::spawn(move || {
                let (id, cfg) = &ids[t % ids.len()];
                while !stop.load(Ordering::Relaxed) {
                    let t0 = Instant::now();
                    match open(&o, id, cfg) {
                        Ok(tls) => {
                            close(tls);
                            done.fetch_add(1, Ordering::Relaxed);
                            lat.fetch_add(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            if errors.fetch_add(1, Ordering::Relaxed) < 5 {
                                eprintln!("loadgen: {id}: {e}");
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
        })
        .collect();
    let mut last = 0;
    for s in 1..=o.duration {
        std::thread::sleep(Duration::from_secs(1));
        let d = done.load(Ordering::Relaxed);
        eprintln!("loadgen: t={s:3}s {:6} conn/s", d - last);
        last = d;
    }
    stop.store(true, Ordering::Relaxed);
    let secs = start.elapsed().as_secs_f64();
    for w in workers {
        let _ = w.join();
    }
    let d = done.load(Ordering::Relaxed);
    println!(
        "loadgen: handshake: {d} connections in {secs:.1} s = {:.0} conn/s (full TLS 1.3 + mTLS + CONNECT), \
         mean latency {:.1} ms, {} error(s)",
        d as f64 / secs,
        lat_us.load(Ordering::Relaxed) as f64 / d.max(1) as f64 / 1000.0,
        errors.load(Ordering::Relaxed)
    );
    Ok(())
}

fn hold(o: &Opts) -> Result<(), String> {
    let ids = identities(o, o.clients)?;
    let mut conns = Vec::with_capacity(ids.len());
    let t0 = Instant::now();
    for (id, cfg) in &ids {
        match open(o, id, cfg) {
            Ok(t) => conns.push((id.clone(), t)),
            Err(e) => eprintln!("loadgen: {id}: {e}"),
        }
    }
    println!(
        "loadgen: hold: {} of {} connections established in {:.1} s",
        conns.len(),
        ids.len(),
        t0.elapsed().as_secs_f64()
    );
    let end = Instant::now() + Duration::from_secs(o.duration);
    let mut published = 0u64;
    let mut next_ping = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if o.publish_ms > 0 {
            for (id, t) in conns.iter_mut() {
                let topic = format!("devices/{id}/telemetry/load");
                if t.write_all(&publish_packet(&topic, b"42")).is_ok() {
                    published += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(o.publish_ms));
        } else {
            std::thread::sleep(Duration::from_millis(500));
        }
        if Instant::now() >= next_ping {
            for (_, t) in conns.iter_mut() {
                let _ = t.write_all(&[0xc0, 0x00]);
            }
            next_ping += Duration::from_secs(30);
        }
    }
    println!(
        "loadgen: hold: {} connections kept for {} s, {published} QoS 0 publish(es)",
        conns.len(),
        o.duration
    );
    for (_, t) in conns {
        close(t);
    }
    Ok(())
}

fn main() {
    let r = parse().and_then(|o| match o.mode.as_str() {
        "handshake" => handshake(&o),
        "hold" => hold(&o),
        m => Err(format!("unknown mode {m:?} (handshake|hold)")),
    });
    if let Err(e) = r {
        eprintln!("urmqtt-loadgen: {e}");
        std::process::exit(2);
    }
}
