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
//!   With `--subscribe 1` every device subscribes to its own command tree
//!   (`devices/<id>/cmd/#`, QoS 1) like a real device.
//!
//! - `storm`: `--rounds` reconnect storms. Every round all `--clients`
//!   connect at once (retrying refused connections for up to `--retry-s`
//!   seconds, like devices with backoff), then all drop their connections
//!   at once without DISCONNECT. Reports per round how many connected, how
//!   many attempts were refused and how long the round took; fails if a
//!   round connects fewer than `--min-connected`.
//!
//! The `handshake` report (PERF, ADR-080) counts the rate over the
//! measurement window only (not the drain of the last connections), gives
//! the latency percentiles of a whole connection (TCP connect, TLS, CONNECT,
//! close), of the TCP connect alone and of the TLS + CONNECT part, and
//! sorts errors by where they happened. `--error-sleep-ms` is the pause
//! after a failed attempt (default 50 ms: an aggressive client; a device
//! with backoff waits seconds) and `--connect-timeout-s` bounds a connect.
//! `--close server` (default) lets the server close first, so the client keeps
//! no TIME_WAIT; `--close client` is the old order and is limited by the
//! client's ephemeral ports (about 550 connections/s on macOS).
//!
//! ```text
//! urmqtt-loadgen handshake --port 18883 --threads 64 --duration 10
//! urmqtt-loadgen hold --port 18883 --clients 500 --duration 30 --publish-ms 1000
//! urmqtt-loadgen storm --port 18883 --clients 2000 --rounds 3 --retry-s 60
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
    subscribe: bool,
    rounds: u64,
    retry_s: u64,
    min_connected: u64,
    prefix: String,
    /// Pause after a failed attempt, ms.
    error_sleep_ms: u64,
    /// Connect timeout, seconds (0: the operating system's).
    connect_timeout_s: u64,
    /// The client sends its FIN first (and keeps the TIME_WAIT).
    close_first: bool,
}

fn parse() -> Result<Opts, String> {
    let mut a = std::env::args().skip(1);
    let mode = a
        .next()
        .ok_or("usage: urmqtt-loadgen handshake|hold|storm [options]")?;
    let mut o = Opts {
        mode,
        host: "127.0.0.1".into(),
        port: 8883,
        certs: "deploy/dev".into(),
        threads: 32,
        clients: 64,
        duration: 10,
        publish_ms: 0,
        subscribe: false,
        rounds: 3,
        retry_s: 60,
        min_connected: 0,
        prefix: "bench".into(),
        error_sleep_ms: 50,
        connect_timeout_s: 0,
        close_first: false,
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
            "--subscribe" => o.subscribe = num(&v)? != 0,
            "--rounds" => o.rounds = num(&v)?,
            "--retry-s" => o.retry_s = num(&v)?,
            "--min-connected" => o.min_connected = num(&v)?,
            "--prefix" => o.prefix = v,
            "--error-sleep-ms" => o.error_sleep_ms = num(&v)?,
            "--connect-timeout-s" => o.connect_timeout_s = num(&v)?,
            "--close" => match v.as_str() {
                "client" => o.close_first = true,
                "server" => o.close_first = false,
                _ => return Err("--close: client|server".into()),
            },
            _ => return Err(format!("unknown option {k}")),
        }
    }
    // A device gives up on a connect that gets no answer and tries again
    // later; a server that drops SYNs when it is full (ADR-080) must not
    // leave the storm threads in the operating system's 75 s connect.
    if o.mode == "storm" && o.connect_timeout_s == 0 {
        o.connect_timeout_s = 3;
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
/// A simulated device: its client id and TLS configuration.
type Identity = (String, Arc<ClientConfig>);

/// TCP connect, with the `--connect-timeout-s` bound if given.
fn connect(o: &Opts) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    if o.connect_timeout_s == 0 {
        return TcpStream::connect((o.host.as_str(), o.port)).map_err(|e| format!("connect: {e}"));
    }
    let addr = (o.host.as_str(), o.port)
        .to_socket_addrs()
        .map_err(|e| format!("connect: {e}"))?
        .next()
        .ok_or("connect: no address")?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(o.connect_timeout_s))
        .map_err(|e| format!("connect: {e}"))
}

/// TCP + TLS + CONNECT/CONNACK.
fn open(o: &Opts, id: &str, cfg: &Arc<ClientConfig>) -> Result<Tls, String> {
    open_timed(o, id, cfg).map(|(t, _)| t)
}

/// [`open`], also returning how long the TCP connect took.
fn open_timed(o: &Opts, id: &str, cfg: &Arc<ClientConfig>) -> Result<(Tls, Duration), String> {
    let t_connect = Instant::now();
    let tcp = connect(o)?;
    let connect_time = t_connect.elapsed();
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
    if o.subscribe {
        let filter = format!("devices/{id}/cmd/#");
        let mut p = vec![0x82, (2 + 2 + filter.len() + 1) as u8, 0, 1];
        p.extend_from_slice(&(filter.len() as u16).to_be_bytes());
        p.extend_from_slice(filter.as_bytes());
        p.push(1);
        tls.write_all(&p).map_err(|e| format!("subscribe: {e}"))?;
        let mut ack = [0u8; 5];
        tls.read_exact(&mut ack)
            .map_err(|e| format!("suback: {e}"))?;
        if ack != [0x90, 3, 0, 1, 1] {
            return Err(format!("SUBACK refused: {ack:02x?}"));
        }
    }
    Ok((tls, connect_time))
}

/// DISCONNECT, close_notify and the end of the TCP connection.
///
/// `client_first`: the client sends its FIN before the server does (the
/// old behaviour). The side that closes first keeps the TIME_WAIT: 30 s on
/// macOS (2 x 15 s) against 16 384 ephemeral ports, which caps a single
/// source at about 550 connections per second, whatever the server does.
/// By default the server closes first (urMQTT keeps no TIME_WAIT) and the
/// client only answers its FIN, so the client's port is free at once.
fn close(mut tls: Tls, client_first: bool) {
    let _ = tls.write_all(&[0xe0, 0x00]);
    tls.conn.send_close_notify();
    let _ = tls.flush();
    if client_first {
        let _ = tls.sock.shutdown(std::net::Shutdown::Write);
    }
    // Wait for the server's FIN on the TCP socket itself (rustls would keep
    // waiting for more records), so the server's session has ended before
    // this identity connects again.
    tls.sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut sink = [0u8; 4096];
    while matches!(tls.sock.read(&mut sink), Ok(n) if n > 0) {}
}

/// Where a failed attempt failed (the prefix of `open`'s error text).
fn error_kind(e: &str) -> usize {
    if e.contains("os error 49") || e.contains("os error 99") {
        // EADDRNOTAVAIL (macOS, Linux): no free ephemeral port left.
        4
    } else if e.starts_with("connect") {
        0
    } else if e.starts_with("tls/connect") {
        1
    } else if e.starts_with("connack") {
        2
    } else {
        3
    }
}

const ERROR_KINDS: [&str; 5] = [
    "connect (no SYN-ACK or refused)",
    "TLS or CONNECT write (reset or alert)",
    "CONNACK (reset or timeout)",
    "other",
    "the client ran out of ephemeral ports (TIME_WAIT: this is the load generator, not the server)",
];

/// The `p`-th percentile (0..=100) of sorted microsecond samples, in ms.
fn percentile_ms(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = (((sorted.len() - 1) as f64) * p / 100.0).round() as usize;
    f64::from(sorted[i.min(sorted.len() - 1)]) / 1000.0
}

fn latency_line(name: &str, samples: &mut [u32]) -> String {
    samples.sort_unstable();
    let mean = samples.iter().map(|&x| f64::from(x)).sum::<f64>() / samples.len().max(1) as f64;
    format!(
        "loadgen: {name}: mean {:.1} ms, p50 {:.1}, p90 {:.1}, p99 {:.1}, max {:.1} ms",
        mean / 1000.0,
        percentile_ms(samples, 50.0),
        percentile_ms(samples, 90.0),
        percentile_ms(samples, 99.0),
        percentile_ms(samples, 100.0)
    )
}

fn handshake(o: &Opts) -> Result<(), String> {
    let ids = Arc::new(identities(o, o.threads)?);
    let done = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    eprintln!(
        "loadgen: {} worker(s), {} identities, {} s",
        o.threads,
        ids.len(),
        o.duration
    );
    let start = Instant::now();
    let workers: Vec<_> = (0..o.threads)
        .map(|t| {
            let (ids, done, errors, stop) =
                (ids.clone(), done.clone(), errors.clone(), stop.clone());
            let o = Opts {
                mode: String::new(),
                host: o.host.clone(),
                certs: String::new(),
                prefix: String::new(),
                ..*o
            };
            // Per thread: whole-connection, connect-only and TLS+CONNECT
            // times in microseconds, completions after the window closed
            // (not counted), and failures by kind.
            std::thread::spawn(move || {
                let (id, cfg) = &ids[t % ids.len()];
                let (mut total, mut conn, mut tls_t) = (Vec::new(), Vec::new(), Vec::new());
                let mut kinds = [0u64; 5];
                while !stop.load(Ordering::Relaxed) {
                    let t0 = Instant::now();
                    match open_timed(&o, id, cfg) {
                        Ok((tls, connect_time)) => {
                            let established = t0.elapsed();
                            close(tls, o.close_first);
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            done.fetch_add(1, Ordering::Relaxed);
                            total.push(t0.elapsed().as_micros() as u32);
                            conn.push(connect_time.as_micros() as u32);
                            tls_t.push(established.saturating_sub(connect_time).as_micros() as u32);
                        }
                        Err(e) => {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            kinds[error_kind(&e)] += 1;
                            if errors.fetch_add(1, Ordering::Relaxed) < 5 {
                                eprintln!("loadgen: {id}: {e}");
                            }
                            std::thread::sleep(Duration::from_millis(o.error_sleep_ms));
                        }
                    }
                }
                (total, conn, tls_t, kinds)
            })
        })
        .collect();
    let mut last = (0, 0);
    for s in 1..=o.duration {
        std::thread::sleep(Duration::from_secs(1));
        let (d, e) = (done.load(Ordering::Relaxed), errors.load(Ordering::Relaxed));
        eprintln!(
            "loadgen: t={s:3}s {:6} conn/s {:6} error(s)",
            d - last.0,
            e - last.1
        );
        last = (d, e);
    }
    // The window closes here; attempts still running are drained and left
    // out of the figures.
    stop.store(true, Ordering::Relaxed);
    let window = start.elapsed().as_secs_f64();
    let (d, e) = (done.load(Ordering::Relaxed), errors.load(Ordering::Relaxed));
    let (mut total, mut conn, mut tls_t) = (Vec::new(), Vec::new(), Vec::new());
    let mut kinds = [0u64; 5];
    for w in workers {
        if let Ok((a, b, c, k)) = w.join() {
            total.extend(a);
            conn.extend(b);
            tls_t.extend(c);
            for (x, y) in kinds.iter_mut().zip(k) {
                *x += y;
            }
        }
    }
    let drained = start.elapsed().as_secs_f64() - window;
    println!(
        "loadgen: handshake: {d} connections in {window:.1} s = {:.0} conn/s (full TLS 1.3 + mTLS + CONNECT), \
         mean latency {:.1} ms, {e} error(s)",
        d as f64 / window,
        total.iter().map(|&x| f64::from(x)).sum::<f64>() / total.len().max(1) as f64 / 1000.0,
    );
    println!("{}", latency_line("whole connection", &mut total));
    println!("{}", latency_line("tcp connect", &mut conn));
    println!("{}", latency_line("tls + connect/connack", &mut tls_t));
    if e > 0 {
        let by: Vec<String> = ERROR_KINDS
            .iter()
            .zip(kinds)
            .filter(|(_, n)| *n > 0)
            .map(|(name, n)| format!("{n} {name}"))
            .collect();
        println!("loadgen: errors by kind: {}", by.join(", "));
    }
    println!("loadgen: drained the last attempts in {drained:.1} s (not counted)");
    Ok(())
}

fn hold(o: &Opts) -> Result<(), String> {
    let ids = identities(o, o.clients)?;
    let t0 = Instant::now();
    // Open in parallel: `--threads` workers each take a share.
    let threads = o.threads.clamp(1, ids.len().max(1));
    let shares: Vec<Vec<(String, Arc<ClientConfig>)>> = (0..threads)
        .map(|t| ids.iter().skip(t).step_by(threads).cloned().collect())
        .collect();
    let opened: Vec<_> = shares
        .into_iter()
        .map(|share| {
            let o = Opts {
                mode: String::new(),
                host: o.host.clone(),
                certs: String::new(),
                prefix: String::new(),
                ..*o
            };
            std::thread::spawn(move || {
                let mut conns = Vec::new();
                for (id, cfg) in share {
                    match open(&o, &id, &cfg) {
                        Ok(t) => conns.push((id, t)),
                        Err(e) => eprintln!("loadgen: {id}: {e}"),
                    }
                }
                conns
            })
        })
        .collect();
    let mut conns: Vec<(String, Tls)> = opened
        .into_iter()
        .flat_map(|h| h.join().unwrap_or_default())
        .collect();
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
        close(t, true);
    }
    Ok(())
}

fn storm(o: &Opts) -> Result<(), String> {
    let ids = identities(o, o.clients)?;
    let threads = o.threads.clamp(1, ids.len().max(1));
    let shares: Vec<Arc<Vec<Identity>>> = (0..threads)
        .map(|t| Arc::new(ids.iter().skip(t).step_by(threads).cloned().collect()))
        .collect();
    let mut failed_rounds = 0;
    for round in 1..=o.rounds {
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(o.retry_s);
        let refused = Arc::new(AtomicU64::new(0));
        let handles: Vec<_> = shares
            .iter()
            .map(|share| {
                let share = share.clone();
                let refused = refused.clone();
                let o = Opts {
                    mode: String::new(),
                    host: o.host.clone(),
                    certs: String::new(),
                    prefix: String::new(),
                    ..*o
                };
                std::thread::spawn(move || {
                    let mut conns = Vec::new();
                    let mut todo: Vec<usize> = (0..share.len()).collect();
                    let mut backoff = Duration::from_millis(100);
                    while !todo.is_empty() && Instant::now() < deadline {
                        let mut again = Vec::new();
                        for i in todo {
                            let Some((id, cfg)) = share.get(i) else {
                                continue;
                            };
                            match open(&o, id, cfg) {
                                Ok(t) => conns.push(t),
                                Err(e) => {
                                    if std::env::var_os("LOADGEN_VERBOSE").is_some() {
                                        eprintln!("loadgen: {id}: {e}");
                                    }
                                    refused.fetch_add(1, Ordering::Relaxed);
                                    again.push(i);
                                }
                            }
                        }
                        todo = again;
                        if !todo.is_empty() {
                            std::thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(2));
                        }
                    }
                    conns
                })
            })
            .collect();
        let conns: Vec<Tls> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect();
        let n = conns.len();
        println!(
            "loadgen: storm round {round}: {n} of {} connected in {:.1} s, {} attempt(s) refused",
            ids.len(),
            t0.elapsed().as_secs_f64(),
            refused.load(Ordering::Relaxed)
        );
        if n < ids.len() {
            failed_rounds += 1;
        }
        if (n as u64) < o.min_connected {
            return Err(format!(
                "storm round {round}: only {n} connected (< {})",
                o.min_connected
            ));
        }
        // Everyone drops at once, without DISCONNECT.
        drop(conns);
        std::thread::sleep(Duration::from_millis(500));
    }
    println!(
        "loadgen: storm: {} round(s), {failed_rounds} incomplete",
        o.rounds
    );
    Ok(())
}

fn main() {
    let r = parse().and_then(|o| match o.mode.as_str() {
        "handshake" => handshake(&o),
        "hold" => hold(&o),
        "storm" => storm(&o),
        m => Err(format!("unknown mode {m:?} (handshake|hold|storm)")),
    });
    if let Err(e) = r {
        eprintln!("urmqtt-loadgen: {e}");
        std::process::exit(2);
    }
}
