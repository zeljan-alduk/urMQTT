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
//! - `pubsub` (X11): `--publishers P` and `--subscribers S` clients on
//!   `fleet/bench/<k>` topics (`--topics K`: client i uses topic i mod K, so
//!   `P = S = K` makes P independent 1:1 pairs and `P = 1, S = 1000, K = 1` is
//!   a fan-out of 1000). `--qos 0|1`, `--payload` bytes (8 or more; the first
//!   8 carry the send time), `--rate` messages per second per publisher (0:
//!   as fast as the broker lets it, QoS 1 with `--window` messages in
//!   flight). After a connect phase and `--warmup` seconds it measures for
//!   `--duration` seconds: messages sent and acknowledged per second,
//!   deliveries per second and the end-to-end latency (publisher write to
//!   subscriber read, one process, one clock; it includes the round trip
//!   to the broker twice) as p50/p90/p99/max. The last line, `RESULT ...`,
//!   is for scripts. It also reports its own CPU use (Linux), because a
//!   load generator at its CPU budget measures itself.
//!
//! `--mqtt5 1` (ADR-274): `open` speaks MQTT 5.0 (CONNECT and SUBSCRIBE with empty
//! property blocks), e.g. `hold --subscribe 1 --mqtt5 1` to compare the bytes per idle
//! connection with 3.1.1.
//!
//! `--plain 1` (P1): the same modes over the plaintext listener, no TLS and no
//! certificates. The simulated devices are `<prefix>-00000`, ... as client ids;
//! `--user NAME --password PW` log in as one account (password mode), without
//! them the CONNECT carries no credentials (anonymous mode). `handshake` then
//! measures TCP connect + CONNECT/CONNACK per second (a login with a password
//! hash included), and `pubsub` the message path with no record layer.
//!
//! The `handshake` report (PERF, ADR-080) counts the rate over the
//! measurement window only (not the drain of the last connections), gives
//! the latency percentiles of a whole connection (TCP connect, TLS, CONNECT,
//! close), of the TCP connect alone and of the TLS + CONNECT part, and
//! sorts errors by where they happened. `--error-sleep-ms` is the pause
//! after a failed attempt (default 50 ms: an aggressive client; a device
//! with backoff waits seconds) and `--connect-timeout-s` bounds a connect.
//! `--io-timeout-s` (default 10) bounds every read and write while a
//! connection opens; in `storm` the `--retry-s` deadline holds for each
//! attempt, and a round whose threads are still busy a connect timeout plus
//! four I/O timeouts after it fails with an error instead of waiting.
//! `--close server` (default) lets the server close first, so the client keeps
//! no TIME_WAIT; `--close client` is the old order and is limited by the
//! client's ephemeral ports (about 550 connections/s on macOS).
//!
//! ```text
//! urmqtt-loadgen handshake --port 18883 --threads 64 --duration 10
//! urmqtt-loadgen hold --port 18883 --clients 500 --duration 30 --publish-ms 1000
//! urmqtt-loadgen storm --port 18883 --clients 2000 --rounds 3 --retry-s 60
//! urmqtt-loadgen pubsub --port 18883 --prefix svc --publishers 8 --subscribers 8 \
//!     --topics 8 --qos 1 --payload 64 --rate 0 --duration 10
//! urmqtt-loadgen handshake --plain 1 --port 11883 --user bench --password secret
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

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
    /// Read and write timeout of every socket operation while a connection
    /// opens (TLS handshake, CONNACK, SUBACK), seconds.
    io_timeout_s: u64,
    /// The client sends its FIN first (and keeps the TIME_WAIT).
    close_first: bool,
    /// pubsub: publishers, subscribers, topics, QoS, payload bytes, rate
    /// per publisher (0: unlimited), QoS 1 window, warm-up seconds,
    /// concurrent connects.
    publishers: usize,
    subscribers: usize,
    topics: usize,
    qos: u8,
    payload: usize,
    rate: u64,
    window: usize,
    warmup: u64,
    open_par: usize,
    /// CONNECT keep-alive, seconds (`hold` pings every 30 s, but only once all
    /// connections are open: opening 20 000 can take longer than 1.5 x 60 s).
    keepalive: u16,
    /// Plaintext listener, no TLS (P1), and the account to log in as.
    plain: bool,
    /// Speak MQTT 5.0 (CONNECT and SUBSCRIBE with empty property blocks;
    /// ADR-274), e.g. to compare the bytes per idle connection.
    mqtt5: bool,
    user: &'static str,
    password: &'static str,
}

fn parse() -> Result<Opts, String> {
    let mut a = std::env::args().skip(1);
    let mode = a
        .next()
        .ok_or("usage: urmqtt-loadgen handshake|hold|storm|pubsub [options]")?;
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
        io_timeout_s: 10,
        close_first: false,
        publishers: 1,
        subscribers: 1,
        topics: 1,
        qos: 0,
        payload: 64,
        rate: 0,
        window: 32,
        warmup: 2,
        open_par: 32,
        keepalive: 60,
        plain: false,
        mqtt5: false,
        user: "",
        password: "",
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
            "--io-timeout-s" => o.io_timeout_s = num(&v)?.max(1),
            "--publishers" => o.publishers = num(&v)? as usize,
            "--subscribers" => o.subscribers = num(&v)? as usize,
            "--topics" => o.topics = (num(&v)? as usize).max(1),
            "--qos" => o.qos = num(&v)?.min(1) as u8,
            "--payload" => o.payload = (num(&v)? as usize).clamp(8, 60_000),
            "--rate" => o.rate = num(&v)?,
            "--window" => o.window = (num(&v)? as usize).max(1),
            "--warmup" => o.warmup = num(&v)?,
            "--open-par" => o.open_par = (num(&v)? as usize).max(1),
            "--keepalive" => o.keepalive = num(&v)?.min(65535) as u16,
            "--plain" => o.plain = num(&v)? != 0,
            "--mqtt5" => o.mqtt5 = num(&v)? != 0,
            // Leaked once: the options are copied into every thread.
            "--user" => o.user = Box::leak(v.into_boxed_str()),
            "--password" => o.password = Box::leak(v.into_boxed_str()),
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

/// One TLS client configuration per simulated device identity (none with
/// `--plain`: a client id is all a plaintext device has).
fn identities(o: &Opts, n: usize) -> Result<Vec<Identity>, String> {
    if o.plain {
        return Ok((0..n)
            .map(|i| (format!("{}-{i:05}", o.prefix), None))
            .collect());
    }
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
        out.push((id, Some(Arc::new(cfg))));
    }
    Ok(out)
}

fn connect_packet(
    client_id: &str,
    keepalive: u16,
    login: Option<(&str, &str)>,
    v5: bool,
) -> Vec<u8> {
    let flags = if login.is_some() { 0xc2 } else { 0x02 };
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', if v5 { 5 } else { 4 }, flags];
    body.extend_from_slice(&keepalive.to_be_bytes());
    if v5 {
        // No properties.
        body.push(0);
    }
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    if let Some((user, password)) = login {
        for field in [user, password] {
            body.extend_from_slice(&(field.len() as u16).to_be_bytes());
            body.extend_from_slice(field.as_bytes());
        }
    }
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

/// One client connection: TLS, or with `--plain` the bare TCP stream. The
/// methods are the few things the modes do with rustls, so that they do not
/// care which it is.
struct Tls {
    conn: Option<ClientConnection>,
    sock: TcpStream,
    /// Plaintext: what waits for the socket.
    out: Vec<u8>,
}

impl Tls {
    fn wants_write(&self) -> bool {
        self.conn
            .as_ref()
            .map_or(!self.out.is_empty(), |c| c.wants_write())
    }

    /// Queues a packet (the record layer seals it for TLS).
    fn queue(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        match &mut self.conn {
            Some(c) => c.writer().write_all(pkt),
            None => {
                self.out.extend_from_slice(pkt);
                Ok(())
            }
        }
    }

    /// Writes what is queued to the (non-blocking) socket.
    fn push(&mut self) -> std::io::Result<usize> {
        match &mut self.conn {
            Some(c) => c.write_tls(&mut self.sock),
            None => {
                let n = self.sock.write(&self.out)?;
                self.out.drain(..n);
                Ok(n)
            }
        }
    }

    /// Reads from the (non-blocking) socket into `inbuf`; `Ok(0)` is the end.
    fn pull(&mut self, inbuf: &mut Vec<u8>, tmp: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.conn {
            Some(c) => {
                let n = c.read_tls(&mut self.sock)?;
                if n > 0 {
                    c.process_new_packets()
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    while let Ok(m) = c.reader().read(tmp) {
                        if m == 0 {
                            break;
                        }
                        inbuf.extend_from_slice(&tmp[..m]);
                    }
                }
                Ok(n)
            }
            None => {
                let n = self.sock.read(tmp)?;
                inbuf.extend_from_slice(&tmp[..n]);
                Ok(n)
            }
        }
    }

    fn close_notify(&mut self) {
        if let Some(c) = &mut self.conn {
            c.send_close_notify();
        }
    }
}

impl Read for Tls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.conn {
            Some(c) => rustls::Stream::new(c, &mut self.sock).read(buf),
            None => self.sock.read(buf),
        }
    }
}

impl Write for Tls {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.conn {
            Some(c) => rustls::Stream::new(c, &mut self.sock).write(buf),
            None => self.sock.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.conn {
            Some(c) => rustls::Stream::new(c, &mut self.sock).flush(),
            None => self.sock.flush(),
        }
    }
}

/// The TLS configuration of a simulated device (none with `--plain`).
type Cfg = Option<Arc<ClientConfig>>;
/// A simulated device: its client id and TLS configuration.
type Identity = (String, Cfg);

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
fn open(o: &Opts, id: &str, cfg: &Cfg) -> Result<Tls, String> {
    open_timed(o, id, cfg).map(|(t, _)| t)
}

/// [`open`], also returning how long the TCP connect took.
fn open_timed(o: &Opts, id: &str, cfg: &Cfg) -> Result<(Tls, Duration), String> {
    let t_connect = Instant::now();
    let tcp = connect(o)?;
    let connect_time = t_connect.elapsed();
    tcp.set_nodelay(true).ok();
    // A server that accepts and then never answers (or stalls) fails the
    // attempt after `--io-timeout-s` instead of holding the thread.
    let io = Duration::from_secs(o.io_timeout_s);
    tcp.set_read_timeout(Some(io)).ok();
    tcp.set_write_timeout(Some(io)).ok();
    let conn = match cfg {
        Some(cfg) => {
            let name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
            Some(ClientConnection::new(cfg.clone(), name).map_err(|e| e.to_string())?)
        }
        None => None,
    };
    let mut tls = Tls {
        conn,
        sock: tcp,
        out: Vec::new(),
    };
    let login = (!o.user.is_empty()).then_some((o.user, o.password));
    tls.write_all(&connect_packet(id, o.keepalive, login, o.mqtt5))
        .map_err(|e| format!("tls/connect: {e}"))?;
    // CONNACK: a 5.0 one carries properties (one-byte remaining length here).
    let mut head = [0u8; 2];
    tls.read_exact(&mut head)
        .map_err(|e| format!("connack: {e}"))?;
    let mut ack = vec![0u8; usize::from(head[1])];
    tls.read_exact(&mut ack)
        .map_err(|e| format!("connack: {e}"))?;
    if head[0] != 0x20 || ack.get(1) != Some(&0) {
        return Err(format!("CONNACK refused: {head:02x?} {ack:02x?}"));
    }
    if o.subscribe {
        let filter = format!("devices/{id}/cmd/#");
        let v5 = usize::from(o.mqtt5);
        let mut p = vec![0x82, (2 + v5 + 2 + filter.len() + 1) as u8, 0, 1];
        if o.mqtt5 {
            p.push(0);
        }
        p.extend_from_slice(&(filter.len() as u16).to_be_bytes());
        p.extend_from_slice(filter.as_bytes());
        p.push(1);
        tls.write_all(&p).map_err(|e| format!("subscribe: {e}"))?;
        let mut ack = vec![0u8; 5 + v5];
        tls.read_exact(&mut ack)
            .map_err(|e| format!("suback: {e}"))?;
        let want: &[u8] = if o.mqtt5 {
            &[0x90, 4, 0, 1, 0, 1]
        } else {
            &[0x90, 3, 0, 1, 1]
        };
        if ack != want {
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
    tls.close_notify();
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
    let cpu0 = cpu_seconds();
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
    let gen_cpu = (cpu_seconds() - cpu0) / window;
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
    println!("loadgen: handshake: generator cpu {gen_cpu:.2} cores (process total, all threads)");
    println!(
        "RESULT mode=handshake threads={} conn_per_s={:.0} errors={e} lat_p50_ms={:.1} lat_p99_ms={:.1} \
         tcp_p50_ms={:.1} tls_p50_ms={:.1} tls_p99_ms={:.1} gen_cpu={gen_cpu:.2}",
        o.threads,
        d as f64 / window,
        percentile_ms(&total, 50.0),
        percentile_ms(&total, 99.0),
        percentile_ms(&conn, 50.0),
        percentile_ms(&tls_t, 50.0),
        percentile_ms(&tls_t, 99.0),
    );
    Ok(())
}

fn hold(o: &Opts) -> Result<(), String> {
    let ids = identities(o, o.clients)?;
    let t0 = Instant::now();
    // Open in parallel: `--threads` workers each take a share.
    let threads = o.threads.clamp(1, ids.len().max(1));
    let shares: Vec<Vec<Identity>> = (0..threads)
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
    // Sending DISCONNECT and waiting for each FIN one by one would take
    // minutes with tens of thousands of connections.
    for (_, mut t) in conns {
        let _ = t.write_all(&[0xe0, 0x00]);
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
        let (done, results) = std::sync::mpsc::channel::<Vec<Tls>>();
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
                let done = done.clone();
                std::thread::spawn(move || {
                    let mut conns = Vec::new();
                    let mut todo: Vec<usize> = (0..share.len()).collect();
                    let mut backoff = Duration::from_millis(100);
                    while !todo.is_empty() && Instant::now() < deadline {
                        let mut again = Vec::new();
                        for i in todo {
                            // The deadline holds for every attempt, not only
                            // between passes: with SYNs dropped (each attempt
                            // a connect timeout) a pass over a few hundred
                            // devices took many minutes past `--retry-s`.
                            if Instant::now() >= deadline {
                                break;
                            }
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
                    // The receiver is gone only after a watchdog error.
                    let _ = done.send(conns);
                })
            })
            .collect();
        drop(done);
        // Watchdog: an attempt started just before the deadline may still
        // take a connect timeout and one I/O timeout per step (TLS flight,
        // CONNACK, SUBACK); anything longer is a hung server or a hung
        // client, reported instead of waited for (a CI job waited 100 min).
        let grace = Duration::from_secs(o.connect_timeout_s + 4 * o.io_timeout_s + 10);
        let mut conns: Vec<Tls> = Vec::new();
        for _ in 0..handles.len() {
            let left = (deadline + grace).saturating_duration_since(Instant::now());
            match results.recv_timeout(left) {
                Ok(c) => conns.extend(c),
                Err(_) => {
                    let n = handles.iter().filter(|h| !h.is_finished()).count();
                    return Err(format!(
                        "storm round {round}: {n} of {} thread(s) still in an attempt {} s after the \
                         {} s deadline (--io-timeout-s {}): the server stopped answering",
                        handles.len(),
                        grace.as_secs(),
                        o.retry_s,
                        o.io_timeout_s
                    ));
                }
            }
        }
        drop(handles);
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

/// User + system CPU seconds of this process (Linux; 0 elsewhere).
fn cpu_seconds() -> f64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    let rest = s.rsplit_once(')').map_or("", |x| x.1);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tick = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

/// PUBLISH at QoS 0 or 1 with any payload length.
fn publish_qos(topic: &str, qos: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x30 | (qos << 1)];
    let rem = 2 + topic.len() + if qos > 0 { 2 } else { 0 } + payload.len();
    varint(rem, &mut p);
    p.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    p.extend_from_slice(topic.as_bytes());
    if qos > 0 {
        p.extend_from_slice(&id.to_be_bytes());
    }
    p.extend_from_slice(payload);
    p
}

/// One MQTT packet at the front of `buf`: (first byte, packet length,
/// header length), or None if it is not complete yet.
fn next_packet(buf: &[u8]) -> Option<(u8, usize, usize)> {
    let first = *buf.first()?;
    let (mut len, mut mult, mut i) = (0usize, 1usize, 1usize);
    loop {
        let b = *buf.get(i)?;
        len += usize::from(b & 0x7f) * mult;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        mult *= 128;
        if mult > 128 * 128 * 128 {
            return None;
        }
    }
    (buf.len() >= i + len).then_some((first, i + len, i))
}

/// A counting semaphore: how many connects run at once.
struct Gate(std::sync::Mutex<usize>, std::sync::Condvar);

impl Gate {
    fn enter(&self) {
        let mut n = self.0.lock().unwrap_or_else(|e| e.into_inner());
        while *n == 0 {
            n = self.1.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n -= 1;
    }
    fn leave(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.1.notify_one();
    }
}

struct PsShared {
    t0: Instant,
    stop: AtomicBool,
    go: AtomicBool,
    measuring: AtomicBool,
    ready: AtomicU64,
    failed: AtomicU64,
    lost: AtomicU64,
    sent: AtomicU64,
    acked: AtomicU64,
    delivered: AtomicU64,
}

fn ps_open(o: &Opts, sh: &PsShared, gate: &Gate, id: &str, cfg: &Cfg) -> Option<Tls> {
    gate.enter();
    let r = open(o, id, cfg);
    gate.leave();
    match r {
        Ok(t) => Some(t),
        Err(e) => {
            if sh.failed.fetch_add(1, Ordering::Relaxed) < 5 {
                eprintln!("loadgen: {id}: {e}");
            }
            None
        }
    }
}

/// A client lost its connection before the end of the run.
fn lost(sh: &PsShared, id: &str, why: &str) {
    if sh.lost.fetch_add(1, Ordering::Relaxed) < 5 {
        eprintln!(
            "loadgen: lost: {id}: {why} (t={:.1}s)",
            sh.t0.elapsed().as_secs_f64()
        );
    }
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// A subscriber: blocking reads, so the time of a delivery is the time the
/// packet arrived; QoS 1 deliveries are acknowledged at once.
fn ps_subscriber(o: &Opts, sh: &PsShared, gate: &Gate, id: &str, cfg: &Cfg, k: usize) -> Vec<u32> {
    let mut lat = Vec::new();
    let Some(mut tls) = ps_open(o, sh, gate, id, cfg) else {
        return lat;
    };
    let filter = format!("fleet/bench/{k}");
    let mut sub = vec![0x82];
    varint(2 + 2 + filter.len() + 1, &mut sub);
    sub.extend_from_slice(&[0, 1]);
    sub.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    sub.extend_from_slice(filter.as_bytes());
    sub.push(o.qos);
    let mut ack = [0u8; 5];
    if tls.write_all(&sub).is_err()
        || tls.read_exact(&mut ack).is_err()
        || ack[0] != 0x90
        || ack[4] != o.qos
    {
        eprintln!("loadgen: {id}: subscribe failed {ack:02x?}");
        sh.failed.fetch_add(1, Ordering::Relaxed);
        return lat;
    }
    tls.sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    sh.ready.fetch_add(1, Ordering::Relaxed);
    let (mut buf, mut tmp) = (Vec::<u8>::new(), vec![0u8; 65536]);
    let mut acks = Vec::new();
    while !sh.stop.load(Ordering::Relaxed) {
        match tls.read(&mut tmp) {
            Ok(0) => {
                lost(sh, id, "subscriber: closed by the broker");
                return lat;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if would_block(&e) => continue,
            Err(e) => {
                lost(sh, id, &format!("subscriber read: {e}"));
                return lat;
            }
        }
        let now_us = sh.t0.elapsed().as_micros() as u64;
        let mut at = 0;
        acks.clear();
        while let Some((first, len, hl)) = next_packet(&buf[at..]) {
            let pkt = &buf[at..at + len];
            at += len;
            if first >> 4 != 3 {
                continue;
            }
            let body = &pkt[hl..];
            let tl = body
                .first()
                .zip(body.get(1))
                .map_or(0, |(a, b)| usize::from(*a) << 8 | usize::from(*b));
            let mut pos = 2 + tl;
            if (first >> 1) & 3 == 1 {
                if let Some(idb) = body.get(pos..pos + 2) {
                    acks.extend_from_slice(&[0x40, 2, idb[0], idb[1]]);
                }
                pos += 2;
            }
            sh.delivered.fetch_add(1, Ordering::Relaxed);
            if sh.measuring.load(Ordering::Relaxed)
                && lat.len() < 200_000
                && let Some(ts) = body.get(pos..pos + 8)
            {
                let sent = u64::from_be_bytes(ts.try_into().unwrap_or([0; 8]));
                lat.push(now_us.saturating_sub(sent).min(u64::from(u32::MAX)) as u32);
            }
        }
        buf.drain(..at);
        if !acks.is_empty() && tls.write_all(&acks).is_err() {
            lost(sh, id, "subscriber: PUBACK write failed");
            return lat;
        }
    }
    let _ = tls.write_all(&[0xe0, 0x00]);
    lat
}

/// A publisher: non-blocking, so it can keep `--window` QoS 1 messages in
/// flight and send at a fixed rate without a second thread per connection.
fn ps_publisher(o: &Opts, sh: &PsShared, gate: &Gate, id: &str, cfg: &Cfg, k: usize) {
    let Some(mut tls) = ps_open(o, sh, gate, id, cfg) else {
        return;
    };
    tls.sock.set_nonblocking(true).ok();
    sh.ready.fetch_add(1, Ordering::Relaxed);
    while !sh.go.load(Ordering::Relaxed) && !sh.stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let topic = format!("fleet/bench/{k}");
    let mut payload = vec![0x5au8; o.payload];
    let interval = (o.rate > 0).then(|| Duration::from_secs_f64(1.0 / o.rate as f64));
    let (mut next, mut inflight, mut pid) = (Instant::now(), 0usize, 0u16);
    let (mut inbuf, mut tmp) = (Vec::<u8>::new(), vec![0u8; 16384]);
    'run: while !sh.stop.load(Ordering::Relaxed) {
        let mut busy = false;
        // 1. push what rustls holds to the socket
        while tls.wants_write() {
            match tls.push() {
                Ok(0) => break,
                Ok(_) => busy = true,
                Err(e) if would_block(&e) => break,
                Err(_) => break 'run,
            }
        }
        // 2. send, unless the socket is backed up or the window is full
        let mut burst = 0;
        while burst < 64
            && !tls.wants_write()
            && (o.qos == 0 || inflight < o.window)
            && interval.is_none_or(|_| Instant::now() >= next)
        {
            pid = pid.wrapping_add(1).max(1);
            let us = sh.t0.elapsed().as_micros() as u64;
            payload[..8].copy_from_slice(&us.to_be_bytes());
            let pkt = publish_qos(&topic, o.qos, pid, &payload);
            if tls.queue(&pkt).is_err() {
                break 'run;
            }
            if o.qos > 0 {
                inflight += 1;
            }
            sh.sent.fetch_add(1, Ordering::Relaxed);
            if let Some(iv) = interval {
                next += iv;
                let now = Instant::now();
                if next + Duration::from_millis(200) < now {
                    next = now;
                }
            }
            burst += 1;
            busy = true;
            while tls.wants_write() {
                match tls.push() {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        // 3. read acknowledgements (and anything else) without blocking
        match tls.pull(&mut inbuf, &mut tmp) {
            Ok(0) => break 'run,
            Ok(_) => {
                let mut at = 0;
                while let Some((first, len, _)) = next_packet(&inbuf[at..]) {
                    at += len;
                    if first >> 4 == 4 {
                        inflight = inflight.saturating_sub(1);
                        sh.acked.fetch_add(1, Ordering::Relaxed);
                    }
                }
                inbuf.drain(..at);
                busy = true;
            }
            Err(e) if would_block(&e) => {}
            Err(_) => break 'run,
        }
        if !busy {
            let wait = interval.map_or(Duration::from_micros(100), |_| {
                next.saturating_duration_since(Instant::now())
                    .min(Duration::from_micros(500))
            });
            std::thread::sleep(wait.max(Duration::from_micros(50)));
        }
    }
    if !sh.stop.load(Ordering::Relaxed) {
        lost(sh, id, "publisher: connection ended");
    }
}

fn pubsub(o: &Opts) -> Result<(), String> {
    let (np, ns) = (o.publishers, o.subscribers);
    let ids = identities(o, np + ns)?;
    let o2 = Arc::new(Opts {
        mode: String::new(),
        host: o.host.clone(),
        certs: String::new(),
        prefix: String::new(),
        ..*o
    });
    let sh = Arc::new(PsShared {
        t0: Instant::now(),
        stop: AtomicBool::new(false),
        go: AtomicBool::new(false),
        measuring: AtomicBool::new(false),
        ready: AtomicU64::new(0),
        failed: AtomicU64::new(0),
        lost: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        acked: AtomicU64::new(0),
        delivered: AtomicU64::new(0),
    });
    let gate = Arc::new(Gate(
        std::sync::Mutex::new(o.open_par),
        std::sync::Condvar::new(),
    ));
    let mut subs = Vec::new();
    let mut pubs = Vec::new();
    for (i, (id, cfg)) in ids.into_iter().enumerate() {
        let (o2, sh, gate) = (o2.clone(), sh.clone(), gate.clone());
        if i < ns {
            subs.push(std::thread::spawn(move || {
                ps_subscriber(&o2, &sh, &gate, &id, &cfg, i % o2.topics)
            }));
        } else {
            let j = i - ns;
            pubs.push(std::thread::spawn(move || {
                ps_publisher(&o2, &sh, &gate, &id, &cfg, j % o2.topics);
            }));
        }
    }
    let t_conn = Instant::now();
    let total = (np + ns) as u64;
    while sh.ready.load(Ordering::Relaxed) + sh.failed.load(Ordering::Relaxed) < total
        && t_conn.elapsed() < Duration::from_secs(120)
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    let (ready, failed) = (
        sh.ready.load(Ordering::Relaxed),
        sh.failed.load(Ordering::Relaxed),
    );
    println!(
        "loadgen: pubsub: {ready} of {total} clients ready in {:.1} s, {failed} failed",
        t_conn.elapsed().as_secs_f64()
    );
    sh.go.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_secs(o.warmup));
    let (c0, w0) = (cpu_seconds(), Instant::now());
    let (s0, a0, d0) = (
        sh.sent.load(Ordering::Relaxed),
        sh.acked.load(Ordering::Relaxed),
        sh.delivered.load(Ordering::Relaxed),
    );
    sh.measuring.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_secs(o.duration));
    sh.measuring.store(false, Ordering::Relaxed);
    let win = w0.elapsed().as_secs_f64();
    let (c1, s1, a1, d1) = (
        cpu_seconds(),
        sh.sent.load(Ordering::Relaxed),
        sh.acked.load(Ordering::Relaxed),
        sh.delivered.load(Ordering::Relaxed),
    );
    sh.stop.store(true, Ordering::Relaxed);
    let mut lat = Vec::new();
    for h in subs {
        lat.extend(h.join().unwrap_or_default());
    }
    for h in pubs {
        let _ = h.join();
    }
    let (sent, acked, deliv) = (
        (s1 - s0) as f64 / win,
        (a1 - a0) as f64 / win,
        (d1 - d0) as f64 / win,
    );
    let cpu = (c1 - c0) / win;
    let lost = sh.lost.load(Ordering::Relaxed);
    println!(
        "loadgen: pubsub: {np} publisher(s), {ns} subscriber(s), {} topic(s), QoS {}, {} B, rate {}/publisher, window {win:.1} s",
        o.topics,
        o.qos,
        o.payload,
        if o.rate == 0 {
            "max".into()
        } else {
            o.rate.to_string()
        },
    );
    println!(
        "loadgen: pubsub: published {sent:.0}/s, acknowledged {acked:.0}/s, delivered {deliv:.0}/s, lost connections {lost}"
    );
    println!("{}", latency_line("end-to-end latency", &mut lat));
    println!("loadgen: pubsub: generator cpu {cpu:.2} cores (process total, all threads)");
    let q = |p: f64| percentile_ms(&lat, p);
    println!(
        "RESULT mode=pubsub pubs={np} subs={ns} topics={} qos={} payload={} rate={} sent_per_s={sent:.0} acked_per_s={acked:.0} \
         delivered_per_s={deliv:.0} lat_p50_ms={:.2} lat_p90_ms={:.2} lat_p99_ms={:.2} lat_max_ms={:.2} samples={} gen_cpu={cpu:.2} \
         ready={ready} failed={failed} lost={lost}",
        o.topics,
        o.qos,
        o.payload,
        o.rate,
        q(50.0),
        q(90.0),
        q(99.0),
        q(100.0),
        lat.len(),
    );
    Ok(())
}

fn main() {
    let r = parse().and_then(|o| match o.mode.as_str() {
        "handshake" => handshake(&o),
        "hold" => hold(&o),
        "storm" => storm(&o),
        "pubsub" => pubsub(&o),
        m => Err(format!("unknown mode {m:?} (handshake|hold|storm|pubsub)")),
    });
    if let Err(e) = r {
        eprintln!("urmqtt-loadgen: {e}");
        std::process::exit(2);
    }
}
