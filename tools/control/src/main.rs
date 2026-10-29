//! `urmqtt-control`: builds, signs and publishes control messages
//! (docs/SECURITY.md "Control channel", docs/PROVISIONING.md).
//!
//! ```text
//! urmqtt-control revoke   --cert device.pem | --serial HEX  [...]
//! urmqtt-control unrevoke --cert device.pem | --serial HEX  [...]
//! urmqtt-control allow    --id device-001 [...]
//! urmqtt-control disallow --id device-001 [...]
//!
//! signing (one of):
//!   --key control.key          Ed25519 PKCS#8 PEM (dev; keep prod keys offline)
//!   --sign-cmd 'CMD'           the signing input on stdin, the 64-byte
//!                              signature (raw or hex) on stdout: an HSM via
//!                              pkcs11-tool, a cloud KMS CLI, ...
//! message:
//!   --env NAME                 deployment the message is for (required)
//!   --seq N                    sequence number (default: Unix time in ms)
//!   --not-before UNIX          start of validity (default: now - 60 s)
//!   --valid-for S              window length (default: 300 s)
//!   --out FILE                 also write the signed message to FILE
//! publishing (as a control service identity, over mTLS):
//!   --host H --port P          default 127.0.0.1:8883
//!   --ca ca.pem --client-cert operator.pem --client-key operator.key
//!   --client-id ID             default: the certificate's CN
//!   --no-publish               only build and sign (with --out)
//!
//! urmqtt-control publish-file FILE [publishing options]   send a stored message as is
//! urmqtt-control show FILE --pub control.pub --env NAME     verify and print a message
//! ```
//!
//! A PUBACK means the broker received the message, not that it was
//! applied: the broker acknowledges and then authenticates. The outcome is
//! in the broker's log (`control: seq N … applied` or `rejected: reason`)
//! and its statsd counters.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command as Proc, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use urmqtt_control::{Command, Message};

#[derive(Default)]
struct Opts {
    serials: Vec<Vec<u8>>,
    ids: Vec<String>,
    key: Option<String>,
    sign_cmd: Option<String>,
    env: Option<String>,
    seq: Option<u64>,
    not_before: Option<u64>,
    valid_for: u64,
    out: Option<String>,
    host: String,
    port: u16,
    ca: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
    client_id: Option<String>,
    no_publish: bool,
    public_key: Option<String>,
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

fn hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| *c != ':').collect();
    if s.len() % 2 != 0 || s.is_empty() {
        return Err(format!("{s:?}: not a hex serial"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("{s:?}: {e}")))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// The serial number of the (first) certificate in a PEM file.
fn serial_of(path: &str) -> Result<Vec<u8>, String> {
    let certs =
        x509_cert::Certificate::load_pem_chain(&read(path)?).map_err(|e| format!("{path}: {e}"))?;
    let c = certs
        .first()
        .ok_or_else(|| format!("{path}: no certificate"))?;
    Ok(c.tbs_certificate().serial_number().as_bytes().to_vec())
}

fn common_name(path: &str) -> Result<String, String> {
    let certs =
        x509_cert::Certificate::load_pem_chain(&read(path)?).map_err(|e| format!("{path}: {e}"))?;
    let c = certs
        .first()
        .ok_or_else(|| format!("{path}: no certificate"))?;
    let subject = c.tbs_certificate().subject().to_string();
    subject
        .split(',')
        .find_map(|p| p.trim().strip_prefix("CN="))
        .map(String::from)
        .ok_or_else(|| format!("{path}: no CN; pass --client-id"))
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        valid_for: 300,
        host: "127.0.0.1".into(),
        port: 8883,
        ..Opts::default()
    };
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let mut v = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{k} needs a value"))
        };
        match k.as_str() {
            "--serial" => o.serials.push(hex(&v()?)?),
            "--cert" => o.serials.push(serial_of(&v()?)?),
            "--id" => o.ids.push(v()?),
            "--key" => o.key = Some(v()?),
            "--sign-cmd" => o.sign_cmd = Some(v()?),
            "--env" => o.env = Some(v()?),
            "--seq" => o.seq = Some(v()?.parse().map_err(|e| format!("--seq: {e}"))?),
            "--not-before" => {
                o.not_before = Some(v()?.parse().map_err(|e| format!("--not-before: {e}"))?)
            }
            "--valid-for" => o.valid_for = v()?.parse().map_err(|e| format!("--valid-for: {e}"))?,
            "--out" => o.out = Some(v()?),
            "--host" => o.host = v()?,
            "--port" => o.port = v()?.parse().map_err(|e| format!("--port: {e}"))?,
            "--ca" => o.ca = Some(v()?),
            "--client-cert" => o.client_cert = Some(v()?),
            "--client-key" => o.client_key = Some(v()?),
            "--client-id" => o.client_id = Some(v()?),
            "--no-publish" => o.no_publish = true,
            "--pub" => o.public_key = Some(v()?),
            _ => return Err(format!("unknown option {k}")),
        }
    }
    Ok(o)
}

/// The Ed25519 signature over `input`, from the key file or the command.
fn sign(o: &Opts, input: &[u8]) -> Result<[u8; 64], String> {
    match (&o.key, &o.sign_cmd) {
        (Some(path), None) => {
            let seed = urmqtt_control::parse_private_key(&read(path)?)
                .ok_or_else(|| format!("{path}: not an Ed25519 PKCS#8 key (BEGIN PRIVATE KEY)"))?;
            Ok(SigningKey::from_bytes(&seed).sign(input).to_bytes())
        }
        (None, Some(cmd)) => {
            let mut child = Proc::new("/bin/sh")
                .args(["-c", cmd])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| format!("--sign-cmd: {e}"))?;
            child
                .stdin
                .take()
                .ok_or("--sign-cmd: no stdin")?
                .write_all(input)
                .map_err(|e| format!("--sign-cmd: {e}"))?;
            let out = child
                .wait_with_output()
                .map_err(|e| format!("--sign-cmd: {e}"))?;
            if !out.status.success() {
                return Err(format!("--sign-cmd failed: {}", out.status));
            }
            let raw = if out.stdout.len() == 64 {
                out.stdout
            } else {
                hex(String::from_utf8_lossy(&out.stdout).trim())?
            };
            raw.try_into()
                .map_err(|_| "--sign-cmd must print a 64-byte Ed25519 signature".into())
        }
        _ => Err("give exactly one of --key or --sign-cmd".into()),
    }
}

fn build(command: Command, o: &Opts) -> Result<Vec<u8>, String> {
    let env = o.env.as_deref().ok_or("--env is required")?;
    let items: Vec<Vec<u8>> = if command.on_serials() {
        if !o.ids.is_empty() {
            return Err(format!(
                "{} takes --cert or --serial, not --id",
                command.name()
            ));
        }
        o.serials.clone()
    } else {
        if !o.serials.is_empty() {
            return Err(format!(
                "{} takes --id, not --cert or --serial",
                command.name()
            ));
        }
        o.ids.iter().map(|s| s.as_bytes().to_vec()).collect()
    };
    let t = now();
    let not_before = o.not_before.unwrap_or(t.as_secs().saturating_sub(60));
    let m = Message {
        seq: o.seq.unwrap_or(t.as_millis() as u64),
        not_before,
        not_after: not_before + o.valid_for,
        command,
        items,
    };
    let body = urmqtt_control::encode_body(&m).ok_or(
        "invalid message: 1..=64 unique items; serials 1..=20 bytes; ids without / + # NUL or a leading $",
    )?;
    let sig = sign(o, &urmqtt_control::signing_input(env, &body))?;
    let mut wire = body;
    wire.extend_from_slice(&sig);
    eprintln!(
        "urmqtt-control: {} seq {} for env {env}, valid {}..{} ({} item(s): {}), {} bytes",
        command.name(),
        m.seq,
        m.not_before,
        m.not_after,
        m.items.len(),
        m.items
            .iter()
            .map(|i| if command.on_serials() {
                to_hex(i)
            } else {
                String::from_utf8_lossy(i).into_owned()
            })
            .collect::<Vec<_>>()
            .join(" "),
        wire.len()
    );
    Ok(wire)
}

// --- MQTT over TLS, just enough to publish one QoS 1 message --------------

fn remaining_len(mut n: usize, out: &mut Vec<u8>) {
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

fn packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![header];
    remaining_len(body.len(), &mut p);
    p.extend_from_slice(body);
    p
}

fn read_packet(s: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut h = [0u8; 1];
    s.read_exact(&mut h).map_err(|e| format!("read: {e}"))?;
    let (mut len, mut mult) = (0usize, 1usize);
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).map_err(|e| format!("read: {e}"))?;
        len += usize::from(b[0] & 0x7f) * mult;
        if b[0] & 0x80 == 0 {
            break;
        }
        mult *= 128;
        if mult > 128 * 128 * 128 {
            return Err("bad remaining length".into());
        }
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).map_err(|e| format!("read: {e}"))?;
    Ok((h[0], body))
}

fn publish(o: &Opts, payload: &[u8]) -> Result<(), String> {
    let (ca, cert, key) = match (&o.ca, &o.client_cert, &o.client_key) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err("publishing needs --ca, --client-cert and --client-key".into()),
    };
    let id = match &o.client_id {
        Some(i) => i.clone(),
        None => common_name(cert)?,
    };
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&read(ca)?) {
        roots
            .add(c.map_err(|e| format!("{ca}: {e}"))?)
            .map_err(|e| format!("{ca}: {e}"))?;
    }
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{cert}: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(&read(key)?).map_err(|e| format!("{key}: {e}"))?;
    let cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(o.host.clone()).map_err(|e| e.to_string())?;
    let tls = ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect((o.host.as_str(), o.port)).map_err(|e| format!("connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut s = StreamOwned::new(tls, tcp);

    // CONNECT: MQTT 3.1.1, clean session, keepalive 30 s.
    let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 30];
    body.extend_from_slice(&(id.len() as u16).to_be_bytes());
    body.extend_from_slice(id.as_bytes());
    s.write_all(&packet(0x10, &body))
        .map_err(|e| format!("CONNECT: {e}"))?;
    match read_packet(&mut s)? {
        (0x20, b) if b.get(1) == Some(&0) => {}
        (0x20, b) => return Err(format!("CONNACK refused (code {:?})", b.get(1))),
        (h, _) => return Err(format!("expected CONNACK, got packet type {:#x}", h >> 4)),
    }
    // PUBLISH QoS 1, packet id 1.
    let topic = urmqtt_control::TOPIC;
    let mut body = Vec::with_capacity(4 + topic.len() + payload.len());
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(payload);
    s.write_all(&packet(0x32, &body))
        .map_err(|e| format!("PUBLISH: {e}"))?;
    match read_packet(&mut s)? {
        (0x40, b) if b == [0, 1] => {}
        (h, _) => return Err(format!("expected PUBACK, got packet type {:#x}", h >> 4)),
    }
    let _ = s.write_all(&[0xe0, 0]);
    let _ = s.flush();
    eprintln!(
        "urmqtt-control: delivered to {}:{} as {id} (PUBACK); the broker's log shows whether it was applied",
        o.host, o.port
    );
    Ok(())
}

fn show(path: &str, o: &Opts) -> Result<(), String> {
    let env = o.env.as_deref().ok_or("--env is required")?;
    let pubkey = o
        .public_key
        .as_deref()
        .ok_or("--pub control.pub is required")?;
    let key = urmqtt_control::parse_public_key(&read(pubkey)?)
        .ok_or_else(|| format!("{pubkey}: not an Ed25519 public key"))?;
    let m = urmqtt_control::verify(env, &key, &read(path)?)
        .map_err(|r| format!("{path}: rejected: {}", r.reason()))?;
    println!(
        "{} seq {} valid {}..{}: {}",
        m.command.name(),
        m.seq,
        m.not_before,
        m.not_after,
        m.items
            .iter()
            .map(|i| if m.command.on_serials() {
                to_hex(i)
            } else {
                String::from_utf8_lossy(i).into_owned()
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or(
        "usage: urmqtt-control revoke|unrevoke|allow|disallow|publish-file|show [options] (see --help)",
    )?;
    match cmd.as_str() {
        "--help" | "-h" | "help" => {
            print!(
                "{}",
                include_str!("main.rs")
                    .lines()
                    .take_while(|l| l.starts_with("//!"))
                    .map(|l| format!(
                        "{}\n",
                        l.trim_start_matches("//!").strip_prefix(' ').unwrap_or("")
                    ))
                    .collect::<String>()
            );
            Ok(())
        }
        "publish-file" => {
            let (file, rest) = rest.split_first().ok_or("publish-file FILE")?;
            publish(&parse(rest)?, &read(file)?)
        }
        "show" => {
            let (file, rest) = rest.split_first().ok_or("show FILE")?;
            show(file, &parse(rest)?)
        }
        name => {
            let command =
                Command::from_name(name).ok_or_else(|| format!("unknown command {name:?}"))?;
            let o = parse(rest)?;
            let wire = build(command, &o)?;
            if let Some(out) = &o.out {
                std::fs::write(out, &wire).map_err(|e| format!("{out}: {e}"))?;
            }
            if o.no_publish {
                return Ok(());
            }
            publish(&o, &wire)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("urmqtt-control: {e}");
        std::process::exit(1);
    }
}
