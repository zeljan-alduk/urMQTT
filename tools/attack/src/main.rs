//! Host-side adversarial clients for urMQTT (H3, SECURITY-PLAN). Dev only,
//! never shipped: each attack drives a running dev VM and prints what it
//! sent and saw. The expected outcome — memory within limits, per-core CPU
//! bounded, counters correct — is asserted in `scripts/smoke.sh` against
//! the kernel's own serial log.
//!
//! Two transports:
//! - the usernet TCP port forward, for application-level attacks (slowloris,
//!   fragmented records, oversize packets, topic/subscription explosion,
//!   keepalive abuse, many identities);
//! - a raw layer-2 datagram socket (QEMU `--dgram`), where this tool is the
//!   whole network and injects crafted TCP segments (SYN/ACK/RST floods).
//!
//! ```text
//! urmqtt-attack syn-flood  --dgram 45001:45002 --port 8883 --count 20000 --pps 5000
//! urmqtt-attack slowloris  --stage tls --port 18883 --clients 200 --duration 15
//! urmqtt-attack topic-flood --port 18883 --topics 5000
//! ```

mod app;
mod raw;
mod wire;

use std::time::Duration;

struct Opts {
    mode: String,
    host: String,
    port: u16,
    certs: String,
    clients: usize,
    duration: u64,
    count: u64,
    pps: u64,
    topics: u64,
    pace_ms: u64,
    filters: u64,
    pings: u64,
    max_packet: usize,
    stage: String,
    dgram: Option<(u16, u16)>,
}

fn parse() -> Result<Opts, String> {
    let mut a = std::env::args().skip(1);
    let mode = a.next().ok_or(USAGE)?;
    let mut o = Opts {
        mode,
        host: "127.0.0.1".into(),
        port: 8883,
        certs: "deploy/dev".into(),
        clients: 100,
        duration: 15,
        count: 20_000,
        pps: 5_000,
        topics: 60,
        pace_ms: 60,
        filters: 64,
        pings: 10_000,
        max_packet: 4096,
        stage: "tcp".into(),
        dgram: None,
    };
    while let Some(k) = a.next() {
        let v = a.next().ok_or(format!("{k} needs a value"))?;
        let num = |v: &str| v.parse::<u64>().map_err(|e| format!("{k}: {e}"));
        match k.as_str() {
            "--host" => o.host = v,
            "--port" => o.port = num(&v)? as u16,
            "--certs" => o.certs = v,
            "--clients" => o.clients = num(&v)? as usize,
            "--duration" => o.duration = num(&v)?,
            "--count" => o.count = num(&v)?,
            "--pps" => o.pps = num(&v)?,
            "--topics" => o.topics = num(&v)?,
            "--pace-ms" => o.pace_ms = num(&v)?,
            "--filters" => o.filters = num(&v)?,
            "--pings" => o.pings = num(&v)?,
            "--max-packet" => o.max_packet = num(&v)? as usize,
            "--stage" => o.stage = v,
            "--dgram" => {
                let (l, r) = v.split_once(':').ok_or("--dgram needs LOCAL:REMOTE")?;
                o.dgram = Some((
                    l.parse().map_err(|_| "--dgram LOCAL")?,
                    r.parse().map_err(|_| "--dgram REMOTE")?,
                ));
            }
            _ => return Err(format!("unknown option {k}")),
        }
    }
    Ok(o)
}

const USAGE: &str = "usage: urmqtt-attack \
    syn-flood|ack-flood|rst-flood|slowloris|half-records|max-packets|topic-flood|sub-flood|keepalive-abuse|identities \
    [options]";

fn raw_transport(o: &Opts) -> Result<raw::Transport, String> {
    let (local, remote) = o.dgram.ok_or("this attack needs --dgram LOCAL:REMOTE")?;
    raw::Transport::bring_up(local, remote, Duration::from_secs(30))
}

fn run(o: &Opts) -> Result<(), String> {
    match o.mode.as_str() {
        "syn-flood" => raw_transport(o)?.syn_flood(o.port, o.count, o.pps),
        "ack-flood" => raw_transport(o)?.ack_flood(o.port, o.count, o.pps),
        "rst-flood" => raw_transport(o)?.rst_flood(o.port, o.count, o.pps),
        "slowloris" => app::slowloris(&o.stage, &o.host, o.port, &o.certs, o.clients, o.duration)?,
        "half-records" => app::half_records(&o.host, o.port, &o.certs)?,
        "max-packets" => app::max_packets(&o.host, o.port, &o.certs, o.max_packet, o.count)?,
        "topic-flood" => app::topic_flood(&o.host, o.port, &o.certs, o.topics, o.pace_ms)?,
        "sub-flood" => app::sub_flood(&o.host, o.port, &o.certs, o.filters)?,
        "keepalive-abuse" => app::keepalive_abuse(&o.host, o.port, &o.certs, o.pings)?,
        "identities" => app::many_identities(&o.host, o.port, &o.certs, o.clients)?,
        other => return Err(format!("unknown mode {other}\n{USAGE}")),
    }
    Ok(())
}

fn main() {
    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("urmqtt-attack: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&o) {
        eprintln!("urmqtt-attack: {e}");
        std::process::exit(1);
    }
}
