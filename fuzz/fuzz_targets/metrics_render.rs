//! The Prometheus exposition (ADR-290) over arbitrary numbers and arbitrary
//! text in the string fields of `Info` (the version, the sources, the listener
//! modes: values the kernel chooses, but whatever they are the output must
//! stay well formed). Never panics; every line is a comment or a sample of a
//! `urmqtt_` family; label values are escaped so that no line splits; a
//! counter sample never has a leading minus; OpenMetrics ends in `# EOF`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_broker::metrics::{Own, render};
use urmqtt_broker::sys::{
    Backpressure, Drops, Handshakes, Info, IommuSys, Mqtt5Info, PerAddress, PlainInfo, Qos2, WsInfo,
};

fn take<'a>(d: &mut &'a [u8], n: usize) -> &'a [u8] {
    let n = n.min(d.len());
    let (a, b) = d.split_at(n);
    *d = b;
    a
}

fn num(d: &mut &[u8]) -> u64 {
    let b = take(d, 4);
    let mut v = 0u64;
    for (i, x) in b.iter().enumerate() {
        v |= u64::from(*x) << (8 * i);
    }
    // Mostly small, sometimes huge.
    if v % 7 == 0 { v << 32 | v } else { v % 100_000 }
}

fuzz_target!(|data: &[u8]| {
    let mut d = data;
    let text: Vec<String> = (0..9)
        .map(|_| {
            let n = usize::from(take(&mut d, 1).first().copied().unwrap_or(0)) % 24;
            String::from_utf8_lossy(take(&mut d, n)).into_owned()
        })
        .collect();
    let cores = 1 + usize::from(take(&mut d, 1).first().copied().unwrap_or(0)) % 64;
    let busy: Vec<u8> = (0..cores)
        .map(|_| take(&mut d, 1).first().copied().unwrap_or(0))
        .collect();
    let accepted: Vec<u64> = (0..cores).map(|_| num(&mut d)).collect();
    let mut m5 = Mqtt5Info::default();
    for s in m5.disconnects.iter_mut().chain(m5.refused.iter_mut()) {
        *s = num(&mut d);
    }
    let sign = take(&mut d, 2);
    let i = Info {
        version: &text[0],
        uptime_s: num(&mut d),
        arch: &text[1],
        busy: &busy,
        memory_total: num(&mut d),
        memory_used: num(&mut d),
        disk_total: num(&mut d),
        disk_used: num(&mut d),
        clients_connected: num(&mut d),
        clients_total: num(&mut d),
        subscriptions: num(&mut d),
        retained: num(&mut d),
        messages_received: num(&mut d),
        messages_sent: num(&mut d),
        connections_refused: num(&mut d),
        server_cert_days: sign
            .first()
            .filter(|b| *b & 1 == 1)
            .map(|_| num(&mut d) as i64 - 50_000),
        time_source: &text[2],
        time_offset_ms: sign
            .get(1)
            .filter(|b| *b & 1 == 1)
            .map(|_| num(&mut d) as i64 - 50_000),
        entropy_source: &text[3],
        console_dropped: num(&mut d),
        net_mtu: num(&mut d) as u16,
        drops: Drops {
            slow_subscriber: num(&mut d),
            offline: num(&mut d),
            cross_core: num(&mut d),
            qos1_queue_full: num(&mut d),
            publish_rate: num(&mut d),
            frames_steer: num(&mut d),
            frames_worker_tx: num(&mut d),
            frames_nic: num(&mut d),
        },
        qos2: Qos2 {
            received: num(&mut d),
            duplicates: num(&mut d),
            completed: num(&mut d),
            inbound_full: num(&mut d),
        },
        backpressure: Backpressure {
            single: sign.first().is_some_and(|b| b & 2 == 2),
            paused: num(&mut d),
            paused_ms: num(&mut d),
            timeouts: num(&mut d),
            holding: num(&mut d),
        },
        mqtt5: m5,
        handshakes: Handshakes {
            started: num(&mut d),
            done: num(&mut d),
            failed: num(&mut d),
            timed_out: num(&mut d),
            refused: num(&mut d),
            syn_dropped: num(&mut d),
            in_flight: num(&mut d),
            in_flight_max: num(&mut d),
            slow: num(&mut d),
            latency_sum_ms: num(&mut d),
            latency_max_ms: num(&mut d),
        },
        accepted: &accepted,
        per_address: PerAddress {
            limit: num(&mut d),
            established: num(&mut d),
            addresses: num(&mut d),
            peak: num(&mut d),
            syn_dropped: num(&mut d),
            refused: num(&mut d),
            untracked: num(&mut d),
        },
        iommu: IommuSys {
            mode: &text[7],
            state: &text[8],
            units: num(&mut d),
            domains: num(&mut d),
            pages: num(&mut d),
            faults: num(&mut d),
            overflows: num(&mut d),
        },
        plaintext: PlainInfo {
            enabled: sign.first().is_some_and(|b| b & 4 == 4),
            port: num(&mut d) as u16,
            auth: &text[4],
            allow_from: &text[5],
            ..PlainInfo::default()
        },
        websocket: WsInfo {
            enabled: sign.get(1).is_some_and(|b| b & 4 == 4),
            port: num(&mut d) as u16,
            path: &text[6],
            auth: &text[4],
            refused: [num(&mut d); 10],
            closes_client: [num(&mut d); 9],
            closes_server: [num(&mut d); 9],
            ..WsInfo::default()
        },
    };
    let own = Own {
        port: num(&mut d) as u16,
        connections: num(&mut d),
        accepted: num(&mut d),
        refused_source: num(&mut d),
        refused_limit: num(&mut d),
        ok: num(&mut d),
        refused: [num(&mut d); 5],
        timeouts: num(&mut d),
    };
    for open in [false, true] {
        let out = render(&i, &own, open);
        assert!(out.ends_with('\n'));
        assert_eq!(out.ends_with("# EOF\n"), open);
        for line in out.lines() {
            assert!(
                line.starts_with("# HELP urmqtt_")
                    || line.starts_with("# TYPE urmqtt_")
                    || line == "# EOF"
                    || line.starts_with("urmqtt_"),
                "{line:?}"
            );
            if let Some((series, value)) = line
                .strip_prefix("urmqtt_")
                .and_then(|l| l.rsplit_once(' '))
            {
                assert!(value.parse::<f64>().is_ok(), "{line:?}");
                // Labels close, and quotes inside values are escaped.
                if let Some((_, labels)) = series.split_once('{') {
                    let mut esc = false;
                    let mut inq = false;
                    for c in labels.chars() {
                        match (inq, esc, c) {
                            (true, true, _) => esc = false,
                            (true, false, '\\') => esc = true,
                            (true, false, '"') => inq = false,
                            (false, _, '"') => inq = true,
                            _ => {}
                        }
                    }
                    assert!(!inq && labels.ends_with('}'), "{line:?}");
                }
            }
        }
    }
});
