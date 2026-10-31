//! ADR-090: the asynchronous mode end to end, in a process of its own (the
//! mode is global). Log calls queue; only the consumer core's `service`
//! (or the panic, flush and raw paths) writes; audit lines never wait for
//! a full ring; a drop is counted and reported.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use urmqtt_log::{Level, audit, console_next, console_read, emergency, flush, log, raw};

static CLOCK: AtomicU64 = AtomicU64::new(1_000);

thread_local! {
    static CPU: Cell<usize> = const { Cell::new(0) };
}

fn clock() -> u64 {
    // 1 ms per call: every limiter sees time pass.
    CLOCK.fetch_add(1_000_000, Ordering::SeqCst)
}

fn cpu() -> usize {
    CPU.with(Cell::get)
}

fn lines(cursor: &mut u64) -> Vec<String> {
    let mut out = Vec::new();
    console_read(cursor, usize::MAX, |r| out.push(r.text().to_owned()));
    out
}

#[test]
fn queued_lines_reach_the_console_only_through_the_drain() {
    urmqtt_log::set_clock(clock);
    urmqtt_log::set_cpu(cpu);
    urmqtt_log::enable_console();
    urmqtt_log::enable_records();
    let mut cur = console_next();

    // Before `start`: synchronous, as at boot.
    log(Level::Info, format_args!("boot line"));
    assert_eq!(lines(&mut cur), ["boot line"]);

    urmqtt_log::start(0, true);
    assert!(urmqtt_log::is_async());

    // Three cores log; nothing is written until the consumer runs.
    std::thread::scope(|s| {
        for c in 1..4usize {
            s.spawn(move || {
                CPU.with(|x| x.set(c));
                for i in 0..10 {
                    log(Level::Warn, format_args!("core {c} line {i}"));
                }
            });
        }
    });
    assert!(lines(&mut cur).is_empty(), "log() must not write the sinks");
    assert!(urmqtt_log::pending());

    // A core that is not the consumer drains nothing.
    std::thread::scope(|s| {
        s.spawn(|| {
            CPU.with(|x| x.set(2));
            assert!(!urmqtt_log::service());
        });
    });
    assert!(lines(&mut cur).is_empty());

    // The consumer drains in passes; the console sees every line, once, per
    // core in order.
    let mut got = Vec::new();
    while urmqtt_log::service() {
        got.extend(lines(&mut cur));
    }
    assert_eq!(got.len(), 30);
    for c in 1..4 {
        let mine: Vec<_> = got
            .iter()
            .filter(|l| l.starts_with(&format!("core {c} ")))
            .collect();
        assert_eq!(mine.len(), 10);
        assert!(
            mine.iter()
                .enumerate()
                .all(|(i, l)| **l == format!("core {c} line {i}"))
        );
    }
    assert!(!urmqtt_log::pending());

    // A flood past the ring is dropped (newest), counted and reported; an
    // audit line in the same full ring is still written (synchronously).
    CPU.with(|x| x.set(1));
    for i in 0..100 {
        log(Level::Warn, format_args!("flood {i}"));
    }
    audit(format_args!("audited command"));
    assert_eq!(lines(&mut cur), ["audited command"]);
    CPU.with(|x| x.set(0));
    let mut got = Vec::new();
    while urmqtt_log::service() {
        got.extend(lines(&mut cur));
    }
    let queued = got.iter().filter(|l| l.starts_with("flood ")).count();
    assert_eq!(queued, urmqtt_log::RING_LINES);
    let note = got
        .iter()
        .find(|l| l.starts_with("log: ") && l.contains("dropped"))
        .expect("the drop is reported");
    assert!(
        note.contains(&format!("{} line(s)", 100 - urmqtt_log::RING_LINES)),
        "{note}"
    );

    // The fatal, flush and raw paths write what is queued first.
    log(Level::Error, format_args!("before the fault"));
    assert!(lines(&mut cur).is_empty());
    emergency(format_args!("PANIC\n"));
    assert_eq!(lines(&mut cur), ["before the fault"]);
    log(Level::Error, format_args!("before the marker"));
    raw(format_args!("URMQTT READY\n"));
    assert_eq!(lines(&mut cur), ["before the marker"]);
    log(Level::Error, format_args!("before the power-off"));
    flush();
    assert_eq!(lines(&mut cur), ["before the power-off"]);

    // The syslog records come from the same drained lines.
    let mut texts = Vec::new();
    let lost = urmqtt_log::drain_records(|r| texts.push(r.text().to_owned()));
    assert_eq!(lost, 0);
    for want in [
        "audited command",
        "before the fault",
        "before the power-off",
    ] {
        assert!(texts.iter().any(|t| t == want), "{want} in the records");
    }
    assert!(
        texts
            .iter()
            .any(|t| t.starts_with("log: ") && t.contains("dropped")),
        "the drop note reaches the syslog too"
    );
}
