//! The WebSocket frame decoder (ADR-272) against itself: any client byte
//! stream, any message limit, cut into feeds at arbitrary points. It must
//! never panic, never hand out more payload than it was fed, give the same
//! events and the same verdict however the stream is cut, stop for good at a
//! violation or a close, and never let a message exceed its limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_ws::frame::{Config, Decoder, Event, Violation};

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Data(Vec<u8>, bool),
    End(bool),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>, Vec<u8>),
}

fn run(cfg: Config, stream: &[u8], cuts: &[usize]) -> (Vec<Ev>, Option<Violation>, bool, u64) {
    let mut d = Decoder::new(cfg);
    let mut evs: Vec<Ev> = Vec::new();
    let mut buf = stream.to_vec();
    let mut verdict = None;
    let mut message = 0u64;
    let mut longest = 0u64;
    let mut start = 0;
    let mut points: Vec<usize> = cuts.iter().map(|c| c % (stream.len() + 1)).collect();
    points.push(stream.len());
    points.sort_unstable();
    for p in points {
        if p < start {
            continue;
        }
        let r = d.feed(&mut buf[start..p], &mut |e| {
            let e = match e {
                Event::Data { bytes, text } => {
                    assert!(!bytes.is_empty());
                    message += bytes.len() as u64;
                    longest = longest.max(message);
                    if let Some(Ev::Data(v, t)) = evs.last_mut()
                        && *t == text
                    {
                        v.extend_from_slice(bytes);
                        return;
                    }
                    Ev::Data(bytes.to_vec(), text)
                }
                Event::End { text } => {
                    message = 0;
                    Ev::End(text)
                }
                Event::Ping(p) => {
                    assert!(p.len() <= 125);
                    Ev::Ping(p.to_vec())
                }
                Event::Pong(p) => {
                    assert!(p.len() <= 125);
                    Ev::Pong(p.to_vec())
                }
                Event::Close { code, reason } => {
                    assert!(code.is_none_or(urmqtt_ws::frame::valid_close_code));
                    assert!(core::str::from_utf8(reason).is_ok());
                    Ev::Close(code, reason.to_vec())
                }
            };
            evs.push(e);
        });
        if let Err(v) = r {
            assert!(d.is_done());
            verdict.get_or_insert(v);
        }
        start = p;
    }
    let closed = matches!(evs.last(), Some(Ev::Close(..)));
    (evs, verdict, d.is_done() || closed, longest)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let cfg = Config {
        max_message: u64::from(u16::from_le_bytes([data[0], data[1]])),
        text: data[2] & 1 == 1,
    };
    let ncuts = usize::from(data[3] % 8);
    let rest = &data[4..];
    let (cut_bytes, stream) = rest.split_at((ncuts * 2).min(rest.len()));
    let cuts: Vec<usize> = cut_bytes
        .chunks(2)
        .map(|c| usize::from(c[0]) | usize::from(*c.get(1).unwrap_or(&0)) << 8)
        .collect();
    let whole = run(cfg, stream, &[]);
    let pieces = run(cfg, stream, &cuts);
    assert_eq!(whole, pieces, "the cut points changed the result");
    let (evs, _, _, longest) = whole;
    assert!(longest <= cfg.max_message);
    let data_len: usize = evs
        .iter()
        .map(|e| if let Ev::Data(v, _) = e { v.len() } else { 0 })
        .sum();
    assert!(data_len <= stream.len());
    if !cfg.text {
        assert!(
            !evs.iter()
                .any(|e| matches!(e, Ev::Data(_, true) | Ev::End(true)))
        );
    }
});
