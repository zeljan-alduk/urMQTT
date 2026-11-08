//! A WebSocket echo server on the crate's codec, for the Autobahn|Testsuite
//! fuzzing client (docs/audit/ws-autobahn.md). Host only, std, one thread per
//! connection; not part of the kernel.
//!
//!     cargo run --release -p urmqtt-ws --example echo -- 0.0.0.0:9001
//!
//! What it shares with the broker is exactly what Autobahn should test: the
//! request parser (with the broker's checks) and the frame decoder, each
//! violation answered by a close frame with the decoder's code. What it adds
//! is what the broker does not need: Autobahn connects to `/` without a
//! subprotocol, so the example tells the parser the request offered `mqtt`
//! and answers without the header; and Autobahn echoes text, so the example
//! accepts text frames and checks their UTF-8 as the bytes arrive (the broker
//! refuses text frames with 1003).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use urmqtt_ws::frame::{self, Config, Decoder, Event, close, op};
use urmqtt_ws::upgrade::{self, Policy, Scan};

/// Autobahn's largest message is 16 MiB (case 9.1.6, 9.2.6).
const MAX_MESSAGE: u64 = 64 << 20;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into());
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!("echo: listening on {addr}");
    for s in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let _ = s.set_nodelay(true);
            if let Err(e) = serve(s) {
                eprintln!("echo: {e}");
            }
        });
    }
}

/// The message being received.
struct Message {
    data: Vec<u8>,
    text: bool,
    /// Bytes of `data` known to be complete, valid UTF-8 (text only).
    valid: usize,
}

impl Message {
    /// Fail fast: invalid UTF-8 is found as soon as its bytes arrive, not at
    /// the end of the message (Autobahn 6.x).
    fn check_utf8(&mut self, end: bool) -> bool {
        if !self.text {
            return true;
        }
        match std::str::from_utf8(&self.data[self.valid..]) {
            Ok(_) => {
                self.valid = self.data.len();
                true
            }
            Err(e) if e.error_len().is_none() && !end => {
                self.valid += e.valid_up_to();
                true
            }
            Err(_) => false,
        }
    }
}

fn send_frame(s: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let (h, n) = frame::header(opcode, payload.len());
    let mut out = Vec::with_capacity(n + payload.len());
    out.extend_from_slice(&h[..n]);
    out.extend_from_slice(payload);
    s.write_all(&out)
}

fn serve(mut s: TcpStream) -> std::io::Result<()> {
    // The opening handshake.
    let mut req = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let end = loop {
        let n = s.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        req.extend_from_slice(&buf[..n]);
        match upgrade::scan(&req) {
            Scan::Complete { end } => break end,
            Scan::TooLarge => {
                s.write_all(upgrade::Refusal::Malformed.response())?;
                return Ok(());
            }
            Scan::Incomplete => {}
        }
    };
    // Autobahn offers no subprotocol: say it offered mqtt, so the broker's
    // own checks run unchanged on the rest.
    let mut checked = req[..end - 2].to_vec();
    checked.extend_from_slice(b"Sec-WebSocket-Protocol: mqtt\r\n\r\n");
    let policy = Policy {
        path: "/",
        origins: &[],
    };
    let accepted = match upgrade::parse(&checked, &policy) {
        Ok(a) => a,
        Err(r) => {
            s.write_all(r.response())?;
            return Ok(());
        }
    };
    let mut resp = Vec::new();
    resp.extend_from_slice(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
    );
    resp.extend_from_slice(accepted.accept_value());
    resp.extend_from_slice(b"\r\n\r\n");
    s.write_all(&resp)?;

    // Frames.
    let mut dec = Decoder::new(Config {
        max_message: MAX_MESSAGE,
        text: true,
    });
    let mut msg = Message {
        data: Vec::new(),
        text: false,
        valid: 0,
    };
    let mut rest = req[end..].to_vec();
    loop {
        // What to send after this batch, in order.
        let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut fail: Option<u16> = None;
        let mut closing: Option<Option<u16>> = None;
        let r = dec.feed(&mut rest, &mut |e| match e {
            Event::Data { bytes, text } => {
                if fail.is_some() {
                    return;
                }
                if msg.data.is_empty() {
                    msg.text = text;
                }
                msg.data.extend_from_slice(bytes);
                if !msg.check_utf8(false) {
                    fail = Some(close::INVALID_PAYLOAD);
                }
            }
            Event::End { text } => {
                if fail.is_some() {
                    return;
                }
                msg.text = text;
                if !msg.check_utf8(true) {
                    fail = Some(close::INVALID_PAYLOAD);
                    return;
                }
                let opcode = if text { op::TEXT } else { op::BINARY };
                out.push((opcode, std::mem::take(&mut msg.data)));
                msg.valid = 0;
                msg.text = false;
            }
            Event::Ping(p) => out.push((op::PONG, p.to_vec())),
            Event::Pong(_) => {}
            Event::Close { code, .. } => closing = Some(code),
        });
        if let Err(v) = r {
            fail = Some(v.code());
        }
        // Everything in `out` came before the violation or the close (the
        // decoder stops at either): it is answered first.
        for (opcode, payload) in out {
            send_frame(&mut s, opcode, &payload)?;
        }
        if let Some(code) = fail {
            s.write_all(&frame::close_frame(code))?;
            return linger(s);
        }
        if let Some(code) = closing {
            match code {
                Some(c) => s.write_all(&frame::close_frame(c))?,
                None => s.write_all(&frame::CLOSE_EMPTY)?,
            }
            return linger(s);
        }
        let n = s.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        rest = buf[..n].to_vec();
    }
}

/// After our close frame: the server closes TCP first (RFC 6455 7.1.1).
fn linger(s: TcpStream) -> std::io::Result<()> {
    s.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}
