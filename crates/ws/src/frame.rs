//! The RFC 6455 framing (section 5), server side: a streaming decoder for the
//! client's frames and the encoder of the server's.
//!
//! MQTT does not care where frames begin or end (MQTT 3.1.1 section 6: "the
//! receiver MUST NOT assume that MQTT Control Packets are aligned on
//! WebSocket frame boundaries"), so the decoder does not reassemble messages:
//! it unmasks each payload byte in place and hands it on as soon as it
//! arrives ([`Event::Data`]). The only bytes it keeps are a frame header
//! (at most 14) and one control frame's payload (at most 125). Nothing is
//! allocated, so nothing is sized by a length the client chose; a length is
//! checked against the message limit as soon as the header is complete,
//! before a byte of its payload is accepted.
//!
//! Every rule a server must enforce is enforced, with the close code RFC 6455
//! section 7.4.1 gives it ([`Violation::code`]):
//!
//! - every client frame is masked (5.1), 1002;
//! - no reserved bit is set: no extension is ever agreed on (5.2), 1002;
//! - known opcodes only (5.2), 1002;
//! - a control frame is not fragmented and carries at most 125 bytes (5.5),
//!   1002; control frames may come between the fragments of a message (5.4);
//! - a continuation frame continues a message, and a new data frame does not
//!   start inside one (5.4), 1002;
//! - a 64-bit length has its top bit clear, and every length uses the
//!   shortest encoding (5.2), 1002;
//! - a close frame's payload is empty or a valid code and a UTF-8 reason
//!   (5.5.1, 7.4), 1002 or 1007;
//! - a message is at most [`Config::max_message`] bytes, 1009;
//! - text frames: refused with 1003 unless [`Config::text`] (MQTT is binary;
//!   only the conformance echo server accepts them, and checks their UTF-8
//!   itself).

/// Opcodes (RFC 6455 5.2).
pub mod op {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xa;
}

/// Close codes the server sends (RFC 6455 7.4.1).
pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED_DATA: u16 = 1003;
    pub const INVALID_PAYLOAD: u16 = 1007;
    pub const POLICY: u16 = 1008;
    pub const TOO_BIG: u16 = 1009;
    pub const INTERNAL: u16 = 1011;
}

/// The largest payload of a control frame (RFC 6455 5.5).
pub const MAX_CONTROL: usize = 125;
/// The largest server frame header: 2 bytes, 8 of length, no mask.
pub const MAX_HEADER: usize = 10;

/// How the decoder behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The largest message (the payloads of a data frame and its
    /// continuations), in bytes. A frame whose length alone exceeds it is
    /// refused at its header.
    pub max_message: u64,
    /// Accept text frames (the conformance echo server). The broker does not.
    pub text: bool,
}

/// A protocol violation by the client: the connection must be closed with
/// [`Violation::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    Unmasked,
    ReservedBits,
    UnknownOpcode,
    ControlTooLong,
    ControlFragmented,
    /// A continuation frame without a message to continue.
    StrayContinuation,
    /// A data frame while a fragmented message is still open.
    MessageInterleaved,
    /// A length with its top bit set, or not in its shortest form.
    BadLength,
    /// A close payload of one byte, or a code a peer may not send.
    BadCloseCode,
    /// A close reason that is not UTF-8.
    BadCloseReason,
    /// Text in a text frame, and text is not accepted.
    Text,
    TooBig,
}

impl Violation {
    pub const ALL: [Self; 12] = [
        Self::Unmasked,
        Self::ReservedBits,
        Self::UnknownOpcode,
        Self::ControlTooLong,
        Self::ControlFragmented,
        Self::StrayContinuation,
        Self::MessageInterleaved,
        Self::BadLength,
        Self::BadCloseCode,
        Self::BadCloseReason,
        Self::Text,
        Self::TooBig,
    ];

    /// The close code to answer with.
    pub const fn code(self) -> u16 {
        match self {
            Self::Text => close::UNSUPPORTED_DATA,
            Self::BadCloseReason => close::INVALID_PAYLOAD,
            Self::TooBig => close::TOO_BIG,
            _ => close::PROTOCOL_ERROR,
        }
    }

    pub const fn text(self) -> &'static str {
        match self {
            Self::Unmasked => "unmasked client frame",
            Self::ReservedBits => "reserved bits set",
            Self::UnknownOpcode => "unknown opcode",
            Self::ControlTooLong => "control frame over 125 bytes",
            Self::ControlFragmented => "fragmented control frame",
            Self::StrayContinuation => "continuation without a message",
            Self::MessageInterleaved => "data frame inside a fragmented message",
            Self::BadLength => "bad payload length",
            Self::BadCloseCode => "bad close code",
            Self::BadCloseReason => "close reason not UTF-8",
            Self::Text => "text frame",
            Self::TooBig => "message too big",
        }
    }
}

/// Whether a peer may send close code `code` (RFC 6455 7.4.1, 7.4.2, and the
/// IANA registry's 1012 to 1014): 1000-1003, 1007-1014, 3000-4999.
pub const fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// What the decoder found, in order.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// Unmasked payload bytes of a data message. `text` is the message's
    /// type (only with [`Config::text`]). Never empty: an empty frame
    /// produces no `Data`.
    Data {
        bytes: &'a [u8],
        text: bool,
    },
    /// The data message the preceding `Data` belonged to is complete (an
    /// empty message has no `Data`, so its type is given here too).
    End {
        text: bool,
    },
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    /// The client closes: its code (if any) and reason. The decoder accepts
    /// nothing after this.
    Close {
        code: Option<u16>,
        reason: &'a [u8],
    },
}

/// What a frame header said.
#[derive(Debug, Clone, Copy, Default)]
struct Frame {
    opcode: u8,
    fin: bool,
    mask: [u8; 4],
    remaining: u64,
    /// Payload bytes of this frame consumed so far, mod 4 (the mask's phase).
    phase: u8,
}

/// The decoder of one connection's client-to-server stream.
#[derive(Debug, Clone)]
pub struct Decoder {
    cfg: Config,
    /// A header being received.
    hdr: [u8; 14],
    hdr_len: u8,
    /// The frame whose payload is being received, once its header is complete.
    frame: Option<Frame>,
    /// A fragmented data message is open: `Some(text)`.
    message: Option<bool>,
    /// Bytes of the open message so far.
    message_len: u64,
    /// A control frame's payload being received.
    ctrl: [u8; MAX_CONTROL],
    ctrl_len: u8,
    /// A close frame was received (or a violation found): nothing more.
    done: bool,
}

/// The header length that `first two bytes` announce: 2, 4 or 10, and 4 more
/// with a mask.
fn header_len(b1: u8) -> usize {
    let len = match b1 & 0x7f {
        126 => 4,
        127 => 10,
        _ => 2,
    };
    if b1 & 0x80 != 0 { len + 4 } else { len }
}

/// XORs `data` with `mask`, starting at mask position `phase`; returns the
/// new phase.
fn unmask(data: &mut [u8], mask: [u8; 4], phase: u8) -> u8 {
    let mut p = usize::from(phase & 3);
    for b in data.iter_mut() {
        *b ^= mask.get(p).copied().unwrap_or(0);
        p = (p + 1) & 3;
    }
    p as u8
}

impl Decoder {
    pub const fn new(cfg: Config) -> Self {
        Self {
            cfg,
            hdr: [0; 14],
            hdr_len: 0,
            frame: None,
            message: None,
            message_len: 0,
            ctrl: [0; MAX_CONTROL],
            ctrl_len: 0,
            done: false,
        }
    }

    /// A close frame was received or a violation found.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Whether a frame or a message is partly received (an abrupt end now
    /// cuts something off).
    pub fn mid_frame(&self) -> bool {
        self.hdr_len > 0 || self.frame.is_some() || self.message.is_some()
    }

    /// Feeds bytes from the client. Payload is unmasked in place in `buf`;
    /// every event goes to `sink` as it is found. A violation stops the
    /// decoder (all later input is ignored) and is returned: the caller sends
    /// a close frame with its code and closes.
    pub fn feed(
        &mut self,
        buf: &mut [u8],
        sink: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Violation> {
        if self.done {
            return Ok(());
        }
        let r = self.feed_inner(buf, sink);
        if r.is_err() {
            self.done = true;
        }
        r
    }

    fn feed_inner(
        &mut self,
        mut buf: &mut [u8],
        sink: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Violation> {
        while !buf.is_empty() && !self.done {
            let Some(mut f) = self.frame else {
                // Header bytes: take what is needed, as far as known.
                let have = usize::from(self.hdr_len);
                let need = if have < 2 {
                    2
                } else {
                    header_len(self.hdr.get(1).copied().unwrap_or(0))
                };
                let take = (need - have).min(buf.len());
                let (head, rest) = core::mem::take(&mut buf).split_at_mut(take);
                if let Some(d) = self.hdr.get_mut(have..have + take) {
                    d.copy_from_slice(head);
                }
                buf = rest;
                self.hdr_len += take as u8;
                if usize::from(self.hdr_len) == 2 {
                    // The first two bytes alone decide most violations: say
                    // so before waiting for the rest of the header.
                    self.check_start()?;
                }
                let len = usize::from(self.hdr_len);
                if len >= 2 && len == header_len(self.hdr.get(1).copied().unwrap_or(0)) {
                    self.start_frame(sink)?;
                }
                continue;
            };
            // Payload bytes of the current frame.
            let take = usize::try_from(f.remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            let (chunk, rest) = core::mem::take(&mut buf).split_at_mut(take);
            buf = rest;
            f.phase = unmask(chunk, f.mask, f.phase);
            f.remaining -= take as u64;
            if f.opcode >= op::CLOSE {
                let have = usize::from(self.ctrl_len);
                if let Some(d) = self.ctrl.get_mut(have..have + chunk.len()) {
                    d.copy_from_slice(chunk);
                }
                self.ctrl_len += chunk.len() as u8;
            } else if !chunk.is_empty() {
                sink(Event::Data {
                    bytes: chunk,
                    text: self.message.unwrap_or(false),
                });
            }
            self.frame = Some(f);
            if f.remaining == 0 {
                self.end_frame(f, sink)?;
            }
        }
        Ok(())
    }

    /// The first two header bytes.
    fn check_start(&self) -> Result<(), Violation> {
        let b0 = self.hdr.first().copied().unwrap_or(0);
        let b1 = self.hdr.get(1).copied().unwrap_or(0);
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0f;
        if b0 & 0x70 != 0 {
            return Err(Violation::ReservedBits);
        }
        match opcode {
            op::CONTINUATION if self.message.is_none() => {
                return Err(Violation::StrayContinuation);
            }
            op::TEXT | op::BINARY if self.message.is_some() => {
                return Err(Violation::MessageInterleaved);
            }
            op::TEXT if !self.cfg.text => return Err(Violation::Text),
            op::CONTINUATION | op::TEXT | op::BINARY => {}
            op::CLOSE | op::PING | op::PONG => {
                if !fin {
                    return Err(Violation::ControlFragmented);
                }
                if usize::from(b1 & 0x7f) > MAX_CONTROL {
                    return Err(Violation::ControlTooLong);
                }
            }
            _ => return Err(Violation::UnknownOpcode),
        }
        if b1 & 0x80 == 0 {
            return Err(Violation::Unmasked);
        }
        Ok(())
    }

    /// A complete header: checks the length, opens the frame.
    fn start_frame(&mut self, sink: &mut impl FnMut(Event<'_>)) -> Result<(), Violation> {
        let [b0, b1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13] = self.hdr;
        self.hdr_len = 0;
        let (len, mask) = match b1 & 0x7f {
            126 => {
                let l = u64::from(u16::from_be_bytes([h2, h3]));
                if l < 126 {
                    return Err(Violation::BadLength);
                }
                (l, [h4, h5, h6, h7])
            }
            127 => {
                let l = u64::from_be_bytes([h2, h3, h4, h5, h6, h7, h8, h9]);
                if l >> 63 != 0 || l <= 0xffff {
                    return Err(Violation::BadLength);
                }
                (l, [h10, h11, h12, h13])
            }
            l => (u64::from(l), [h2, h3, h4, h5]),
        };
        let opcode = b0 & 0x0f;
        if opcode < op::CLOSE {
            if self.message_len.saturating_add(len) > self.cfg.max_message {
                return Err(Violation::TooBig);
            }
            self.message_len += len;
            if opcode != op::CONTINUATION {
                self.message = Some(opcode == op::TEXT);
            }
        } else {
            self.ctrl_len = 0;
        }
        let f = Frame {
            opcode,
            fin: b0 & 0x80 != 0,
            mask,
            remaining: len,
            phase: 0,
        };
        self.frame = Some(f);
        if len == 0 {
            self.end_frame(f, sink)?;
        }
        Ok(())
    }

    /// The frame's payload is complete.
    fn end_frame(&mut self, f: Frame, sink: &mut impl FnMut(Event<'_>)) -> Result<(), Violation> {
        self.frame = None;
        let payload = self.ctrl.get(..usize::from(self.ctrl_len)).unwrap_or(&[]);
        match f.opcode {
            op::PING => sink(Event::Ping(payload)),
            op::PONG => sink(Event::Pong(payload)),
            op::CLOSE => {
                self.done = true;
                let (code, reason) = match payload {
                    [] => (None, &[][..]),
                    [_] => return Err(Violation::BadCloseCode),
                    [a, b, rest @ ..] => (Some(u16::from_be_bytes([*a, *b])), rest),
                };
                if code.is_some_and(|c| !valid_close_code(c)) {
                    return Err(Violation::BadCloseCode);
                }
                if core::str::from_utf8(reason).is_err() {
                    return Err(Violation::BadCloseReason);
                }
                sink(Event::Close { code, reason });
            }
            _ if f.fin => {
                let text = self.message.take().unwrap_or(false);
                self.message_len = 0;
                sink(Event::End { text });
            }
            _ => {}
        }
        Ok(())
    }
}

/// The header of a server frame (FIN set, never masked) for a payload of
/// `len` bytes; returns the bytes and how many of them are used.
pub fn header(opcode: u8, len: usize) -> ([u8; MAX_HEADER], usize) {
    let b0 = 0x80 | (opcode & 0x0f);
    if len < 126 {
        ([b0, len as u8, 0, 0, 0, 0, 0, 0, 0, 0], 2)
    } else if len <= 0xffff {
        let [a, b] = (len as u16).to_be_bytes();
        ([b0, 126, a, b, 0, 0, 0, 0, 0, 0], 4)
    } else {
        let [a, b, c, d, e, f, g, h] = (len as u64).to_be_bytes();
        ([b0, 127, a, b, c, d, e, f, g, h], 10)
    }
}

/// A close frame without a code: the answer to a close that carried none.
pub const CLOSE_EMPTY: [u8; 2] = [0x80 | op::CLOSE, 0];

/// A whole close frame with `code` and no reason.
pub fn close_frame(code: u16) -> [u8; 4] {
    let c = code.to_be_bytes();
    [0x80 | op::CLOSE, 2, c[0], c[1]]
}

/// A whole pong frame answering a ping's payload (at most 125 bytes); returns
/// the bytes and how many are used.
pub fn pong_frame(payload: &[u8]) -> ([u8; 2 + MAX_CONTROL], usize) {
    let mut out = [0u8; 2 + MAX_CONTROL];
    let n = payload.len().min(MAX_CONTROL);
    if let Some(h) = out.get_mut(..2) {
        h.copy_from_slice(&[0x80 | op::PONG, n as u8]);
    }
    if let (Some(d), Some(s)) = (out.get_mut(2..2 + n), payload.get(..n)) {
        d.copy_from_slice(s);
    }
    (out, 2 + n)
}
