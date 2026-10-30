//! H3: packetdrill-style scripted tests. One line per event:
//!
//! ```text
//! +300                           advance the clock 300 ms (timers run)
//! < S seq=0 win=65535 mss=1460   the client sends (flags: S . P F R U)
//! > S. ack=1                     the next segment from the server matches
//! > nothing                      the server sent nothing
//! app send 100                   the application sends 100 bytes
//! app close                      the application closes
//! expect conns=1 data=100 peer_closed closed=reset
//! ```
//!
//! Sequence numbers are relative: the client's to its ISN, the server's
//! to the ISN of its SYN-ACK. `seq`/`ack` default to what the client has
//! sent and received so far. A line may start with `+N` to advance the
//! clock first. `opts=<hex>` replaces the options of a client segment
//! (raw, checksum recomputed); `len=N` sends N payload bytes; `win=` and
//! `mss=` in an expectation check the server's values (`*` for any).

use super::*;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

pub(crate) const SERVER: [u8; 4] = [10, 0, 2, 15];
pub(crate) const CLIENT: [u8; 4] = [10, 0, 2, 2];
pub(crate) const PORT: u16 = 8883;
pub(crate) const CPORT: u16 = 40000;
pub(crate) const C_ISN: u32 = 1_000_000;

pub fn cfg() -> Config {
    Config {
        local_addr: SERVER,
        ports: vec![PORT],
        mss: 1460,
        rcv_wnd: 65535,
        max_conns: 64,
        tx_max: 256 * 1024,
        cookie_key: [9; 16],
        rst_per_sec: 1000,
    }
}

#[derive(Default)]
struct ScriptApp {
    conns: Vec<ConnId>,
    data: usize,
    peer_closed: bool,
    closed: Vec<CloseReason>,
}

impl App for ScriptApp {
    fn accept(&mut self, c: ConnId, _p: u16, _r: Endpoint) -> bool {
        self.conns.push(c);
        true
    }
    fn data(&mut self, _c: ConnId, d: &[u8]) {
        self.data += d.len();
    }
    fn peer_closed(&mut self, _c: ConnId) {
        self.peer_closed = true;
    }
    fn closed(&mut self, _c: ConnId, why: CloseReason) {
        self.closed.push(why);
    }
}

struct Got {
    flags: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mss: Option<u16>,
    len: usize,
}

fn flags_of(s: &str) -> Result<u8, String> {
    let mut f = 0;
    for ch in s.chars() {
        f |= match ch {
            'S' => wire::SYN,
            '.' => wire::ACK,
            'P' => wire::PSH,
            'F' => wire::FIN,
            'R' => wire::RST,
            'U' => wire::URG,
            _ => return Err(format!("unknown flag {ch:?}")),
        };
    }
    Ok(f)
}

fn flags_str(f: u8) -> String {
    let mut s = String::new();
    for (bit, ch) in [
        (wire::SYN, 'S'),
        (wire::FIN, 'F'),
        (wire::RST, 'R'),
        (wire::PSH, 'P'),
        (wire::URG, 'U'),
        (wire::ACK, '.'),
    ] {
        if f & bit != 0 {
            s.push(ch);
        }
    }
    s
}

fn hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| *c != '_').collect();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// A client segment with raw options and payload, checksum filled in.
fn raw_segment(
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
    urg: u16,
    opts: &[u8],
    len: usize,
) -> Vec<u8> {
    let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
    segment(CPORT, seq, ack, flags, win, urg, opts, &payload)
}

/// A segment from the client's `port` (absolute numbers), checksummed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn segment(
    port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
    urg: u16,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let hlen = wire::HEADER + opts.len().div_ceil(4) * 4;
    let mut b = Vec::with_capacity(hlen + payload.len());
    b.extend_from_slice(&port.to_be_bytes());
    b.extend_from_slice(&PORT.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&ack.to_be_bytes());
    b.push(((hlen / 4) as u8) << 4);
    b.push(flags);
    b.extend_from_slice(&win.to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&urg.to_be_bytes());
    b.extend_from_slice(opts);
    b.resize(hlen, 0);
    b.extend_from_slice(payload);
    let c = wire::checksum(CLIENT, SERVER, &b);
    b[16..18].copy_from_slice(&c.to_be_bytes());
    b
}

pub struct Runner {
    s: TcpStack,
    app: ScriptApp,
    now: u64,
    out: VecDeque<Vec<u8>>,
    /// Relative to C_ISN: the client's next sequence number.
    cnext: u32,
    /// The server's ISN once known, and its next sequence number (relative).
    s_isn: Option<u32>,
    snext: u32,
}

impl Runner {
    pub fn new() -> Self {
        Self {
            s: TcpStack::new(cfg(), 0),
            app: ScriptApp::default(),
            now: 0,
            out: VecDeque::new(),
            cnext: 0,
            s_isn: None,
            snext: 0,
        }
    }

    /// What the kernel loop does after any event.
    fn service(&mut self) {
        let mut q = Vec::new();
        self.s
            .poll(self.now, &mut self.app, &mut |_, b| q.push(b.to_vec()));
        self.s.flush(self.now, &mut |_, b| q.push(b.to_vec()));
        self.out.extend(q);
    }

    fn send(&mut self, args: &[&str]) -> Result<(), String> {
        let flags = flags_of(args.first().ok_or("missing flags")?)?;
        let (mut seq, mut ack, mut win, mut mss, mut len, mut opts, mut urg) =
            (self.cnext, self.snext, 65535u16, None, 0usize, None, 0u16);
        for kv in args.iter().skip(1) {
            let (k, v) = kv.split_once('=').ok_or(format!("bad field {kv:?}"))?;
            let num = || v.parse::<u32>().map_err(|e| format!("{kv}: {e}"));
            match k {
                "seq" => seq = num()?,
                "ack" => ack = num()?,
                "win" => win = num()? as u16,
                "mss" => mss = Some(num()? as u16),
                "len" => len = num()? as usize,
                "urg" => urg = num()? as u16,
                "opts" => opts = Some(hex(v)?),
                _ => return Err(format!("unknown field {k}")),
            }
        }
        let opts = opts.unwrap_or_else(|| {
            mss.map_or(Vec::new(), |m| {
                let b = m.to_be_bytes();
                vec![2, 4, b[0], b[1]]
            })
        });
        let abs_ack = self.s_isn.map_or(ack, |i| i.wrapping_add(ack));
        let seg = raw_segment(
            C_ISN.wrapping_add(seq),
            if flags & wire::ACK != 0 { abs_ack } else { 0 },
            flags,
            win,
            urg,
            &opts,
            len,
        );
        let mut adv = len as u32;
        if flags & (wire::SYN | wire::FIN) != 0 {
            adv += 1;
        }
        if flags & wire::RST == 0 {
            self.cnext = self.cnext.max(seq.wrapping_add(adv));
        }
        let mut q = Vec::new();
        self.s
            .input(self.now, CLIENT, &seg, &mut self.app, &mut |_, b| {
                q.push(b.to_vec())
            });
        self.out.extend(q);
        self.service();
        Ok(())
    }

    fn expect(&mut self, args: &[&str]) -> Result<(), String> {
        if args.first() == Some(&"nothing") {
            return match self.out.pop_front() {
                None => Ok(()),
                Some(b) => Err(format!("expected nothing, got {}", self.describe(&b))),
            };
        }
        let want = flags_of(args.first().ok_or("missing flags")?)?;
        let b = self
            .out
            .pop_front()
            .ok_or("expected a segment, got nothing")?;
        let h = wire::parse(SERVER, CLIENT, &b).map_err(|e| format!("bad segment {e:?}"))?;
        if h.flags & wire::SYN != 0 && self.s_isn.is_none() {
            self.s_isn = Some(h.seq);
        }
        let isn = self.s_isn.unwrap_or(0);
        let g = Got {
            flags: h.flags,
            seq: h.seq.wrapping_sub(isn),
            ack: h.ack.wrapping_sub(C_ISN),
            win: h.window,
            mss: h.mss,
            len: b.len() - h.data_off,
        };
        let mut adv = g.len as u32;
        if g.flags & (wire::SYN | wire::FIN) != 0 {
            adv += 1;
        }
        self.snext = self.snext.max(g.seq.wrapping_add(adv));
        let what = self.describe(&b);
        // PSH is informational: "." matches with or without it.
        if (g.flags & !wire::PSH) != (want & !wire::PSH) {
            return Err(format!("flags: expected {}, got {what}", flags_str(want)));
        }
        for kv in args.iter().skip(1) {
            let (k, v) = kv.split_once('=').ok_or(format!("bad field {kv:?}"))?;
            if v == "*" {
                continue;
            }
            let n: u64 = v.parse().map_err(|e| format!("{kv}: {e}"))?;
            let got = match k {
                "seq" => u64::from(g.seq),
                "ack" => u64::from(g.ack),
                "win" => u64::from(g.win),
                "len" => g.len as u64,
                "mss" => u64::from(g.mss.unwrap_or(0)),
                _ => return Err(format!("unknown field {k}")),
            };
            if got != n {
                return Err(format!("{k}: expected {n}, got {got} in {what}"));
            }
        }
        Ok(())
    }

    fn describe(&self, b: &[u8]) -> String {
        match wire::parse(SERVER, CLIENT, b) {
            Ok(h) => {
                let isn = self.s_isn.unwrap_or(h.seq);
                format!(
                    "{} seq={} ack={} win={} len={}{}",
                    flags_str(h.flags),
                    h.seq.wrapping_sub(isn),
                    h.ack.wrapping_sub(C_ISN),
                    h.window,
                    b.len() - h.data_off,
                    h.mss.map_or(String::new(), |m| format!(" mss={m}"))
                )
            }
            Err(e) => format!("unparsable {e:?}"),
        }
    }

    fn app_cmd(&mut self, args: &[&str]) -> Result<(), String> {
        let c = *self.app.conns.last().ok_or("no connection")?;
        match args {
            ["send", n] => {
                let n: usize = n.parse().map_err(|e| format!("{e}"))?;
                let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
                let sent = self.s.send(c, &data);
                if sent != n {
                    return Err(format!("app send: only {sent} of {n} queued"));
                }
            }
            ["close"] => self.s.close(c),
            ["window", n] => self
                .s
                .set_recv_space(c, n.parse().map_err(|e| format!("{e}"))?),
            _ => return Err(format!("unknown app command {args:?}")),
        }
        self.service();
        Ok(())
    }

    fn check(&self, args: &[&str]) -> Result<(), String> {
        for a in args {
            let ok = match a.split_once('=') {
                Some(("conns", n)) => self.s.connections().to_string() == n,
                Some(("data", n)) => self.app.data.to_string() == n,
                Some(("closed", why)) => self
                    .app
                    .closed
                    .iter()
                    .any(|c| format!("{c:?}").eq_ignore_ascii_case(why)),
                None if *a == "peer_closed" => self.app.peer_closed,
                _ => return Err(format!("unknown expectation {a}")),
            };
            if !ok {
                return Err(format!(
                    "expectation {a} failed (conns={}, data={}, peer_closed={}, closed={:?})",
                    self.s.connections(),
                    self.app.data,
                    self.app.peer_closed,
                    self.app.closed
                ));
            }
        }
        Ok(())
    }

    pub fn run(&mut self, script: &str) -> Result<(), String> {
        for (i, raw) in script.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut words: Vec<&str> = line.split_whitespace().collect();
            if let Some(t) = words.first().and_then(|w| w.strip_prefix('+')) {
                let ms: u64 = t.parse().map_err(|e| format!("line {}: {e}", i + 1))?;
                self.now += ms;
                self.service();
                words.remove(0);
            }
            let r = match words.split_first() {
                None => Ok(()),
                Some((&"<", rest)) => self.send(rest),
                Some((&">", rest)) => self.expect(rest),
                Some((&"app", rest)) => self.app_cmd(rest),
                Some((&"expect", rest)) => self.check(rest),
                Some((w, _)) => Err(format!("unknown command {w}")),
            };
            r.map_err(|e| format!("line {} `{}`: {e}", i + 1, raw.trim()))?;
        }
        Ok(())
    }
}

/// Runs `script`; panics with the failing line.
pub fn run(script: &str) {
    if let Err(e) = Runner::new().run(script) {
        panic!("{e}");
    }
}
