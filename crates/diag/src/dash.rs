//! The dashboard: panels with borders, aligned columns and bar graphs,
//! drawn through a small [`Canvas`] so the kernel's framebuffer console and
//! the host tests share the layout. The look is ALDO TECH's: a dark navy
//! page, slightly lighter panels, white text and amber accents.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::bars;
use crate::fmt;
use crate::names;
use crate::report::{CryptoBench, Disk, RamBench, Report, WriteState};

pub type Rgb = (u8, u8, u8);

pub const BG: Rgb = (0x0b, 0x12, 0x2b);
pub const PANEL: Rgb = (0x13, 0x1c, 0x3d);
pub const BORDER: Rgb = (0x2e, 0x3d, 0x73);
pub const AMBER: Rgb = (0xff, 0xb0, 0x20);
pub const TEXT: Rgb = (0xf2, 0xf4, 0xfa);
pub const DIM: Rgb = (0x8e, 0x9a, 0xc4);
pub const GOOD: Rgb = (0x5f, 0xd3, 0x9a);
pub const BAD: Rgb = (0xff, 0x6b, 0x5b);
pub const TRACK: Rgb = (0x24, 0x30, 0x5c);

/// Something the dashboard can be drawn on: a grid of text cells over a
/// pixel surface.
pub trait Canvas {
    fn cols(&self) -> usize;
    fn rows(&self) -> usize;
    /// Pixels per text cell (a square).
    fn cell_px(&self) -> usize;
    fn fill_px(&mut self, x: usize, y: usize, w: usize, h: usize, c: Rgb);
    /// Draws `s` from cell (`col`, `row`); the canvas clips at its edge.
    fn text(&mut self, col: usize, row: usize, s: &str, fg: Rgb, bg: Rgb);
}

/// Where the run is, for the footer.
#[derive(Debug, Clone, Default)]
pub struct Status {
    pub stage: String,
    pub step: usize,
    pub steps: usize,
    /// A question for the operator, shown in the footer in amber.
    pub prompt: Option<String>,
    /// What the operator has typed so far.
    pub typed: String,
    pub done: bool,
}

/// One row of a panel.
enum Line {
    Kv(&'static str, String, Rgb),
    Text(String, Rgb),
    Bar {
        label: String,
        scale: Scale,
        value: String,
        color: Rgb,
    },
    Gap,
}

enum Scale {
    Linear(u64, u64),
    Log(u64, u64, u64),
}

const LABEL_W: usize = 14;

fn fill_cells<C: Canvas>(c: &mut C, col: usize, row: usize, w: usize, h: usize, rgb: Rgb) {
    let k = c.cell_px();
    c.fill_px(col * k, row * k, w * k, h * k, rgb);
}

/// Breaks `s` at spaces into at most `lines` lines of `width` characters;
/// the last line ends in `~` if text was left over.
fn wrap(s: &str, width: usize, lines: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut words = s.split_whitespace().peekable();
    while let Some(w) = words.next() {
        let need = if cur.is_empty() {
            w.len()
        } else {
            cur.len() + 1 + w.len()
        };
        if need > width && !cur.is_empty() {
            out.push(core::mem::take(&mut cur));
            if out.len() == lines {
                // Out of lines: mark the cut.
                if let Some(last) = out.last_mut() {
                    *last = fmt::clip(&format!("{last} ~"), width);
                }
                return out;
            }
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
        if words.peek().is_none() {
            out.push(core::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.truncate(lines);
    out
}

/// Draws one panel at (`col`, `row`) of `w` cells; returns the rows used
/// (at most `avail`).
fn panel<C: Canvas>(
    c: &mut C,
    (col, row, w, avail): (usize, usize, usize, usize),
    title: &str,
    lines: &[Line],
) -> usize {
    if avail < 3 || w < 12 {
        return 0;
    }
    let h = (lines.len() + 2).min(avail);
    let k = c.cell_px();
    let half = k / 2;
    let (x0, y0) = (col * k + half, row * k + half);
    let (pw, ph) = (w * k - k, h * k - k);
    c.fill_px(x0, y0, pw, ph, PANEL);
    // A 2 px outline just inside the panel's rectangle.
    let t = if k >= 16 { 2 } else { 1 };
    c.fill_px(x0, y0, pw, t, BORDER);
    c.fill_px(x0, y0 + ph - t, pw, t, BORDER);
    c.fill_px(x0, y0, t, ph, BORDER);
    c.fill_px(x0 + pw - t, y0, t, ph, BORDER);
    // The title sits on the top border.
    let tt = fmt::clip(title, w.saturating_sub(6));
    c.text(col + 1, row, &format!(" {tt} "), AMBER, BG);
    let inner = w.saturating_sub(4);
    let room = h - 2;
    for (i, line) in lines.iter().enumerate() {
        let r = row + 1 + i;
        let last_cut = i + 1 == room && lines.len() > room;
        if i >= room {
            break;
        }
        if last_cut {
            c.text(
                col + 2,
                r,
                &fmt::clip(&format!("... {} more", lines.len() - i), inner),
                DIM,
                PANEL,
            );
            break;
        }
        match line {
            Line::Gap => {}
            Line::Text(s, fg) => c.text(col + 2, r, &fmt::clip(s, inner), *fg, PANEL),
            Line::Kv(label, value, fg) => {
                c.text(col + 2, r, &fmt::left(label, LABEL_W), DIM, PANEL);
                c.text(
                    col + 2 + LABEL_W,
                    r,
                    &fmt::clip(value, inner.saturating_sub(LABEL_W)),
                    *fg,
                    PANEL,
                );
            }
            Line::Bar {
                label,
                scale,
                value,
                color,
            } => {
                let vw = value.chars().count().min(inner / 2);
                let lw = LABEL_W + 2;
                c.text(col + 2, r, &fmt::left(label, lw), DIM, PANEL);
                let bar_cells = inner.saturating_sub(lw + vw + 1);
                if bar_cells >= 4 {
                    let bx = (col + 2 + lw) * k;
                    let by = r * k + k / 4;
                    let bh = k - k / 2;
                    let width = bar_cells * k;
                    c.fill_px(bx, by, width, bh, TRACK);
                    let px = match scale {
                        Scale::Linear(v, max) => bars::linear_px(*v, *max, width),
                        Scale::Log(v, lo, hi) => bars::log_px(*v, *lo, *hi, width),
                    };
                    if px > 0 {
                        c.fill_px(bx, by, px, bh, *color);
                    }
                }
                let vx = col + 2 + lw + bar_cells + usize::from(bar_cells > 0);
                c.text(vx, r, &fmt::clip(value, vw), TEXT, PANEL);
            }
        }
    }
    h
}

fn opt_yes_no(b: Option<bool>) -> String {
    match b {
        Some(true) => "yes".into(),
        Some(false) => "no".into(),
        None => "n/a".into(),
    }
}

fn system_lines(r: &Report, inner: usize) -> Vec<Line> {
    let mut v = Vec::new();
    let cpu = &r.cpu;
    v.push(Line::Kv("CPU", cpu.model.clone(), TEXT));
    v.push(Line::Kv(
        "Identity",
        format!("{} {}", cpu.vendor, cpu.identity),
        TEXT,
    ));
    v.push(Line::Kv("Logical CPUs", format!("{}", cpu.logical), TEXT));
    let fw = inner.saturating_sub(LABEL_W);
    for (i, l) in wrap(&cpu.features.join(" "), fw, 2).into_iter().enumerate() {
        v.push(Line::Kv(if i == 0 { "Features" } else { "" }, l, TEXT));
    }
    let units = if cpu.crypto_units.is_empty() {
        String::from("none (software)")
    } else {
        cpu.crypto_units.join(" ")
    };
    v.push(Line::Kv("Crypto units", units, GOOD));
    for (i, l) in wrap(&cpu.crypto_backend, fw, 2).into_iter().enumerate() {
        v.push(Line::Kv(if i == 0 { "Active" } else { "" }, l, AMBER));
    }
    v.push(Line::Gap);
    let hv = if r.hypervisor.is_empty() {
        "none detected (bare metal)".into()
    } else {
        r.hypervisor.clone()
    };
    v.push(Line::Kv("Hypervisor", hv, TEXT));
    v.push(Line::Kv(
        "Firmware",
        format!("{}, {}", r.firmware.kind, r.firmware.bootloader),
        TEXT,
    ));
    v.push(Line::Kv("Booted from", r.firmware.medium.clone(), TEXT));
    let t = &r.time;
    let mhz = t.counter_hz / 1_000_000;
    let clock = match (t.invariant_tsc, t.kvmclock) {
        (Some(inv), Some(kvm)) => format!(
            "{} ({} MHz), invariant TSC {}, kvmclock {}",
            t.source,
            mhz,
            opt_yes_no(Some(inv)),
            opt_yes_no(Some(kvm))
        ),
        _ => format!("{} counter, {} MHz", t.source, mhz),
    };
    v.push(Line::Kv("Time source", clock, TEXT));
    match t.rtc_unix {
        Some(u) => {
            let (txt, col) = if t.rtc_plausible {
                (crate::time::iso8601(u), TEXT)
            } else {
                (
                    format!("{} (before the build: wrong)", crate::time::iso8601(u)),
                    BAD,
                )
            };
            v.push(Line::Kv("RTC", txt, col));
        }
        None => v.push(Line::Kv("RTC", "not reported".into(), BAD)),
    }
    v
}

fn memory_lines(r: &Report) -> Vec<Line> {
    let m = &r.memory;
    vec![
        Line::Bar {
            label: "Usable".into(),
            scale: Scale::Linear(m.usable, m.total),
            value: fmt::bytes(m.usable),
            color: GOOD,
        },
        Line::Kv("Total", fmt::bytes(m.total), TEXT),
        Line::Kv("Reserved/MMIO", fmt::bytes(m.reserved), TEXT),
    ]
}

fn pci_lines(r: &Report) -> Vec<Line> {
    if r.pci.is_empty() {
        return vec![Line::Text("no PCI devices found".into(), DIM)];
    }
    r.pci
        .iter()
        .map(|p| {
            Line::Text(
                format!(
                    "{} {:04x}:{:04x} {} - {}{}",
                    p.bdf,
                    p.vendor,
                    p.device,
                    fmt::left(names::pci_class(p.class, p.subclass), 20),
                    names::pci_vendor(p.vendor),
                    p.driver.map_or(String::new(), |d| format!(" [{d}]")),
                ),
                TEXT,
            )
        })
        .collect()
}

fn disk_lines(r: &Report) -> Vec<Line> {
    if r.disks.is_empty() {
        return vec![Line::Text("no disks found".into(), DIM)];
    }
    let mut v = Vec::new();
    for d in &r.disks {
        v.push(Line::Text(
            format!(
                "{}  {}{}{}",
                d.name,
                fmt::bytes(d.bytes()),
                if d.read_only { "  read-only" } else { "" },
                if d.boot_medium { "  boot medium" } else { "" },
            ),
            TEXT,
        ));
        v.push(Line::Text(
            format!(
                "  bus {}, model {}, contents: {}",
                d.bus,
                d.model.as_deref().unwrap_or("not reported"),
                d.state
            ),
            DIM,
        ));
    }
    v
}

fn nic_lines(r: &Report) -> Vec<Line> {
    if r.nics.is_empty() && r.other_nics.is_empty() {
        return vec![Line::Text("no network interface found".into(), BAD)];
    }
    let mut v = Vec::new();
    for n in &r.nics {
        let mac = n.mac.map_or("?".into(), fmt::mac);
        let (link, col) = match n.link {
            Some(true) => ("link up", GOOD),
            Some(false) => ("link down", BAD),
            None => ("link ?", DIM),
        };
        v.push(Line::Text(format!("{}  {}  {}", n.name, mac, link), col));
    }
    for (ven, dev) in &r.other_nics {
        v.push(Line::Text(
            format!(
                "{ven:04x}:{dev:04x} {} - no driver here",
                names::pci_vendor(*ven)
            ),
            BAD,
        ));
    }
    v
}

fn ram_lines(b: Option<&RamBench>) -> Vec<Line> {
    let Some(b) = b else {
        return vec![Line::Text("measuring...".into(), DIM)];
    };
    let max = bars::nice_max(b.read_mib_s.max(b.write_mib_s).max(b.copy_mib_s));
    let mut v = Vec::new();
    for (name, val) in [
        ("Read", b.read_mib_s),
        ("Write", b.write_mib_s),
        ("Copy", b.copy_mib_s),
    ] {
        v.push(Line::Bar {
            label: name.into(),
            scale: Scale::Linear(val, max),
            value: fmt::rate_mib(val),
            color: AMBER,
        });
    }
    v.push(Line::Text(
        format!(
            "buffer {}; access latency by working set (dependent loads):",
            fmt::bytes(b.buffer)
        ),
        DIM,
    ));
    for &(size, ns10) in &b.latency {
        v.push(Line::Bar {
            label: fmt::bytes(size),
            scale: Scale::Log(ns10, 5, 10_000),
            value: fmt::duration_x10(ns10),
            color: AMBER,
        });
    }
    v
}

fn iops_text(n: u64) -> String {
    if n >= 10_000 {
        format!("{}.{}k IOPS", n / 1000, n % 1000 / 100)
    } else {
        format!("{n} IOPS")
    }
}

fn disk_perf_lines(d: &Disk, seq_max: u64, iops_max: u64) -> Vec<Line> {
    let mut v = Vec::new();
    v.push(Line::Text(
        format!("{}  {}", d.name, fmt::bytes(d.bytes())),
        TEXT,
    ));
    if let Some(why) = &d.unmeasured {
        v.push(Line::Text(format!("  not measured: {why}"), DIM));
        return v;
    }
    match &d.seq_read {
        Some(s) => v.push(Line::Bar {
            label: "Seq read".into(),
            scale: Scale::Linear(s.mib_s, seq_max),
            value: fmt::rate_mib(s.mib_s),
            color: AMBER,
        }),
        None => v.push(Line::Text("Seq read: waiting...".into(), DIM)),
    }
    match &d.rand_read {
        Some(r) => {
            v.push(Line::Bar {
                label: format!("Rand {}K", r.block / 1024),
                scale: Scale::Linear(r.iops, iops_max),
                value: iops_text(r.iops),
                color: AMBER,
            });
            let l = &r.lat;
            v.push(Line::Bar {
                label: "Latency p50".into(),
                scale: Scale::Log(l.p50, 1_000, 100_000_000),
                value: fmt::duration_ns(l.p50),
                color: AMBER,
            });
            v.push(Line::Bar {
                label: "Latency p99".into(),
                scale: Scale::Log(l.p99, 1_000, 100_000_000),
                value: fmt::duration_ns(l.p99),
                color: AMBER,
            });
            v.push(Line::Text(
                format!(
                    "  p90 {}   max {}   ({} reads)",
                    fmt::duration_ns(l.p90),
                    fmt::duration_ns(l.max),
                    l.count
                ),
                DIM,
            ));
        }
        None => v.push(Line::Text("Random read: waiting...".into(), DIM)),
    }
    match &d.write {
        WriteState::Pending => v.push(Line::Text("Seq write: waiting...".into(), DIM)),
        WriteState::Done {
            mib_s, verified, ..
        } => v.push(Line::Bar {
            label: "Seq write".into(),
            scale: Scale::Linear(*mib_s, seq_max),
            value: format!(
                "{}{}",
                fmt::rate_mib(*mib_s),
                if *verified { "" } else { " (unverified)" }
            ),
            color: AMBER,
        }),
        WriteState::Skipped(why) => {
            v.push(Line::Text(format!("Seq write skipped: {why}"), AMBER));
        }
        WriteState::Failed(why) => v.push(Line::Text(format!("Seq write FAILED: {why}"), BAD)),
    }
    v
}

fn crypto_lines(c: Option<&CryptoBench>) -> Vec<Line> {
    let Some(c) = c else {
        return vec![Line::Text("measuring...".into(), DIM)];
    };
    let hs = c.handshake_us_x10;
    let max = c
        .x25519_us_x10
        .max(c.sign_us_x10)
        .max(c.verify_us_x10)
        .max(1);
    vec![
        Line::Kv(
            "Handshake",
            format!(
                "{} per mutual-TLS handshake, {} ticks ({})",
                fmt::duration_x10(hs * 1000),
                c.handshake_ticks,
                c.tick_clock
            ),
            AMBER,
        ),
        Line::Bar {
            label: "X25519".into(),
            scale: Scale::Linear(c.x25519_us_x10, max),
            value: fmt::duration_x10(c.x25519_us_x10 * 1000),
            color: AMBER,
        },
        Line::Bar {
            label: "ECDSA sign".into(),
            scale: Scale::Linear(c.sign_us_x10, max),
            value: fmt::duration_x10(c.sign_us_x10 * 1000),
            color: AMBER,
        },
        Line::Bar {
            label: "ECDSA verify".into(),
            scale: Scale::Linear(c.verify_us_x10, max),
            value: fmt::duration_x10(c.verify_us_x10 * 1000),
            color: AMBER,
        },
        Line::Text(
            format!(
                "AES-GCM {}  ChaCha20 {}  SHA-256 {}  CRC-32C {}",
                fmt::rate_mib(c.aes_gcm_mib_s),
                fmt::rate_mib(c.chacha_mib_s),
                fmt::rate_mib(c.sha256_mib_s),
                fmt::rate_mib(c.crc32c_mib_s)
            ),
            TEXT,
        ),
    ]
}

fn header<C: Canvas>(c: &mut C, r: &Report) {
    let cols = c.cols();
    let k = c.cell_px();
    fill_cells(c, 0, 0, cols, 3, BG);
    c.text(2, 1, "ALDO TECH", AMBER, BG);
    c.text(12, 1, "urMQTT DIAGNOSTIC", TEXT, BG);
    let right = format!("{} {} {}", r.version, r.arch, r.env);
    let rc = cols.saturating_sub(right.chars().count() + 2);
    if rc > 32 {
        c.text(rc, 1, &right, DIM, BG);
    }
    // The amber rule under the title.
    c.fill_px(k, 2 * k + k / 2, (cols.saturating_sub(2)) * k, 2, AMBER);
}

fn footer<C: Canvas>(c: &mut C, s: &Status) {
    let (cols, rows) = (c.cols(), c.rows());
    if rows < 8 {
        return;
    }
    let row = rows - 2;
    fill_cells(c, 0, row, cols, 2, BG);
    let line = match &s.prompt {
        Some(p) => {
            let shown = format!("{p} > {}_", s.typed);
            c.text(
                2,
                row,
                &fmt::clip(&shown, cols.saturating_sub(4)),
                AMBER,
                BG,
            );
            return;
        }
        None if s.done => {
            let msg =
                "Done. The same figures are on the serial port as JSON. Press any key to reboot.";
            c.text(2, row, &fmt::clip(msg, cols.saturating_sub(4)), AMBER, BG);
            return;
        }
        None => format!("{}/{}  {}", s.step.min(s.steps), s.steps, s.stage),
    };
    let k = c.cell_px();
    let bar_cells = cols.saturating_sub(4).min(40);
    c.fill_px(2 * k, row * k + k / 4, bar_cells * k, k / 2, TRACK);
    let px = bars::linear_px(s.step as u64, s.steps.max(1) as u64, bar_cells * k);
    c.fill_px(2 * k, row * k + k / 4, px, k / 2, AMBER);
    c.text(
        2 + bar_cells + 2,
        row,
        &fmt::clip(&line, cols.saturating_sub(bar_cells + 6)),
        TEXT,
        BG,
    );
}

/// Draws the whole dashboard for the current state of the report.
pub fn draw<C: Canvas>(c: &mut C, r: &Report, s: &Status) {
    let (cols, rows) = (c.cols(), c.rows());
    if cols < 40 || rows < 12 {
        return;
    }
    let k = c.cell_px();
    c.fill_px(0, 0, cols * k, rows * k, BG);
    header(c, r);
    let body_top = 3usize;
    let body_rows = rows.saturating_sub(body_top + 2);
    let two = cols >= 100;
    let lw = if two { (cols - 3) / 2 } else { cols - 2 };
    let rw = if two { cols - 3 - lw } else { cols - 2 };
    let (lx, rx) = (1, if two { 2 + lw } else { 1 });

    let inner_l = lw.saturating_sub(4);
    let mut left: Vec<(&str, Vec<Line>)> = vec![
        ("SYSTEM", system_lines(r, inner_l)),
        ("MEMORY", memory_lines(r)),
        ("NETWORK", nic_lines(r)),
        ("DISKS", disk_lines(r)),
        ("PCI DEVICES", pci_lines(r)),
    ];
    let seq_max = bars::nice_max(
        r.disks
            .iter()
            .flat_map(|d| {
                [
                    d.seq_read.map_or(0, |s| s.mib_s),
                    match &d.write {
                        WriteState::Done { mib_s, .. } => *mib_s,
                        _ => 0,
                    },
                ]
            })
            .max()
            .unwrap_or(1),
    );
    let iops_max = bars::nice_max(
        r.disks
            .iter()
            .filter_map(|d| d.rand_read.map(|x| x.iops))
            .max()
            .unwrap_or(1),
    );
    let mut disk_perf: Vec<Line> = Vec::new();
    for d in &r.disks {
        if !disk_perf.is_empty() {
            disk_perf.push(Line::Gap);
        }
        disk_perf.extend(disk_perf_lines(d, seq_max, iops_max));
    }
    if disk_perf.is_empty() {
        disk_perf.push(Line::Text("no disk to measure".into(), DIM));
    }
    let mut right: Vec<(&str, Vec<Line>)> = vec![
        ("RAM THROUGHPUT AND LATENCY", ram_lines(r.ram.as_ref())),
        ("DISK PERFORMANCE", disk_perf),
        ("CRYPTO", crypto_lines(r.crypto.as_ref())),
    ];
    if two {
        stack(c, lx, body_top, lw, body_rows, &mut left);
        stack(c, rx, body_top, rw, body_rows, &mut right);
    } else {
        left.append(&mut right);
        stack(c, lx, body_top, lw, body_rows, &mut left);
    }
    footer(c, s);
}

fn stack<C: Canvas>(
    c: &mut C,
    col: usize,
    top: usize,
    w: usize,
    rows: usize,
    panels: &mut [(&str, Vec<Line>)],
) {
    let mut used = 0usize;
    for (title, lines) in panels.iter() {
        let avail = rows.saturating_sub(used);
        if avail < 4 {
            break;
        }
        used += panel(c, (col, top + used, w, avail), title, lines);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::*;
    use crate::stats;

    /// Records every operation and checks it stays on the surface.
    struct Fake {
        cols: usize,
        rows: usize,
        k: usize,
        texts: Vec<(usize, usize, String)>,
        rects: usize,
    }

    impl Canvas for Fake {
        fn cols(&self) -> usize {
            self.cols
        }
        fn rows(&self) -> usize {
            self.rows
        }
        fn cell_px(&self) -> usize {
            self.k
        }
        fn fill_px(&mut self, x: usize, y: usize, w: usize, h: usize, _c: Rgb) {
            assert!(
                x + w <= self.cols * self.k,
                "rect {x}+{w} beyond {}",
                self.cols * self.k
            );
            assert!(
                y + h <= self.rows * self.k,
                "rect {y}+{h} beyond {}",
                self.rows * self.k
            );
            self.rects += 1;
        }
        fn text(&mut self, col: usize, row: usize, s: &str, _fg: Rgb, _bg: Rgb) {
            assert!(row < self.rows, "row {row} of {}", self.rows);
            assert!(
                col + s.chars().count() <= self.cols,
                "text {s:?} at {col} runs past {} columns",
                self.cols
            );
            self.texts.push((col, row, s.into()));
        }
    }

    fn full_report() -> Report {
        let mut lat = [90_000u64, 120_000, 150_000, 800_000, 2_000_000];
        Report {
            version: "v0.1.0-12-gabcdef0".into(),
            arch: "x86_64".into(),
            env: "prod".into(),
            hypervisor: "KVM".into(),
            cpu: Cpu {
                vendor: "GenuineIntel".into(),
                model: "Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz".into(),
                identity: "family 6 model 0x55 stepping 7".into(),
                logical: 8,
                features: "aes pclmulqdq sha avx avx2 vaes vpclmulqdq gfni avx512f avx512bw avx512vl rdrand rdseed fsgsbase x2apic tsc-deadline invariant-tsc xsave pcid smep smap"
                    .split(' ')
                    .map(String::from)
                    .collect(),
                crypto_units: vec!["aes".into(), "pclmul".into(), "sha".into()],
                crypto_backend: "aes-gcm=aesni ghash=pclmul sha256=sha-ni crc32c=sse4.2 (all detected units in use)".into(),
            },
            memory: Memory { total: 4 << 30, usable: (4 << 30) - (300 << 20), reserved: 300 << 20 },
            pci: (0..40)
                .map(|i| PciFn {
                    bdf: format!("00:{i:02x}.0"),
                    vendor: 0x1af4,
                    device: 0x1041,
                    class: 2,
                    subclass: 0,
                    driver: Some("virtio-net"),
                })
                .collect(),
            disks: vec![
                Disk {
                    name: "virtio-scsi 00:05.0 target 0 lun 0".into(),
                    bus: "virtio-scsi".into(),
                    sectors: 200 << 21,
                    state: "installed".into(),
                    seq_read: Some(SeqRead { bytes: 64 << 20, ns: 100_000_000, mib_s: 640, block: 65_536 }),
                    rand_read: Some(RandRead { ops: 5, ns: 1, iops: 31_400, block: 4096, lat: stats::summarize(&mut lat).unwrap() }),
                    write: WriteState::Skipped(crate::guard::Skip::NoFreeSpace.reason().into()),
                    ..Disk::default()
                },
                Disk {
                    name: "virtio-blk 00:06.0".into(),
                    bus: "virtio-blk".into(),
                    sectors: 1 << 21,
                    boot_medium: true,
                    unmeasured: Some("boot medium".into()),
                    state: "foreign".into(),
                    ..Disk::default()
                },
            ],
            nics: vec![Nic { name: "virtio-net 00:03.0".into(), mac: Some([0x52, 0x54, 0, 1, 2, 3]), link: Some(true) }],
            other_nics: vec![(0x8086, 0x10fb)],
            time: TimeInfo {
                source: "kvmclock".into(),
                invariant_tsc: Some(true),
                kvmclock: Some(true),
                counter_hz: 2_500_000_000,
                deadline_timer: Some(true),
                rtc_unix: Some(1_761_913_696),
                rtc_plausible: true,
            },
            firmware: Firmware { kind: "UEFI (x86-64)".into(), bootloader: "Limine 12.9.4".into(), medium: "optical media (ISO)".into() },
            ram: Some(RamBench {
                buffer: 128 << 20,
                read_mib_s: 12_000,
                write_mib_s: 9_000,
                copy_mib_s: 6_000,
                latency: (12..=26).map(|b| (1u64 << b, 12 + (b as u64 - 12) * 40)).collect(),
            }),
            crypto: Some(CryptoBench {
                x25519_us_x10: 450,
                sign_us_x10: 700,
                verify_us_x10: 1900,
                handshake_us_x10: 5000,
                handshake_ticks: 1_250_000,
                tick_clock: "tsc".into(),
                aes_gcm_mib_s: 3000,
                chacha_mib_s: 1500,
                sha256_mib_s: 1900,
                crc32c_mib_s: 9000,
            }),
        }
    }

    fn texts(f: &Fake) -> String {
        f.texts
            .iter()
            .map(|t| t.2.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn draws_inside_the_screen_at_many_sizes() {
        let full = full_report();
        let empty = Report::default();
        let status = [
            Status {
                stage: "RAM latency".into(),
                step: 3,
                steps: 9,
                ..Status::default()
            },
            Status {
                done: true,
                steps: 9,
                step: 9,
                ..Status::default()
            },
            Status {
                prompt: Some(
                    "Type WIPE and Enter to write to virtio-blk 00:06.0, anything else skips"
                        .into(),
                ),
                typed: "WI".into(),
                steps: 9,
                step: 6,
                ..Status::default()
            },
        ];
        for (cols, rows, k) in [
            (40, 12, 8),
            (64, 30, 8),
            (80, 30, 8),
            (99, 60, 8),
            (100, 60, 8),
            (128, 96, 8),
            (120, 67, 16),
            (240, 135, 8),
            (200, 11, 8),
        ] {
            for r in [&full, &empty] {
                for s in &status {
                    let mut f = Fake {
                        cols,
                        rows,
                        k,
                        texts: vec![],
                        rects: 0,
                    };
                    draw(&mut f, r, s);
                }
            }
        }
    }

    #[test]
    fn shows_the_figures_and_panels() {
        let mut f = Fake {
            cols: 128,
            rows: 96,
            k: 8,
            texts: vec![],
            rects: 0,
        };
        draw(
            &mut f,
            &full_report(),
            &Status {
                done: true,
                steps: 9,
                step: 9,
                ..Status::default()
            },
        );
        let all = texts(&f);
        for want in [
            "ALDO TECH",
            "urMQTT DIAGNOSTIC",
            "SYSTEM",
            "MEMORY",
            "NETWORK",
            "DISKS",
            "PCI DEVICES",
            "RAM THROUGHPUT AND LATENCY",
            "DISK PERFORMANCE",
            "CRYPTO",
            "Xeon",
            "11.7 GiB/s",
            "640 MiB/s",
            "31.4k IOPS",
            "52:54:00:01:02:03",
            "link up",
            "Press any key to reboot",
            "no driver here",
            "no unallocated space",
        ] {
            assert!(all.contains(want), "missing {want:?} in:\n{all}");
        }
    }

    #[test]
    fn single_column_on_a_narrow_screen_still_has_every_panel_it_can_fit() {
        let mut f = Fake {
            cols: 80,
            rows: 200,
            k: 8,
            texts: vec![],
            rects: 0,
        };
        draw(&mut f, &full_report(), &Status::default());
        let all = texts(&f);
        for want in ["SYSTEM", "CRYPTO", "DISK PERFORMANCE"] {
            assert!(all.contains(want), "{want}");
        }
        assert!(f.texts.iter().all(|t| t.0 < 80));
    }

    #[test]
    fn the_prompt_shows_what_was_typed() {
        let mut f = Fake {
            cols: 100,
            rows: 50,
            k: 8,
            texts: vec![],
            rects: 0,
        };
        let s = Status {
            prompt: Some("Type WIPE".into()),
            typed: "WIP".into(),
            ..Status::default()
        };
        draw(&mut f, &Report::default(), &s);
        assert!(texts(&f).contains("Type WIPE > WIP_"));
    }

    #[test]
    fn wrapping() {
        assert_eq!(wrap("aa bb cc", 5, 3), ["aa bb", "cc"]);
        assert_eq!(wrap("aa bb cc dd ee", 5, 2), ["aa bb", "cc d~"]);
        assert_eq!(wrap("", 5, 2), Vec::<String>::new());
        assert_eq!(
            wrap("abcdefgh", 5, 2),
            ["abcdefgh"],
            "a long word stays whole"
        );
    }

    #[test]
    fn panels_are_clipped_not_overflowed() {
        // A short body: the PCI list of 40 entries must end with a "more" line.
        let mut f = Fake {
            cols: 128,
            rows: 40,
            k: 8,
            texts: vec![],
            rects: 0,
        };
        draw(&mut f, &full_report(), &Status::default());
        assert!(f.rects > 0);
    }
}
