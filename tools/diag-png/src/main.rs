//! `urmqtt-diag-png REPORT.json OUT.png [WIDTHxHEIGHT]`
//!
//! The Diagnostic entry shows a dashboard on the framebuffer and writes the
//! same figures as one JSON line. A machine with no visible console (a VPS)
//! publishes that JSON as the retained `$SYS/diag/report` (`diag-serve`).
//! This tool draws the dashboard from the JSON with the code the kernel
//! uses (`urmqtt_diag::dash::draw` on `urmqtt_log::fbcon::FbConsole`), so the
//! picture is the screen the machine would have shown. Default size 1280x800.

mod json;
mod png;

use std::process::ExitCode;

use urmqtt_diag::dash::{self, Canvas, Rgb, Status};
use urmqtt_diag::report::{CryptoBench, Firmware, Memory, Nic, PciFn, RamBench, Report, TimeInfo};
use urmqtt_log::fbcon::{FbConsole, PixelFormat};

use json::Value;

struct Fb<'a, 'b>(&'a mut FbConsole<'b>);

impl Canvas for Fb<'_, '_> {
    fn cols(&self) -> usize {
        self.0.cols()
    }
    fn rows(&self) -> usize {
        self.0.rows()
    }
    fn cell_px(&self) -> usize {
        self.0.cell_px()
    }
    fn fill_px(&mut self, x: usize, y: usize, w: usize, h: usize, c: Rgb) {
        self.0.fill_rect(x, y, w, h, c);
    }
    fn text(&mut self, col: usize, row: usize, s: &str, fg: Rgb, bg: Rgb) {
        self.0.text_at(col, row, s, fg, bg);
    }
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn num(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_f64).map_or(0, |f| f as u64)
}

/// A figure written in tenths (`x10`) back to tenths.
fn tenths(v: &Value, k: &str) -> u64 {
    v.get(k)
        .and_then(Value::as_f64)
        .map_or(0, |f| (f * 10.0).round() as u64)
}

fn strings(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_arr)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn hex(s: &str) -> u16 {
    u16::from_str_radix(s, 16).unwrap_or(0)
}

fn mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut it = s.split(':');
    for b in &mut out {
        *b = u8::from_str_radix(it.next()?, 16).ok()?;
    }
    Some(out)
}

/// The report of the JSON; fields a run did not produce stay empty.
fn report(j: &Value) -> Result<Report, String> {
    if num(j, "urmqtt_diag") != 1 {
        return Err("not a urMQTT diagnostic report (urmqtt_diag != 1)".into());
    }
    let cpu = j.get("cpu").ok_or("no cpu")?;
    let mem = j.get("memory").ok_or("no memory")?;
    let t = j.get("time").ok_or("no time")?;
    let fw = j.get("firmware").ok_or("no firmware")?;
    let mut r = Report {
        version: str_of(j, "version"),
        arch: str_of(j, "arch"),
        env: str_of(j, "env"),
        hypervisor: str_of(j, "hypervisor"),
        cpu: urmqtt_diag::report::Cpu {
            vendor: str_of(cpu, "vendor"),
            model: str_of(cpu, "model"),
            identity: str_of(cpu, "identity"),
            logical: num(cpu, "logical") as u32,
            features: strings(cpu, "features"),
            crypto_units: strings(cpu, "crypto_units"),
            crypto_backend: str_of(cpu, "crypto_backend"),
        },
        memory: Memory {
            total: num(mem, "total_bytes"),
            usable: num(mem, "usable_bytes"),
            reserved: num(mem, "reserved_bytes"),
        },
        time: TimeInfo {
            source: str_of(t, "source"),
            invariant_tsc: t.get("invariant_tsc").and_then(Value::as_bool),
            kvmclock: t.get("kvmclock").and_then(Value::as_bool),
            counter_hz: num(t, "counter_hz"),
            deadline_timer: t.get("deadline_timer").and_then(Value::as_bool),
            rtc_unix: t.get("rtc_unix").and_then(Value::as_f64).map(|f| f as u64),
            rtc_plausible: t
                .get("rtc_plausible")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        firmware: Firmware {
            kind: str_of(fw, "kind"),
            bootloader: str_of(fw, "bootloader"),
            medium: str_of(fw, "boot_medium"),
        },
        ..Report::default()
    };
    for p in j.get("pci").and_then(Value::as_arr).unwrap_or_default() {
        r.pci.push(PciFn {
            bdf: str_of(p, "bdf"),
            vendor: hex(&str_of(p, "vendor")),
            device: hex(&str_of(p, "device")),
            class: class_code(&str_of(p, "class")).0,
            subclass: class_code(&str_of(p, "class")).1,
            driver: p.get("driver").and_then(Value::as_str).map(leak),
        });
    }
    for n in j.get("nics").and_then(Value::as_arr).unwrap_or_default() {
        r.nics.push(Nic {
            name: str_of(n, "name"),
            mac: mac(&str_of(n, "mac")),
            link: n.get("link").and_then(Value::as_bool),
        });
    }
    if let Some(b) = j.get("ram").filter(|b| !matches!(b, Value::Null)) {
        r.ram = Some(RamBench {
            buffer: num(b, "buffer_bytes"),
            read_mib_s: num(b, "read_mib_s"),
            write_mib_s: num(b, "write_mib_s"),
            copy_mib_s: num(b, "copy_mib_s"),
            latency: b
                .get("latency")
                .and_then(Value::as_arr)
                .unwrap_or_default()
                .iter()
                .map(|e| (num(e, "bytes"), tenths(e, "ns")))
                .collect(),
        });
    }
    if let Some(c) = j.get("crypto").filter(|c| !matches!(c, Value::Null)) {
        r.crypto = Some(CryptoBench {
            x25519_us_x10: tenths(c, "x25519_us"),
            sign_us_x10: tenths(c, "ecdsa_sign_us"),
            verify_us_x10: tenths(c, "ecdsa_verify_us"),
            handshake_us_x10: tenths(c, "handshake_us"),
            handshake_ticks: num(c, "handshake_ticks"),
            tick_clock: str_of(c, "tick_clock"),
            aes_gcm_mib_s: num(c, "aes_gcm_mib_s"),
            aes_xts_mib_s: num(c, "aes_xts_mib_s"),
            aes_xts_hardware: c
                .get("aes_xts_hardware")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            chacha_mib_s: num(c, "chacha20_poly1305_mib_s"),
            sha256_mib_s: num(c, "sha256_mib_s"),
            crc32c_mib_s: num(c, "crc32c_mib_s"),
        });
    }
    Ok(r)
}

/// The class names `urmqtt_diag::names` prints back to the PCI class code
/// (the JSON carries the name, the dashboard prints the name again).
fn class_code(name: &str) -> (u8, u8) {
    (0..=0xffu8)
        .flat_map(|c| (0..=0xffu8).map(move |s| (c, s)))
        .find(|&(c, s)| urmqtt_diag::names::pci_class(c, s) == name)
        .unwrap_or((0xff, 0xff))
}

fn render(r: &Report, w: usize, h: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; w * h * 4];
    // BGRX, the layout of UEFI GOP framebuffers.
    let fmt = PixelFormat {
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };
    let mut con = FbConsole::new(&mut buf, w, h, w * 4, fmt).ok_or("no console for this size")?;
    let status = Status {
        stage: "Done".into(),
        step: 3,
        steps: 3,
        done: true,
        ..Status::default()
    };
    dash::draw(&mut Fb(&mut con), r, &status);
    let mut rgb = Vec::with_capacity(w * h * 3);
    for px in buf.as_chunks::<4>().0 {
        rgb.extend_from_slice(&[px[2], px[1], px[0]]);
    }
    Ok(png::encode(w as u32, h as u32, &rgb))
}

fn run() -> Result<(), String> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        return Err("usage: urmqtt-diag-png REPORT.json OUT.png [WIDTHxHEIGHT]".into());
    }
    let (w, h) = match a.get(3) {
        Some(s) => {
            let (w, h) = s.split_once('x').ok_or("size is WIDTHxHEIGHT")?;
            (
                w.parse().map_err(|_| "bad width")?,
                h.parse().map_err(|_| "bad height")?,
            )
        }
        None => (1280, 800),
    };
    let text = std::fs::read_to_string(&a[1]).map_err(|e| format!("{}: {e}", a[1]))?;
    let text = text
        .trim()
        .strip_prefix("URMQTT-DIAG-JSON ")
        .unwrap_or(text.trim());
    let r = report(&json::parse(text)?)?;
    std::fs::write(&a[2], render(&r, w, h)?).map_err(|e| format!("{}: {e}", a[2]))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("urmqtt-diag-png: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the kernel writes (`Report::to_json`) comes back as the report.
    #[test]
    fn the_kernels_json_draws_a_dashboard() {
        let mut r = Report {
            version: "v0.0.0-test".into(),
            arch: "aarch64".into(),
            ram: Some(RamBench {
                buffer: 1 << 27,
                read_mib_s: 6000,
                ..RamBench::default()
            }),
            ..Report::default()
        };
        r.cpu.model = "Neoverse N1".into();
        r.cpu.logical = 2;
        r.memory.total = 4 << 30;
        let text = r.to_json();
        let back = report(&json::parse(&text).unwrap()).unwrap();
        assert_eq!(
            (back.version.as_str(), back.cpu.logical),
            ("v0.0.0-test", 2)
        );
        assert_eq!(back.ram.as_ref().unwrap().read_mib_s, 6000);
        let png = render(&back, 1280, 800).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn a_foreign_document_is_refused() {
        assert!(report(&json::parse("{\"a\":1}").unwrap()).is_err());
    }
}
