//! The figures of one diagnostic run, filled in as the stages finish, and
//! their JSON document (the same numbers the dashboard draws).

use alloc::string::String;
use alloc::vec::Vec;

use crate::json::Json;
use crate::stats::Summary;
use crate::{fmt, names, time};

/// Version of the JSON document's shape.
pub const SCHEMA: u64 = 1;

#[derive(Debug, Clone, Default)]
pub struct Cpu {
    pub vendor: String,
    pub model: String,
    /// `family 6 model 0x55 stepping 7`, or the Arm part and revision.
    pub identity: String,
    /// CPUs the firmware lists.
    pub logical: u32,
    pub features: Vec<String>,
    /// The crypto units the CPU has (AES, carry-less multiply, SHA, ...).
    pub crypto_units: Vec<String>,
    /// What the sealed dispatch selected, e.g. `aes-gcm=aesni sha256=sha-ni`.
    pub crypto_backend: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Memory {
    /// RAM the memory map describes (usable plus bootloader and kernel).
    pub total: u64,
    /// Free for the kernel.
    pub usable: u64,
    /// Firmware, ACPI, framebuffer and other reserved ranges.
    pub reserved: u64,
}

#[derive(Debug, Clone)]
pub struct PciFn {
    pub bdf: String,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    /// A driver of this kernel uses it.
    pub driver: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct Nic {
    pub name: String,
    pub mac: Option<[u8; 6]>,
    pub link: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct TimeInfo {
    /// Where the time base's frequency came from.
    pub source: String,
    /// x86: CPUID says the TSC is invariant.
    pub invariant_tsc: Option<bool>,
    /// x86: the KVM paravirtual clock supplied the frequency.
    pub kvmclock: Option<bool>,
    pub counter_hz: u64,
    pub deadline_timer: Option<bool>,
    /// The firmware's RTC at boot (Unix seconds), if the bootloader gave it.
    pub rtc_unix: Option<u64>,
    /// The RTC is before the image's build time: it is wrong.
    pub rtc_plausible: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Firmware {
    /// `UEFI`, `BIOS`, ...
    pub kind: String,
    pub bootloader: String,
    /// `optical (ISO)` or `disk`.
    pub medium: String,
}

#[derive(Debug, Clone, Default)]
pub struct RamBench {
    /// Size of the buffer the throughput figures used.
    pub buffer: u64,
    pub read_mib_s: u64,
    pub write_mib_s: u64,
    pub copy_mib_s: u64,
    /// `(working set in bytes, ns per dependent load in tenths)`.
    pub latency: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Default)]
pub struct CryptoBench {
    pub x25519_us_x10: u64,
    pub sign_us_x10: u64,
    pub verify_us_x10: u64,
    /// One mutual-TLS handshake on the server: key exchange, one signature,
    /// two verifications (client certificate and its chain), in tenths of us.
    pub handshake_us_x10: u64,
    /// The same in ticks of `tick_clock`.
    pub handshake_ticks: u64,
    pub tick_clock: String,
    pub aes_gcm_mib_s: u64,
    pub chacha_mib_s: u64,
    pub sha256_mib_s: u64,
    pub crc32c_mib_s: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SeqRead {
    pub bytes: u64,
    pub ns: u64,
    pub mib_s: u64,
    pub block: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RandRead {
    pub ops: u64,
    pub ns: u64,
    pub iops: u64,
    pub block: u64,
    /// Per-request latency in nanoseconds.
    pub lat: Summary,
}

#[derive(Debug, Clone, Default)]
pub enum WriteState {
    #[default]
    Pending,
    Skipped(String),
    Done {
        bytes: u64,
        ns: u64,
        mib_s: u64,
        first_lba: u64,
        sectors: u64,
        verified: bool,
    },
    Failed(String),
}

#[derive(Debug, Clone, Default)]
pub struct Disk {
    pub name: String,
    pub bus: String,
    pub model: Option<String>,
    pub sectors: u64,
    pub read_only: bool,
    pub boot_medium: bool,
    /// `installed`, `blank`, `foreign`, `unreadable`, or `not read`.
    pub state: String,
    /// Why the disk was not measured at all.
    pub unmeasured: Option<String>,
    pub seq_read: Option<SeqRead>,
    pub rand_read: Option<RandRead>,
    pub write: WriteState,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub version: String,
    pub arch: String,
    pub env: String,
    pub hypervisor: String,
    pub cpu: Cpu,
    pub memory: Memory,
    pub pci: Vec<PciFn>,
    pub disks: Vec<Disk>,
    pub nics: Vec<Nic>,
    /// Network controllers with no driver here: `(vendor, device)`.
    pub other_nics: Vec<(u16, u16)>,
    pub time: TimeInfo,
    pub firmware: Firmware,
    pub ram: Option<RamBench>,
    pub crypto: Option<CryptoBench>,
}

fn strs(j: &mut Json, key: &str, v: &[String]) {
    j.begin_arr(Some(key));
    for s in v {
        j.str(None, s);
    }
    j.end_arr();
}

fn summary(j: &mut Json, s: &Summary) {
    j.begin_obj(Some("latency_ns"));
    j.u64(Some("min"), s.min);
    j.u64(Some("p50"), s.p50);
    j.u64(Some("p90"), s.p90);
    j.u64(Some("p99"), s.p99);
    j.u64(Some("max"), s.max);
    j.u64(Some("mean"), s.mean);
    j.u64(Some("samples"), s.count as u64);
    j.end_obj();
}

impl Disk {
    pub fn bytes(&self) -> u64 {
        self.sectors * 512
    }
}

impl Report {
    /// The JSON document: one line, no secrets (MAC addresses and the disk
    /// sizes are the most identifying things in it).
    pub fn to_json(&self) -> String {
        let mut j = Json::new();
        j.begin_obj(None);
        j.u64(Some("urmqtt_diag"), SCHEMA);
        j.str(Some("version"), &self.version);
        j.str(Some("arch"), &self.arch);
        j.str(Some("env"), &self.env);
        j.str(Some("hypervisor"), &self.hypervisor);

        let c = &self.cpu;
        j.begin_obj(Some("cpu"));
        j.str(Some("vendor"), &c.vendor);
        j.str(Some("model"), &c.model);
        j.str(Some("identity"), &c.identity);
        j.u64(Some("logical"), u64::from(c.logical));
        strs(&mut j, "features", &c.features);
        strs(&mut j, "crypto_units", &c.crypto_units);
        j.str(Some("crypto_backend"), &c.crypto_backend);
        j.end_obj();

        let m = &self.memory;
        j.begin_obj(Some("memory"));
        j.u64(Some("total_bytes"), m.total);
        j.u64(Some("usable_bytes"), m.usable);
        j.u64(Some("reserved_bytes"), m.reserved);
        j.end_obj();

        j.begin_arr(Some("pci"));
        for p in &self.pci {
            j.begin_obj(None);
            j.str(Some("bdf"), &p.bdf);
            j.str(Some("vendor"), &alloc::format!("{:04x}", p.vendor));
            j.str(Some("device"), &alloc::format!("{:04x}", p.device));
            j.str(Some("vendor_name"), &names::pci_vendor(p.vendor));
            j.str(Some("class"), names::pci_class(p.class, p.subclass));
            j.opt_str(Some("driver"), p.driver);
            j.end_obj();
        }
        j.end_arr();

        j.begin_arr(Some("disks"));
        for d in &self.disks {
            j.begin_obj(None);
            j.str(Some("name"), &d.name);
            j.str(Some("bus"), &d.bus);
            j.opt_str(Some("model"), d.model.as_deref());
            j.u64(Some("bytes"), d.bytes());
            j.bool(Some("read_only"), d.read_only);
            j.bool(Some("boot_medium"), d.boot_medium);
            j.str(Some("state"), &d.state);
            j.opt_str(Some("unmeasured"), d.unmeasured.as_deref());
            match &d.seq_read {
                Some(s) => {
                    j.begin_obj(Some("seq_read"));
                    j.u64(Some("mib_s"), s.mib_s);
                    j.u64(Some("bytes"), s.bytes);
                    j.u64(Some("block"), s.block);
                    j.end_obj();
                }
                None => j.null(Some("seq_read")),
            }
            match &d.rand_read {
                Some(r) => {
                    j.begin_obj(Some("rand_read"));
                    j.u64(Some("block"), r.block);
                    j.u64(Some("iops"), r.iops);
                    j.u64(Some("ops"), r.ops);
                    summary(&mut j, &r.lat);
                    j.end_obj();
                }
                None => j.null(Some("rand_read")),
            }
            j.begin_obj(Some("seq_write"));
            match &d.write {
                WriteState::Pending => j.str(Some("status"), "pending"),
                WriteState::Skipped(why) => {
                    j.str(Some("status"), "skipped");
                    j.str(Some("reason"), why);
                }
                WriteState::Failed(why) => {
                    j.str(Some("status"), "failed");
                    j.str(Some("reason"), why);
                }
                WriteState::Done {
                    bytes,
                    mib_s,
                    first_lba,
                    sectors,
                    verified,
                    ..
                } => {
                    j.str(Some("status"), "done");
                    j.u64(Some("mib_s"), *mib_s);
                    j.u64(Some("bytes"), *bytes);
                    j.u64(Some("first_lba"), *first_lba);
                    j.u64(Some("sectors"), *sectors);
                    j.bool(Some("verified"), *verified);
                }
            }
            j.end_obj();
            j.end_obj();
        }
        j.end_arr();

        j.begin_arr(Some("nics"));
        for n in &self.nics {
            j.begin_obj(None);
            j.str(Some("name"), &n.name);
            match n.mac {
                Some(m) => j.str(Some("mac"), &fmt::mac(m)),
                None => j.null(Some("mac")),
            }
            match n.link {
                Some(l) => j.bool(Some("link"), l),
                None => j.null(Some("link")),
            }
            j.end_obj();
        }
        for (v, d) in &self.other_nics {
            j.begin_obj(None);
            j.str(Some("name"), &alloc::format!("{v:04x}:{d:04x} (no driver)"));
            j.null(Some("mac"));
            j.null(Some("link"));
            j.end_obj();
        }
        j.end_arr();

        let t = &self.time;
        j.begin_obj(Some("time"));
        j.str(Some("source"), &t.source);
        match t.invariant_tsc {
            Some(b) => j.bool(Some("invariant_tsc"), b),
            None => j.null(Some("invariant_tsc")),
        }
        match t.kvmclock {
            Some(b) => j.bool(Some("kvmclock"), b),
            None => j.null(Some("kvmclock")),
        }
        j.u64(Some("counter_hz"), t.counter_hz);
        match t.deadline_timer {
            Some(b) => j.bool(Some("deadline_timer"), b),
            None => j.null(Some("deadline_timer")),
        }
        match t.rtc_unix {
            Some(u) => {
                j.str(Some("rtc"), &time::iso8601(u));
                j.u64(Some("rtc_unix"), u);
            }
            None => {
                j.null(Some("rtc"));
                j.null(Some("rtc_unix"));
            }
        }
        j.bool(Some("rtc_plausible"), t.rtc_plausible);
        j.end_obj();

        let f = &self.firmware;
        j.begin_obj(Some("firmware"));
        j.str(Some("kind"), &f.kind);
        j.str(Some("bootloader"), &f.bootloader);
        j.str(Some("boot_medium"), &f.medium);
        j.end_obj();

        match &self.ram {
            Some(r) => {
                j.begin_obj(Some("ram"));
                j.u64(Some("buffer_bytes"), r.buffer);
                j.u64(Some("read_mib_s"), r.read_mib_s);
                j.u64(Some("write_mib_s"), r.write_mib_s);
                j.u64(Some("copy_mib_s"), r.copy_mib_s);
                j.begin_arr(Some("latency"));
                for &(size, ns10) in &r.latency {
                    j.begin_obj(None);
                    j.u64(Some("bytes"), size);
                    j.x10(Some("ns"), ns10);
                    j.end_obj();
                }
                j.end_arr();
                j.end_obj();
            }
            None => j.null(Some("ram")),
        }
        match &self.crypto {
            Some(c) => {
                j.begin_obj(Some("crypto"));
                j.x10(Some("x25519_us"), c.x25519_us_x10);
                j.x10(Some("ecdsa_sign_us"), c.sign_us_x10);
                j.x10(Some("ecdsa_verify_us"), c.verify_us_x10);
                j.x10(Some("handshake_us"), c.handshake_us_x10);
                j.u64(Some("handshake_ticks"), c.handshake_ticks);
                j.str(Some("tick_clock"), &c.tick_clock);
                j.u64(Some("aes_gcm_mib_s"), c.aes_gcm_mib_s);
                j.u64(Some("chacha20_poly1305_mib_s"), c.chacha_mib_s);
                j.u64(Some("sha256_mib_s"), c.sha256_mib_s);
                j.u64(Some("crc32c_mib_s"), c.crc32c_mib_s);
                j.end_obj();
            }
            None => j.null(Some("crypto")),
        }
        j.end_obj();
        j.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats;

    fn sample() -> Report {
        let mut lat = [100u64, 200, 300, 400, 500];
        Report {
            version: "v0".into(),
            arch: "x86_64".into(),
            env: "dev".into(),
            hypervisor: "KVM".into(),
            cpu: Cpu {
                vendor: "GenuineIntel".into(),
                model: "Test \"CPU\"".into(),
                logical: 4,
                features: vec!["aes".into(), "avx2".into()],
                ..Cpu::default()
            },
            memory: Memory {
                total: 1 << 30,
                usable: 900 << 20,
                reserved: 100 << 20,
            },
            pci: vec![PciFn {
                bdf: "00:03.0".into(),
                vendor: 0x1af4,
                device: 0x1041,
                class: 2,
                subclass: 0,
                driver: Some("virtio-net"),
            }],
            disks: vec![Disk {
                name: "virtio-blk 00:04.0".into(),
                bus: "virtio-blk".into(),
                sectors: 131_072,
                state: "blank".into(),
                seq_read: Some(SeqRead {
                    bytes: 1 << 26,
                    ns: 1_000_000_000,
                    mib_s: 64,
                    block: 65_536,
                }),
                rand_read: Some(RandRead {
                    ops: 5,
                    ns: 1000,
                    iops: 5_000_000,
                    block: 4096,
                    lat: stats::summarize(&mut lat).unwrap(),
                }),
                write: WriteState::Skipped("not confirmed on the keyboard".into()),
                ..Disk::default()
            }],
            nics: vec![Nic {
                name: "virtio-net".into(),
                mac: Some([0x52, 0x54, 0, 1, 2, 3]),
                link: Some(true),
            }],
            time: TimeInfo {
                source: "kvmclock".into(),
                invariant_tsc: Some(true),
                kvmclock: Some(true),
                counter_hz: 2_000_000_000,
                deadline_timer: Some(true),
                rtc_unix: Some(1_761_913_696),
                rtc_plausible: true,
            },
            ram: Some(RamBench {
                buffer: 64 << 20,
                read_mib_s: 9000,
                write_mib_s: 7000,
                copy_mib_s: 5000,
                latency: vec![(4096, 12), (1 << 26, 853)],
            }),
            ..Report::default()
        }
    }

    /// Checks the document is well formed JSON with a minimal parser.
    fn check_json(s: &str) {
        let b = s.as_bytes();
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc = false;
        for &c in b {
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
                assert!(c >= 0x20, "raw control byte in a string");
                continue;
            }
            match c {
                b'"' => in_str = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    assert!(depth >= 0);
                }
                _ => {}
            }
        }
        assert_eq!((depth, in_str), (0, false));
        assert!(!s.contains('\n'), "one line");
        assert!(!s.contains(",}") && !s.contains(",]") && !s.contains("{,") && !s.contains("[,"));
    }

    #[test]
    fn document_has_the_expected_keys() {
        let json = sample().to_json();
        check_json(&json);
        for key in [
            "\"urmqtt_diag\":1",
            "\"cpu\":{",
            "\"memory\":{\"total_bytes\":1073741824",
            "\"pci\":[{\"bdf\":\"00:03.0\"",
            "\"vendor_name\":\"Red Hat (virtio)\"",
            "\"disks\":[{",
            "\"seq_read\":{\"mib_s\":64",
            "\"rand_read\":{\"block\":4096,\"iops\":5000000",
            "\"p99\":500",
            "\"seq_write\":{\"status\":\"skipped\",\"reason\":\"not confirmed on the keyboard\"}",
            "\"mac\":\"52:54:00:01:02:03\"",
            "\"invariant_tsc\":true",
            "\"rtc\":\"2025-10-31T12:28:16Z\"",
            "\"read_mib_s\":9000",
            "{\"bytes\":4096,\"ns\":1.2}",
            "\"crypto\":null",
            "\"model\":\"Test \\\"CPU\\\"\"",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
    }

    #[test]
    fn an_empty_report_is_still_valid() {
        let json = Report::default().to_json();
        check_json(&json);
        assert!(json.contains("\"ram\":null"));
        assert!(json.contains("\"disks\":[]"));
    }

    #[test]
    fn write_states() {
        let mut r = sample();
        r.disks[0].write = WriteState::Done {
            bytes: 64 << 20,
            ns: 1,
            mib_s: 210,
            first_lba: 2048,
            sectors: 131_072,
            verified: true,
        };
        let json = r.to_json();
        check_json(&json);
        assert!(json.contains("\"seq_write\":{\"status\":\"done\",\"mib_s\":210"));
        r.disks[0].write = WriteState::Failed("device error".into());
        assert!(
            r.to_json()
                .contains("\"status\":\"failed\",\"reason\":\"device error\"")
        );
        r.disks[0].write = WriteState::Pending;
        assert!(r.to_json().contains("\"status\":\"pending\""));
    }
}
