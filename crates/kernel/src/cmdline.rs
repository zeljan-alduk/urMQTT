//! Kernel command line (from `limine.conf`).
//!
//! The command line is part of the immutable image, but test switches are
//! still honoured only in `dev` builds so a production image cannot be
//! talked into fault-injection modes.

/// Deliberate faults used by `make smoke` to verify exception reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestFault {
    /// Load from an unmapped address (data abort).
    DataAbort,
    /// `brk` that the handler must resume from.
    BrkResume,
    /// Permanently undefined instruction.
    Undefined,
    /// Kernel panic.
    Panic,
    /// Store to kernel text (must be a permission fault).
    WriteText,
    /// Branch into heap memory (must be an instruction abort, PXN).
    ExecHeap,
    /// Unbounded recursion into the guard page.
    StackOverflow,
    /// Load through a near-null pointer (lower half is disabled).
    NullDeref,
    /// Return through a corrupted, unsigned return address.
    Pac,
    /// Indirect branch to an instruction without a BTI landing pad.
    Bti,
    /// Store into the sealed CPU dispatch page (must be a permission fault).
    SealedWrite,
    /// x86_64: load from a non-canonical address (#GP).
    GeneralProtection,
    /// x86_64: a fault while delivering a fault (#DF, on its IST stack).
    DoubleFault,
}

/// Storage self-tests (M11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbTest {
    /// Measure batched vs unbatched commits, then continue booting.
    Bench,
    /// Write committed transactions forever (the host kills the VM).
    Crash,
    /// Check the rows written by `Crash`, then continue booting.
    Verify,
    /// Telemetry log: every core but the DB core appends records forever.
    LogCrash,
    /// Check the records written by `LogCrash`, then continue booting.
    LogVerify,
    /// Write telemetry records, then a deliberately torn one (the next
    /// boot must truncate it), then continue booting.
    LogTear,
    /// In-guest data-plane scaling benchmark on the worker cores.
    DpBench,
    /// A handler overruns the watchdog budget on purpose (M16).
    Watchdog,
    /// A handshake-class handler stays inside, then overruns, its own budget (ADR-071).
    WatchdogHandshake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootOptions {
    /// Power off (instead of reset) on panic, and after `URMQTT READY`
    /// unless `serve` is also given.
    pub smoke: bool,
    /// Keep serving after `URMQTT READY` even in smoke mode (client tests).
    pub serve: bool,
    pub test_fault: Option<TestFault>,
    pub db_test: Option<DbTest>,
    /// `log=error|warn|info|debug|trace`: lower the log level at run time
    /// (benchmarks: the emulated UART is slow).
    pub log_level: Option<urmqtt_config::LogLevel>,
    /// `heap_limit_mb=N`: admission behaves as if the heap had only N MiB
    /// (reconnect-storm tests on a host that cannot open enough sockets).
    pub heap_limit_mb: Option<u32>,
    /// `test=disk-fault:<spec>`: inject faults on the boot disk
    /// (`urmqtt_store::fault::FaultSpec`), e.g. a power cut after the N-th
    /// write of the first boot.
    pub disk_fault: Option<urmqtt_store::fault::FaultSpec>,
    /// `install`: the self-installing ISO's install entry (S1b). The only
    /// word a production image honours (ADR-052).
    pub install: bool,
    /// `live`: the ISO live entry (O3, ADR-054). Honoured everywhere, but
    /// the baked `storage.mode` still has to allow it ("auto" or "ram").
    pub live: bool,
    /// `diag`: the ISO's Diagnostic entry (O4, ADR-063). Honoured everywhere
    /// like `install`, but the baked `storage.diagnostic` must allow it.
    pub diag: bool,
    /// `diag-confirm=WIPE` (dev only): answers the write confirmation, so
    /// the smoke test can exercise the write path without a keyboard.
    pub diag_auto_confirm: bool,
    /// `diag-confirm-timeout=S` (dev only): how long the prompt waits.
    pub diag_confirm_timeout_s: Option<u64>,
    /// `install-countdown=S` (dev only): the installer's countdown instead
    /// of 30 s, for unattended tests.
    pub install_countdown_s: Option<u64>,
    /// `cpu-disable=aes,pmull,...` (dev only): features taken out of the
    /// CPU dispatch on top of `[cpu] disable`, to compare backends.
    pub cpu_disable: urmqtt_dispatch::CpuFeatures,
    /// `test=crypto-bench` (dev only): throughput of the dispatched
    /// primitives, then continue booting.
    pub crypto_bench: bool,
    /// `test=simd-irq` (dev only): crypto known answers on every core under
    /// an IPI storm for 10 s.
    pub simd_irq: bool,
    /// `test=ticket-rotate:S` (dev only): rotate the session-ticket keys
    /// every S seconds instead of 12 h (H2 rotation tests).
    pub ticket_rotate_s: Option<u64>,
    /// `test=slow-log:US` (dev only): every log line holds the sink lock US
    /// microseconds longer, like a trapped serial port or a scrolling
    /// framebuffer on a VPS (ADR-072).
    pub slow_log_us: Option<u32>,
    /// `test=log-sync` (dev only): keep the synchronous log path (the
    /// "before" of ADR-090), for comparison.
    pub log_sync: bool,
    /// `test=log-cost` (dev only): measure every log call and report the
    /// mean and worst every 5 s (`log: cost ...`). `slow-log` implies it.
    pub log_cost: bool,
    /// `test=log-flood:MS` (dev only): every data core logs one line every
    /// MS milliseconds from inside a watched handler (ADR-090).
    pub log_flood_ms: Option<u32>,
    /// `limits=bench` (dev only): the handshake limits are relaxed so one
    /// source address can load the server (`make bench`, ADR-082). A
    /// production image ignores the word; its bench counterpart is the
    /// `deploy/bench` configuration.
    pub bench_limits: bool,
    /// `sntp=a.b.c.d[:port]` (dev only): one more SNTP server on top of
    /// `[time] servers`, for the smoke test (a responder on the host,
    /// reached through QEMU's user network at 10.0.2.2).
    pub sntp_server: Option<([u8; 4], u16)>,
    /// `registry=allowlist`: allowlist mode even if the configuration says
    /// "open" (stricter only, for tests of one image in both modes).
    pub allowlist: bool,
    /// Options that were present but rejected or unknown.
    pub ignored: usize,
}

impl BootOptions {
    pub fn parse(cmdline: &str, dev_build: bool) -> Self {
        let mut o = Self::default();
        for word in cmdline.split_ascii_whitespace() {
            // The installer entry of the ISO menu: honoured everywhere (it
            // only runs with the hash-pinned installation image, S1b).
            if word == "install" {
                o.install = true;
                continue;
            }
            // The live entry: RAM-backed, ephemeral. A production image
            // honours the word only if its configuration allows live
            // mode (`storage.mode`), checked at boot.
            if word == "live" {
                o.live = true;
                continue;
            }
            // The diagnostic entry: detection and measurements; honoured
            // only if the configuration allows it (`storage.diagnostic`).
            if word == "diag" {
                o.diag = true;
                continue;
            }
            if !dev_build {
                o.ignored += 1;
                continue;
            }
            match word {
                "smoke" => o.smoke = true,
                "serve" => o.serve = true,
                "test=data-abort" => o.test_fault = Some(TestFault::DataAbort),
                "test=brk" => o.test_fault = Some(TestFault::BrkResume),
                "test=undef" => o.test_fault = Some(TestFault::Undefined),
                "test=panic" => o.test_fault = Some(TestFault::Panic),
                "test=write-text" => o.test_fault = Some(TestFault::WriteText),
                "test=exec-heap" => o.test_fault = Some(TestFault::ExecHeap),
                "test=stack-overflow" => o.test_fault = Some(TestFault::StackOverflow),
                "test=null" => o.test_fault = Some(TestFault::NullDeref),
                "test=pac" => o.test_fault = Some(TestFault::Pac),
                "test=bti" => o.test_fault = Some(TestFault::Bti),
                "test=db-bench" => o.db_test = Some(DbTest::Bench),
                "test=db-crash" => o.db_test = Some(DbTest::Crash),
                "test=db-verify" => o.db_test = Some(DbTest::Verify),
                "test=log-crash" => o.db_test = Some(DbTest::LogCrash),
                "test=log-verify" => o.db_test = Some(DbTest::LogVerify),
                "test=log-tear" => o.db_test = Some(DbTest::LogTear),
                "test=dp-bench" => o.db_test = Some(DbTest::DpBench),
                "test=watchdog" => o.db_test = Some(DbTest::Watchdog),
                "test=watchdog-handshake" => o.db_test = Some(DbTest::WatchdogHandshake),
                "log=error" => o.log_level = Some(urmqtt_config::LogLevel::Error),
                "log=warn" => o.log_level = Some(urmqtt_config::LogLevel::Warn),
                "log=info" => o.log_level = Some(urmqtt_config::LogLevel::Info),
                "log=debug" => o.log_level = Some(urmqtt_config::LogLevel::Debug),
                "log=trace" => o.log_level = Some(urmqtt_config::LogLevel::Trace),
                "registry=allowlist" => o.allowlist = true,
                "test=sealed-write" => o.test_fault = Some(TestFault::SealedWrite),
                "test=gp" => o.test_fault = Some(TestFault::GeneralProtection),
                "test=df" => o.test_fault = Some(TestFault::DoubleFault),
                "test=crypto-bench" => o.crypto_bench = true,
                "test=simd-irq" => o.simd_irq = true,
                "diag-confirm=WIPE" => o.diag_auto_confirm = true,
                "limits=bench" => o.bench_limits = true,
                w => {
                    if let Some(mb) = w
                        .strip_prefix("heap_limit_mb=")
                        .and_then(|v| v.parse().ok())
                    {
                        o.heap_limit_mb = Some(mb);
                    } else if let Some(Ok(d)) = w
                        .strip_prefix("cpu-disable=")
                        .map(urmqtt_dispatch::parse_disable_csv)
                    {
                        o.cpu_disable = d;
                    } else if let Some(s) = w
                        .strip_prefix("test=ticket-rotate:")
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|&s| s > 0)
                    {
                        o.ticket_rotate_s = Some(s);
                    } else if let Some(us) = w
                        .strip_prefix("test=slow-log:")
                        .and_then(|v| v.parse::<u32>().ok())
                    {
                        o.slow_log_us = Some(us);
                    } else if w == "test=log-sync" {
                        o.log_sync = true;
                    } else if w == "test=log-cost" {
                        o.log_cost = true;
                    } else if let Some(ms) = w
                        .strip_prefix("test=log-flood:")
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|&ms| ms > 0)
                    {
                        o.log_flood_ms = Some(ms);
                    } else if let Some(s) = w
                        .strip_prefix("diag-confirm-timeout=")
                        .and_then(|v| v.parse().ok())
                    {
                        o.diag_confirm_timeout_s = Some(s);
                    } else if let Some(s) = w
                        .strip_prefix("install-countdown=")
                        .and_then(|v| v.parse().ok())
                    {
                        o.install_countdown_s = Some(s);
                    } else if let Some(a) = w.strip_prefix("sntp=").and_then(parse_server) {
                        o.sntp_server = Some(a);
                    } else if let Some(f) = w
                        .strip_prefix("test=disk-fault:")
                        .and_then(urmqtt_store::fault::FaultSpec::parse)
                    {
                        o.disk_fault = Some(f);
                    } else {
                        o.ignored += 1;
                    }
                }
            }
        }
        o
    }
}

/// `a.b.c.d` or `a.b.c.d:port` (port 123 by default).
fn parse_server(s: &str) -> Option<([u8; 4], u16)> {
    let (ip, port) = match s.split_once(':') {
        Some((ip, p)) => (ip, p.parse::<u16>().ok().filter(|&p| p != 0)?),
        None => (s, urmqtt_sntp::PORT),
    };
    let mut o = [0u8; 4];
    let mut parts = ip.split('.');
    for b in &mut o {
        *b = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some((o, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERYTHING: &str = "smoke serve test=panic test=db-crash log=trace heap_limit_mb=1 \
                              registry=allowlist test=ticket-rotate:60 test=pac test=disk-fault:stop-after-write=3 bogus";

    /// H0-W11: a production image ignores the whole command line, test
    /// switches included; every word is counted as ignored.
    #[test]
    fn production_ignores_every_option() {
        let o = BootOptions::parse(EVERYTHING, false);
        assert_eq!(
            o,
            BootOptions {
                ignored: 11,
                ..BootOptions::default()
            }
        );
    }

    /// ADR-052: `install` is the one word production honours; every other
    /// word, the dev countdown included, is still ignored.
    #[test]
    fn production_honours_install_and_nothing_else() {
        let o = BootOptions::parse("install install-countdown=0 smoke serve", false);
        assert!(o.install);
        assert_eq!(o.install_countdown_s, None);
        assert!(!o.smoke && !o.serve);
        assert_eq!(o.ignored, 3);
        // Only the exact word.
        for w in ["Install", "install=1", "installx", "--install"] {
            assert!(!BootOptions::parse(w, false).install, "{w}");
        }
        assert_eq!(
            BootOptions::parse("install install-countdown=2", true).install_countdown_s,
            Some(2)
        );
    }

    /// ADR-054: `live` is the second word production honours, and only the
    /// exact word.
    #[test]
    fn production_honours_live_and_nothing_else() {
        let o = BootOptions::parse("live smoke serve", false);
        assert!(o.live && !o.install && !o.smoke && !o.serve);
        assert_eq!(o.ignored, 2);
        for w in ["Live", "live=1", "liver", "--live", "test=live"] {
            assert!(!BootOptions::parse(w, true).live, "{w}");
            assert!(!BootOptions::parse(w, false).live, "{w}");
        }
        let both = BootOptions::parse("live install", false);
        assert!(both.live && both.install, "install wins in the kernel");
        assert!(BootOptions::parse("live smoke", true).smoke);
    }

    /// ADR-063: `diag` is honoured by production (the configuration decides
    /// at boot); its test helpers are dev only.
    #[test]
    fn production_honours_diag_and_its_helpers_are_dev_only() {
        let o = BootOptions::parse("diag diag-confirm=WIPE diag-confirm-timeout=3 smoke", false);
        assert!(o.diag && !o.diag_auto_confirm && !o.smoke);
        assert_eq!((o.diag_confirm_timeout_s, o.ignored), (None, 3));
        let d = BootOptions::parse("diag diag-confirm=WIPE diag-confirm-timeout=3", true);
        assert!(d.diag && d.diag_auto_confirm);
        assert_eq!((d.diag_confirm_timeout_s, d.ignored), (Some(3), 0));
        for w in [
            "Diag",
            "diag=1",
            "diagnostic",
            "--diag",
            "diag-confirm=wipe",
        ] {
            assert!(!BootOptions::parse(w, true).diag, "{w}");
            assert!(!BootOptions::parse(w, true).diag_auto_confirm, "{w}");
        }
    }

    /// ADR-072: `test=slow-log:US` is a dev switch like the other tests.
    #[test]
    fn slow_log_is_dev_only() {
        assert_eq!(
            BootOptions::parse("test=slow-log:4000", true).slow_log_us,
            Some(4000)
        );
        assert_eq!(BootOptions::parse("test=slow-log:x", true).ignored, 1);
        let p = BootOptions::parse("test=slow-log:4000", false);
        assert_eq!((p.slow_log_us, p.ignored), (None, 1));
    }

    /// ADR-090: the log test words are dev switches too.
    #[test]
    fn log_test_words_are_dev_only() {
        let o = BootOptions::parse("test=log-sync test=log-cost test=log-flood:20", true);
        assert!(o.log_sync && o.log_cost);
        assert_eq!(o.log_flood_ms, Some(20));
        assert_eq!(BootOptions::parse("test=log-flood:0", true).ignored, 1);
        let p = BootOptions::parse("test=log-sync test=log-cost test=log-flood:20", false);
        assert!(!p.log_sync && !p.log_cost && p.log_flood_ms.is_none());
        assert_eq!(p.ignored, 3);
    }

    #[test]
    fn x86_fault_words_are_dev_only() {
        let gp = BootOptions::parse("smoke test=gp", true);
        assert_eq!(gp.test_fault, Some(TestFault::GeneralProtection));
        let df = BootOptions::parse("smoke test=df", true);
        assert_eq!(df.test_fault, Some(TestFault::DoubleFault));
        let prod = BootOptions::parse("test=df", false);
        assert_eq!((prod.test_fault, prod.ignored), (None, 1));
    }

    /// The relaxed bench limits exist in dev builds only.
    #[test]
    fn sntp_server_is_a_dev_word() {
        let d = BootOptions::parse("sntp=10.0.2.2:12300", true);
        assert_eq!(d.sntp_server, Some(([10, 0, 2, 2], 12300)));
        assert_eq!(
            BootOptions::parse("sntp=192.0.2.1", true).sntp_server,
            Some(([192, 0, 2, 1], 123))
        );
        for bad in [
            "sntp=",
            "sntp=1.2.3",
            "sntp=1.2.3.4.5",
            "sntp=1.2.3.4:0",
            "sntp=a.b.c.d",
            "sntp=1.2.3.256",
        ] {
            let o = BootOptions::parse(bad, true);
            assert_eq!((o.sntp_server, o.ignored), (None, 1), "{bad}");
        }
        let p = BootOptions::parse("sntp=10.0.2.2:12300", false);
        assert_eq!((p.sntp_server, p.ignored), (None, 1));
    }

    #[test]
    fn bench_limits_are_a_dev_word() {
        assert!(BootOptions::parse("serve limits=bench", true).bench_limits);
        let prod = BootOptions::parse("limits=bench", false);
        assert!(!prod.bench_limits);
        assert_eq!(prod.ignored, 1);
    }

    #[test]
    fn dev_honours_known_options_and_counts_the_rest() {
        let o = BootOptions::parse(EVERYTHING, true);
        assert!(o.smoke && o.serve && o.allowlist);
        assert_eq!(o.test_fault, Some(TestFault::Pac), "the last fault wins");
        assert_eq!(o.db_test, Some(DbTest::Crash));
        assert_eq!(o.log_level, Some(urmqtt_config::LogLevel::Trace));
        assert_eq!(o.heap_limit_mb, Some(1));
        assert_eq!(o.disk_fault.and_then(|f| f.stop_after_writes), Some(3));
        assert_eq!(o.ignored, 1);
        assert_eq!(BootOptions::parse("heap_limit_mb=x", true).ignored, 1);
        assert_eq!(o.ticket_rotate_s, Some(60));
        for w in [
            "test=ticket-rotate:0",
            "test=ticket-rotate:x",
            "test=ticket-rotate:",
        ] {
            let o = BootOptions::parse(w, true);
            assert_eq!((o.ticket_rotate_s, o.ignored), (None, 1), "{w}");
        }
    }
}
