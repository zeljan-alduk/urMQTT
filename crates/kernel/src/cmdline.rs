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
                "log=error" => o.log_level = Some(urmqtt_config::LogLevel::Error),
                "log=warn" => o.log_level = Some(urmqtt_config::LogLevel::Warn),
                "log=info" => o.log_level = Some(urmqtt_config::LogLevel::Info),
                "log=debug" => o.log_level = Some(urmqtt_config::LogLevel::Debug),
                "log=trace" => o.log_level = Some(urmqtt_config::LogLevel::Trace),
                "registry=allowlist" => o.allowlist = true,
                w => {
                    if let Some(mb) = w
                        .strip_prefix("heap_limit_mb=")
                        .and_then(|v| v.parse().ok())
                    {
                        o.heap_limit_mb = Some(mb);
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

#[cfg(test)]
mod tests {
    use super::*;

    const EVERYTHING: &str = "smoke serve test=panic test=db-crash log=trace heap_limit_mb=1 \
                              registry=allowlist test=pac test=disk-fault:stop-after-write=3 bogus";

    /// H0-W11: a production image ignores the whole command line, test
    /// switches included; every word is counted as ignored.
    #[test]
    fn production_ignores_every_option() {
        let o = BootOptions::parse(EVERYTHING, false);
        assert_eq!(
            o,
            BootOptions {
                ignored: 10,
                ..BootOptions::default()
            }
        );
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
    }
}
