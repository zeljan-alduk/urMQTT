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
                _ => o.ignored += 1,
            }
        }
        o
    }
}
