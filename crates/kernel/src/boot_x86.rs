//! The x86_64 side of the boot sequence (`boot.rs` calls these seams).
//!
//! `_start` (`arch-x86_64::entry`) has already checked the x86-64-v2
//! baseline and enabled the x87/SSE state; the shared sequence takes over
//! in `urmqtt_kmain`. What differs from AArch64 lives here: COM1 is the
//! console from the first instruction, ACPI is the only platform
//! description, the time base is the TSC (calibrated against the HPET or
//! the ACPI PM timer), and interrupts go through the APICs.

#![allow(unsafe_code)]

use urmqtt_arch::features::{self, Census, Features, Identity};
use urmqtt_arch::time::{PmTimer, Sources};
use urmqtt_arch::{cpu, serial, time};
use urmqtt_log::{info, warn};
use urmqtt_platform::PlatformInfo;
use urmqtt_platform::x86::AddrSpace;

use crate::boot::{EXECUTABLE_ADDRESS, fatal_fmt};
use crate::cmdline::TestFault;
use crate::memory;
use crate::{console, irq, trap};

/// The architecture's name, for `$SYS/broker/arch` (O1).
pub(crate) const ARCH: &str = "x86_64";

/// Appended to the `URMQTT BOOT` line.
pub(crate) const BOOT_TAG: &str = " arch=x86_64";

/// The boot log's name for the privilege level.
pub(crate) const PRIVILEGE_LABEL: &str = "cpl";

/// The text after `vm: switched to kernel tables`.
pub(crate) const ACTIVATED: &str = "(CR3), lower half unmapped, NX and WP on";

/// COM1 and the framebuffer take the log before anything else runs.
pub(crate) fn early_console() {
    if serial::init() {
        console::init_serial();
    }
}

/// What the early hardware setup found, for the boot log.
pub(crate) struct EarlyHw {
    time: time::Info,
}

/// Starts the clock: the TSC frequency from the hypervisor, CPUID, the HPET
/// or the PM timer. Device mappings are made in the bootloader's tables and
/// replayed into the kernel's.
pub(crate) fn early_hw(platform: Option<&PlatformInfo>, mmio_ok: bool, _dev: bool) -> EarlyHw {
    let x86 = platform.and_then(|p| p.x86);
    let hpet_mmio = x86
        .and_then(|x| x.hpet)
        .filter(|_| mmio_ok)
        .and_then(|h| memory::map_mmio(h.address, 0x1000).ok())
        .map(|va| va as usize);
    let pm_timer = x86.and_then(|x| x.fadt).and_then(|f| {
        f.pm_tmr.map(|port| PmTimer {
            port,
            wide: f.pm_tmr_32bit,
        })
    });
    let src = Sources {
        hpet_mmio,
        pm_timer,
        virt_to_phys: Some(kernel_virt_to_phys),
    };
    if let Some(x) = x86 {
        let io = |s: AddrSpace, a: u64| match s {
            AddrSpace::Io => u16::try_from(a).ok(),
            _ => None,
        };
        let f = x.fadt;
        urmqtt_arch::power::set_acpi(&urmqtt_arch::power::Acpi {
            pm1a_cnt: f.and_then(|f| f.pm1a_cnt),
            pm1b_cnt: f.and_then(|f| f.pm1b_cnt),
            s5: x.s5.map(|s| (s.a, s.b)),
            reset_port: f
                .and_then(|f| f.reset)
                .and_then(|r| Some((io(r.space, r.address)?, r.value))),
        });
    }
    match time::init(&src) {
        Ok(time) => {
            *TIME_INFO.lock() = Some(time);
            EarlyHw { time }
        }
        Err(e) => fatal_fmt(format_args!(
            "no usable time base ({e:?}): the platform offers no HPET, PM timer or TSC frequency"
        )),
    }
}

/// Physical address of a kernel image address (for the paravirtual clock
/// page, a static).
fn kernel_virt_to_phys(va: usize) -> u64 {
    EXECUTABLE_ADDRESS.response().map_or(0, |e| {
        (va as u64).wrapping_sub(e.virtual_base) + e.physical_base
    })
}

impl EarlyHw {
    pub(crate) fn log(&self, platform: Option<&PlatformInfo>) {
        let i = self.time;
        info!(
            "time: tsc {} Hz from {:?}, invariant={}, deadline timer={}",
            i.tsc_hz, i.source, i.invariant_tsc, i.tsc_deadline
        );
        if !i.invariant_tsc {
            warn!("time: the TSC is not invariant: it may stop in deep C-states");
        }
        if let Some(x) = platform.and_then(|p| p.x86) {
            info!("acpi: {x}");
            match (x.fadt.and_then(|f| f.pm1a_cnt), x.s5) {
                (Some(port), Some(s)) => info!(
                    "power: ACPI S5 through PM1a_CNT {port:#x} (SLP_TYP {}/{}), then the hypervisor's ports",
                    s.a, s.b
                ),
                _ => info!(
                    "power: no ACPI S5 (no PM1a_CNT or no \\_S5 in the DSDT): hypervisor ports only"
                ),
            }
        }
    }
}

/// XSAVE state, CPUID summary and the features the dispatch looks at.
pub(crate) fn cpu_summary() -> Features {
    // XSAVE state before CPUID is read: the census reports XCR0.
    let xcr0 = cpu::enable_extended_state();
    let id = features::read_id_regs();
    info!("cpu: {}", Identity(&id));
    info!("cpu features: {}", Census(&id));
    if xcr0 == 0 {
        warn!("cpu: no XSAVE, x87/SSE state only");
    }
    let f = Features::decode(id);
    info!(
        "cpu dispatch inputs: aes={} pclmul={} sha={} sse4.2={} avx2={} bmi2+adx={} rdrand={} rdseed={}",
        f.aes, f.pclmul, f.sha, f.sse42, f.avx2, f.bmi2_adx, f.rdrand, f.rdseed
    );
    f
}

/// What `time::init` found, kept for the diagnostic (O4).
static TIME_INFO: urmqtt_sync::sync::SpinLock<Option<time::Info>> =
    urmqtt_sync::sync::SpinLock::new(None);

/// CPU identity for the diagnostic (O4).
pub(crate) fn diag_cpu() -> crate::diag::CpuFacts {
    let id = features::read_id_regs();
    let (fam, model, step) = features::family_model_stepping(id.l1_eax);
    let census = alloc::format!("{}", Census(&id));
    let toks: alloc::vec::Vec<alloc::string::String> = census
        .split_whitespace()
        .filter(|t| !t.starts_with("xcr0="))
        .map(alloc::string::String::from)
        .collect();
    const CRYPTO: [&str; 8] = [
        "aes",
        "pclmulqdq",
        "sha",
        "vaes",
        "vpclmulqdq",
        "gfni",
        "rdrand",
        "rdseed",
    ];
    let crypto_units = toks
        .iter()
        .filter(|t| CRYPTO.contains(&t.as_str()))
        .cloned()
        .collect();
    let ascii = |b: &[u8]| {
        alloc::string::String::from(
            core::str::from_utf8(b)
                .unwrap_or("?")
                .trim_matches(|c: char| c == '\0' || c == ' '),
        )
    };
    let brand = id.brand.as_flattened();
    let hv = if id.l1_ecx & (1 << 31) != 0 {
        let sig = ascii(&id.hypervisor);
        alloc::format!("{} ({sig})", urmqtt_diag::names::hypervisor(&sig))
    } else {
        alloc::string::String::new()
    };
    crate::diag::CpuFacts {
        vendor: ascii(&id.vendor),
        model: ascii(brand),
        identity: alloc::format!("family {fam} model {model:#x} stepping {step}"),
        features: toks,
        crypto_units,
        hypervisor: hv,
    }
}

/// The time base for the diagnostic (O4).
pub(crate) fn diag_time() -> urmqtt_diag::report::TimeInfo {
    let info = *TIME_INFO.lock();
    match info {
        Some(i) => {
            let source = alloc::format!("{:?}", i.source);
            urmqtt_diag::report::TimeInfo {
                kvmclock: Some(source == "Kvmclock"),
                source,
                invariant_tsc: Some(i.invariant_tsc),
                counter_hz: i.tsc_hz,
                deadline_timer: Some(i.tsc_deadline),
                ..Default::default()
            }
        }
        None => urmqtt_diag::report::TimeInfo::default(),
    }
}

/// A scancode from the PS/2 keyboard, if one is waiting.
pub(crate) fn poll_scancode() -> Option<u8> {
    urmqtt_arch::ps2::poll()
}

/// The firmware type Limine reports.
pub(crate) fn firmware_kind(t: u64) -> &'static str {
    match t {
        0 => "BIOS",
        1 => "UEFI (32-bit)",
        2 => "UEFI (x86-64)",
        _ => "unknown",
    }
}

/// No branch-target identification here (CET is a later step).
pub(crate) fn bti(_f: &Features) -> bool {
    false
}

/// No pointer authentication on x86.
pub(crate) fn pac_key(_f: &Features) -> Option<(u64, u64)> {
    None
}

pub(crate) fn protection_summary(_f: &Features) -> &'static str {
    "nx+wp"
}

/// Brings up the APICs. Returns the timer's interrupt number (its vector)
/// and a description for the boot log.
pub(crate) fn init_interrupts(
    platform: Option<&PlatformInfo>,
    cpus: u64,
) -> (u32, alloc::string::String) {
    let Some(x86) = platform.and_then(|p| p.x86) else {
        fatal_fmt(format_args!("no MADT: the APICs are not described"))
    };
    match irq::init_apic(&x86, cpus) {
        Ok(d) => (urmqtt_arch::vectors::TIMER, d),
        Err(e) => fatal_fmt(format_args!("apic init failed: {e:?}")),
    }
}

/// The tick's log description.
pub(crate) fn timer_log(vector: u32) -> alloc::string::String {
    alloc::format!(
        "timer: tsc {} Hz, local APIC timer vector {vector:#x} ({}), tick",
        time::frequency(),
        if time::timer_is_fallback() {
            "one-shot, calibrated"
        } else {
            "TSC-deadline"
        }
    )
}

/// Faults that only exist on x86.
pub(crate) fn run_fault(fault: TestFault, _f: &Features) -> bool {
    match fault {
        TestFault::GeneralProtection => urmqtt_arch::trap::general_protection(),
        TestFault::DoubleFault => urmqtt_arch::trap::double_fault(),
        TestFault::DataAbort => trap::probe_read(memory::unmapped_mmio_probe()),
        TestFault::Pac | TestFault::Bti => {
            info!("test: {fault:?} skipped, aarch64 only")
        }
        _ => return false,
    }
    true
}
