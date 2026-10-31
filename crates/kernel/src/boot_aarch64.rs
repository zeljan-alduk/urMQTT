//! The AArch64 side of the boot sequence (`boot.rs` calls these seams).
//!
//! The UART comes from the device tree or SPCR and is mapped before the
//! first log line; the generic timer needs no setup; interrupts go through
//! a GICv3 or GICv2 described by the DTB or the MADT.

#![allow(unsafe_code)]

use urmqtt_arch::features::{self, Features};
use urmqtt_arch::{cpu, time};
use urmqtt_log::{info, warn};
use urmqtt_platform::{PlatformInfo, PsciMethod, Uart};

use crate::boot::{ENTROPY, ENTROPY_VALUES, fatal, fatal_fmt};
use crate::cmdline::TestFault;
use crate::{console, irq, memory, power, selftest, trap};

/// The architecture's name, for `$SYS/broker/arch` (O1).
pub(crate) const ARCH: &str = "aarch64";

/// Appended to the `URMQTT BOOT` line.
pub(crate) const BOOT_TAG: &str = "";

/// The boot log's name for the privilege level.
pub(crate) const PRIVILEGE_LABEL: &str = "el";

/// The text after `vm: switched to kernel tables`.
pub(crate) const ACTIVATED: &str = "(TTBR1), lower half disabled, WXN on";

/// Physical address of the default QEMU `virt` PL011, used only in dev
/// builds when neither the DTB nor SPCR describe a UART.
const DEV_FALLBACK_UART: u64 = 0x0900_0000;

/// No console until the UART is mapped.
pub(crate) fn early_console() {}

/// What the early hardware setup found, for the boot log.
pub(crate) struct EarlyHw {
    uart: Option<Uart>,
    uart_va: Option<u64>,
    el2: bool,
}

/// Maps the UART and selects the PSCI conduit.
pub(crate) fn early_hw(platform: Option<&PlatformInfo>, mmio_ok: bool, dev: bool) -> EarlyHw {
    let uart = match platform.and_then(|e| e.uart) {
        Some(u) => Some(u),
        None if dev => Some(Uart {
            base: DEV_FALLBACK_UART,
        }),
        None => None,
    };
    // At EL2 (VHE entry, base revision 6) an HVC would trap to ourselves:
    // only an SMC conduit can reach firmware from there.
    let el2 = cpu::privilege_level() == 2;
    match platform.and_then(|e| e.psci) {
        Some(PsciMethod::Hvc) if el2 => {}
        Some(psci) => power::set_conduit(psci),
        None => {}
    }
    let uart_va = uart
        .filter(|_| mmio_ok)
        .and_then(|u| memory::map_mmio(u.base, 0x1000).ok());
    if let Some(va) = uart_va {
        console::init_uart(va);
    }
    EarlyHw { uart, uart_va, el2 }
}

impl EarlyHw {
    pub(crate) fn log(&self, _platform: Option<&PlatformInfo>) {
        if let Some(va) = self.uart_va {
            info!(
                "console: pl011 at {:#x} mapped at {va:#x}",
                self.uart.map_or(0, |u| u.base)
            );
        }
        if self.el2 {
            warn!("entered at EL2 (VHE): untested configuration, PSCI only via SMC");
        }
        match urmqtt_arch::power::firmware_version() {
            Some((maj, min)) => info!(
                "psci {maj}.{min} via {}",
                urmqtt_arch::power::conduit_name()
            ),
            None => warn!("psci unavailable: power-off and reset will halt instead"),
        }
    }
}

/// Feature detection and its boot log line.
pub(crate) fn cpu_summary() -> Features {
    let features = features::detect();
    info!(
        "cpu features: pauth={} fpac={} bti={} rndr={} aes={} pmull={} sha2={} lse={} mte={} sve={}",
        features.pauth,
        features.fpac,
        features.bti,
        features.rndr,
        features.aes,
        features.pmull,
        features.sha2,
        features.lse,
        features.mte,
        features.sve
    );
    features
}

/// CPU identity for the diagnostic (O4): MIDR_EL1 and the feature bits.
pub(crate) fn diag_cpu() -> crate::diag::CpuFacts {
    use alloc::string::String;
    let midr = features::midr();
    let implementer = (midr >> 24) as u8;
    let part = ((midr >> 4) & 0xfff) as u16;
    let (variant, rev) = ((midr >> 20) & 0xf, midr & 0xf);
    let f = features::detect();
    let mut toks: alloc::vec::Vec<String> = alloc::vec::Vec::new();
    let mut crypto: alloc::vec::Vec<String> = alloc::vec::Vec::new();
    for (name, on, is_crypto) in [
        ("aes", f.aes, true),
        ("pmull", f.pmull, true),
        ("sha2", f.sha2, true),
        ("crc32", f.crc32, true),
        ("rndr", f.rndr, true),
        ("lse", f.lse, false),
        ("pauth", f.pauth, false),
        ("fpac", f.fpac, false),
        ("bti", f.bti, false),
        ("mte", f.mte, false),
        ("sve", f.sve, false),
    ] {
        if on {
            toks.push(name.into());
            if is_crypto {
                crypto.push(name.into());
            }
        }
    }
    crate::diag::CpuFacts {
        vendor: String::from(urmqtt_diag::names::arm_implementer(implementer)),
        model: String::from(urmqtt_diag::names::arm_part(implementer, part)),
        identity: alloc::format!(
            "MIDR {midr:#x} implementer {implementer:#x} part {part:#x} r{variant}p{rev}"
        ),
        features: toks,
        crypto_units: crypto,
        hypervisor: alloc::format!(
            "not detectable from the CPU on Arm; PSCI conduit {}",
            urmqtt_arch::power::conduit_name()
        ),
    }
}

/// The time base for the diagnostic (O4): the generic counter.
pub(crate) fn diag_time() -> urmqtt_diag::report::TimeInfo {
    urmqtt_diag::report::TimeInfo {
        source: "generic counter (CNTFRQ)".into(),
        counter_hz: time::frequency(),
        ..Default::default()
    }
}

/// No keyboard on this platform: confirmation comes from the serial port.
pub(crate) fn poll_scancode() -> Option<u8> {
    None
}

/// The firmware type Limine reports (UEFI on Arm).
pub(crate) fn firmware_kind(_t: u64) -> &'static str {
    "UEFI (aarch64)"
}

pub(crate) fn bti(f: &Features) -> bool {
    f.bti
}

/// Seeds the IA key from bootloader entropy. Returns the key so the
/// application processors can be given the same one.
pub(crate) fn pac_key(f: &Features) -> Option<(u64, u64)> {
    if !f.pauth {
        return None;
    }
    let mut key = [0u64; 2];
    let from_limine = ENTROPY.response().and_then(|r| {
        let n = usize::try_from(r.value_count)
            .ok()?
            .min(ENTROPY_VALUES as usize);
        if n < 2 || r.values.is_null() {
            return None;
        }
        // SAFETY: Limine provides `value_count` u64s at `values` (HHDM).
        Some(unsafe { core::slice::from_raw_parts(r.values, n) })
    });
    let Some(values) = from_limine else {
        warn!("pac: no bootloader entropy, leaving pointer authentication off");
        return None;
    };
    for (i, v) in values.iter().enumerate() {
        if let Some(k) = key.get_mut(i % 2) {
            *k ^= v.rotate_left((i as u32) * 17);
        }
    }
    // SAFETY: PAC is not enabled yet, no signed pointers exist.
    unsafe { cpu::set_return_address_key(key[0], key[1]) };
    Some((key[0], key[1]))
}

pub(crate) fn protection_summary(f: &Features) -> &'static str {
    match (f.pauth, f.bti) {
        (true, true) => "pac=on bti=on",
        (true, false) => "pac=on bti=unsupported",
        (false, true) => "pac=unsupported bti=on",
        (false, false) => "pac=unsupported bti=unsupported",
    }
}

/// Brings up the GIC. Returns the timer's interrupt number (the EL1
/// virtual timer's PPI) and a description for the boot log.
pub(crate) fn init_interrupts(
    platform: Option<&PlatformInfo>,
    cpus: u64,
) -> (u32, alloc::string::String) {
    let Some(intr) = platform.and_then(|p| p.interrupts) else {
        fatal("no GIC/timer description in DTB or ACPI");
    };
    match irq::init(&intr.gic, cpus) {
        Ok(lines) => (
            intr.timer.virt,
            alloc::format!(
                "gic: {} at gicd={:#x} {}={:#x}, {lines} lines, msi via {}",
                if irq::is_v2() { "v2" } else { "v3" },
                intr.gic.gicd,
                if irq::is_v2() { "gicc" } else { "gicr" },
                match intr.gic.cpu {
                    urmqtt_platform::GicCpu::V3 { gicr } => gicr.0,
                    urmqtt_platform::GicCpu::V2 { gicc } => gicc,
                },
                match (intr.gic.its, intr.gic.v2m) {
                    (Some(_), _) => "ITS",
                    (None, Some(_)) => "GICv2m frame",
                    (None, None) => "none",
                }
            ),
        ),
        Err(e) => fatal_fmt(format_args!("gic init failed: {e:?}")),
    }
}

/// The tick's log description.
pub(crate) fn timer_log(intid: u32) -> alloc::string::String {
    alloc::format!(
        "timer: counter {} Hz, virtual timer PPI {intid}, tick",
        time::frequency()
    )
}

/// Faults that only exist on AArch64.
pub(crate) fn run_fault(fault: TestFault, f: &Features) -> bool {
    match fault {
        TestFault::DataAbort => trap::probe_read(memory::unmapped_mmio_probe()),
        TestFault::Pac if f.pauth => selftest::pac_violation(),
        TestFault::Bti if f.bti => selftest::bti_violation(),
        TestFault::Pac | TestFault::Bti => info!("test: {fault:?} skipped, CPU lacks the feature"),
        TestFault::GeneralProtection | TestFault::DoubleFault => {
            info!("test: {fault:?} skipped, x86_64 only")
        }
        _ => return false,
    }
    true
}
