//! Limine entry point and the boot sequence of the bootstrap CPU.

#![allow(unsafe_code)]

use limine::BaseRevision;
use limine::request::{
    BootloaderInfoRequest, DateAtBootRequest, DtbRequest, ExecutableCmdlineRequest,
    FramebufferRequest, HhdmRequest, MemmapRequest, MpRequest, RsdpRequest,
};
use limine::{RequestsEndMarker, RequestsStartMarker};

use urmqtt_arch_aarch64::{exception, regs};
use urmqtt_log::{info, warn};
use urmqtt_platform::{EarlyPlatform, PsciMethod, Uart};

use crate::cmdline::{BootOptions, TestFault};
use crate::{VERSION, console, memory, power, trap};

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();
#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(6);
#[used]
#[unsafe(link_section = ".requests")]
static BOOTLOADER: BootloaderInfoRequest = BootloaderInfoRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static HHDM: HhdmRequest = HhdmRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static MEMMAP: MemmapRequest = MemmapRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static MP: MpRequest = MpRequest::new(0);
#[used]
#[unsafe(link_section = ".requests")]
static DTB: DtbRequest = DtbRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static RSDP: RsdpRequest = RsdpRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static CMDLINE: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static DATE_AT_BOOT: DateAtBootRequest = DateAtBootRequest::new();
#[used]
#[unsafe(link_section = ".requests_end_marker")]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

// Entry from Limine: MMU on, interrupts masked, FP/SIMD disabled (base
// revision 6), SPSel = 0. Enable FP before any compiled code can use SIMD
// registers (ADR-003) and switch to SP_ELx so exceptions to this EL share the
// boot stack.
core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    "_start:",
    "mrs x9, cpacr_el1",
    "orr x9, x9, #(3 << 20)",
    "msr cpacr_el1, x9",
    "isb",
    "mov x9, sp",
    "msr spsel, #1",
    "mov sp, x9",
    "mov x29, xzr",
    "mov x30, xzr",
    "bl urmqtt_kmain",
    "1: wfi",
    "b 1b",
    ".text",
);

/// Physical address of the default QEMU `virt` PL011, used only in dev
/// builds when neither the DTB nor SPCR describe a UART.
const DEV_FALLBACK_UART: u64 = 0x0900_0000;

#[unsafe(no_mangle)]
extern "C" fn urmqtt_kmain() -> ! {
    exception::set_handler(trap::handle);
    exception::install();

    if !BASE_REVISION.is_supported() {
        // No console yet; nothing better to do than stop.
        urmqtt_arch_aarch64::cpu::halt();
    }
    let Some(hhdm) = HHDM.response().map(|r| r.offset) else {
        urmqtt_arch_aarch64::cpu::halt();
    };
    let memmap = MEMMAP.response().map_or(&[][..], |r| r.entries());
    let mem = memory::BootMemory::new(hhdm, memmap);

    let dev = urmqtt_config::CONFIG.env == "dev";
    let early = discover(&mem);
    let uart = match early.and_then(|e| e.uart) {
        Some(u) => Some(u),
        None if dev => Some(Uart {
            base: DEV_FALLBACK_UART,
        }),
        None => None,
    };
    // At EL2 (VHE entry, base revision 6) an HVC would trap to ourselves:
    // only an SMC conduit can reach firmware from there.
    let el2 = regs::current_el() == 2;
    match early.and_then(|e| e.psci) {
        Some(PsciMethod::Hvc) if el2 => {}
        Some(psci) => power::set_conduit(psci),
        None => {}
    }

    let mut mmio = memory::MmioWindow::new(&mem);
    let uart_va = uart.and_then(|u| mmio.as_mut().and_then(|w| w.map(&mem, u.base, 0x1000).ok()));
    if let Some(va) = uart_va {
        console::init_uart(va);
    }
    urmqtt_log::set_clock(uptime_ns);
    if let Some(fb) = FRAMEBUFFER
        .response()
        .and_then(|r| r.framebuffers().first().copied())
    {
        console::init_framebuffer(fb);
    }

    let options = BootOptions::parse(CMDLINE.response().map_or("", |r| r.cmdline()), dev);
    power::set_smoke(options.smoke);

    let cpus = MP.response().map_or(1, |r| r.cpus().len());
    urmqtt_log::raw(format_args!(
        "URMQTT BOOT {VERSION} cpu={cpus} mem={}\n",
        mem.ram_bytes() >> 20
    ));
    info!(
        "env={} el={} bootloader={} {}",
        urmqtt_config::CONFIG.env,
        regs::current_el(),
        BOOTLOADER.response().map_or("?", |r| r.name()),
        BOOTLOADER.response().map_or("?", |r| r.version()),
    );
    match early {
        Some(e) => info!(
            "platform: {:?}, uart={:#x}, psci={:?}",
            e.source,
            e.uart.map_or(0, |u| u.base),
            e.psci
        ),
        None => warn!("platform: neither DTB nor ACPI usable"),
    }
    if let Some(va) = uart_va {
        info!(
            "console: pl011 at {:#x} mapped at {va:#x}",
            uart.map_or(0, |u| u.base)
        );
    }
    if let Some(w) = &mmio {
        info!("mmio window at {:#x}", w.base());
    }
    if el2 {
        warn!("entered at EL2 (VHE): untested configuration, PSCI only via SMC");
    }
    match power::psci_version() {
        Some((maj, min)) => info!(
            "psci {maj}.{min} via {}",
            power::conduit().map_or("?", |c| match c {
                urmqtt_arch_aarch64::psci::Conduit::Hvc => "hvc",
                urmqtt_arch_aarch64::psci::Conduit::Smc => "smc",
            })
        ),
        None => warn!("psci unavailable: power-off and reset will halt instead"),
    }
    if let Some(d) = DATE_AT_BOOT.response() {
        info!("date at boot: unix {}", d.timestamp);
    } else {
        warn!("no date at boot: certificate validity checks will be refused (ADR-009)");
    }
    console::log_framebuffer();
    mem.log_summary();
    if options.ignored > 0 {
        warn!("ignored {} kernel command line option(s)", options.ignored);
    }

    if let Some(fault) = options.test_fault {
        run_test_fault(fault, mmio.as_ref().map(|w| w.unmapped_probe()));
    }

    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if options.smoke {
        power::off();
    }
    urmqtt_arch_aarch64::cpu::halt();
}

/// Nanoseconds since the counter started (boot), from the generic timer.
fn uptime_ns() -> u64 {
    let freq = regs::cntfrq_el0().max(1);
    let ticks = regs::cntvct_el0();
    ((u128::from(ticks) * 1_000_000_000) / u128::from(freq)) as u64
}

fn discover(mem: &memory::BootMemory) -> Option<EarlyPlatform> {
    if let Some(fdt) = DTB.response().and_then(|r| mem.fdt(r.dtb_ptr as u64))
        && let Ok(p) = urmqtt_platform::early_from_fdt(&fdt)
    {
        return Some(p);
    }
    let rsdp_va = RSDP.response().map(|r| r.address as u64)?;
    let acpi = urmqtt_platform::acpi::Acpi::new(mem, mem.virt_to_phys(rsdp_va)?).ok()?;
    urmqtt_platform::early_from_acpi(&acpi).ok()
}

fn run_test_fault(fault: TestFault, probe: Option<u64>) {
    warn!("test mode: triggering {fault:?}");
    match fault {
        TestFault::DataAbort => {
            if let Some(va) = probe {
                trap::probe_read(va);
            }
        }
        TestFault::BrkResume => {
            trap::brk_resume();
            info!("test: resumed after brk");
        }
        TestFault::Undefined => trap::undefined_instruction(),
        TestFault::Panic => panic!("test panic requested on the command line"),
    }
}
