//! Limine entry point and the boot sequence of the bootstrap CPU.

#![allow(unsafe_code)]

use limine::BaseRevision;
use limine::request::{
    BootloaderInfoRequest, DateAtBootRequest, DtbRequest, ExecutableAddressRequest,
    ExecutableCmdlineRequest, FramebufferRequest, HhdmRequest, MemmapRequest, MpRequest, Request,
    RsdpRequest,
};
use limine::{RequestsEndMarker, RequestsStartMarker};

use urmqtt_arch_aarch64::features::Features;
use urmqtt_arch_aarch64::sync::SpinLock;
use urmqtt_arch_aarch64::{cpu, exception, pac, regs};
use urmqtt_log::{error, info, warn};
use urmqtt_platform::{EarlyPlatform, PsciMethod, Uart};

use crate::cmdline::{BootOptions, TestFault};
use crate::{VERSION, console, irq, layout, memory, power, selftest, tick, trap, vm};

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
#[unsafe(link_section = ".requests")]
static EXECUTABLE_ADDRESS: ExecutableAddressRequest = ExecutableAddressRequest::new();

/// Limine "Entropy" response (not yet wrapped by the `limine` crate).
#[repr(C)]
pub struct EntropyRespData {
    value_count: u64,
    values: *const u64,
}
/// Random 64-bit values from the bootloader's best source (EFI RNG, RNDR).
const ENTROPY_VALUES: u64 = 8;
#[used]
#[unsafe(link_section = ".requests")]
// SAFETY: id and response layout follow the Limine protocol's Entropy feature.
static ENTROPY: Request<EntropyRespData, u64> = unsafe {
    Request::new_raw(
        [0x65ea_8025_5d56_82c5, 0x9117_2407_23f4_93eb],
        0,
        ENTROPY_VALUES,
    )
};

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
    "hint #34", // bti c
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

/// State carried across the stack switch into [`kmain_stage2`].
struct Stage2 {
    options: BootOptions,
    interrupts: Option<urmqtt_platform::Interrupts>,
    cpus: u64,
    built: vm::Built,
    early_frames: (u64, u64),
    features: Features,
}

static STAGE2: SpinLock<Option<Stage2>> = SpinLock::new(None);

#[unsafe(no_mangle)]
extern "C" fn urmqtt_kmain() -> ! {
    exception::set_handler(trap::handle);
    exception::install();

    if !BASE_REVISION.is_supported() {
        // No console yet; nothing better to do than stop.
        cpu::halt();
    }
    let Some(hhdm) = HHDM.response().map(|r| r.offset) else {
        cpu::halt();
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

    let mmio_ok = memory::init_early_mmio(&mem);
    let uart_va = uart
        .filter(|_| mmio_ok)
        .and_then(|u| memory::map_mmio(u.base, 0x1000).ok());
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

    // Memory management (M2): kernel page tables, frames, stacks, heap.
    let features = Features::decode(pac::id_regs());
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
    let Some(exe) = EXECUTABLE_ADDRESS.response() else {
        fatal("no executable address response from the bootloader");
    };
    let heap_mb = urmqtt_config::CONFIG.memory.kernel_heap_mb;
    let built = match vm::build(
        &mem,
        exe.physical_base,
        exe.virtual_base,
        features.bti,
        heap_mb,
    ) {
        Ok(b) => b,
        Err(e) => fatal_fmt(format_args!(
            "building the kernel address space failed: {e:?}"
        )),
    };
    info!(
        "vm: kernel tables built ({} table pages), {} MiB free, heap {heap_mb} MiB",
        built.pt_frames,
        (built.free_frames as u64 * 4096) >> 20
    );

    let pac_on = features.pauth && set_pac_key();
    vm::activate();
    info!("vm: switched to kernel tables (TTBR1), lower half disabled, WXN on");
    let (main_top, exc_top) = (built.main_top, built.exc_top);
    *STAGE2.lock() = Some(Stage2 {
        options,
        interrupts: early.and_then(|e| e.interrupts),
        cpus: cpus as u64,
        built,
        early_frames: mem.early_frames_range().unwrap_or((0, 0)),
        features,
    });
    // SAFETY: both stacks were mapped by `vm::build` and are 16-byte aligned
    // at the top; this frame (on the bootloader's stack) is abandoned.
    unsafe { pac::switch_to(main_top, exc_top, 0, kmain_stage2, pac_on) }
}

/// Seeds the IA key from bootloader entropy (and RNDR if present).
fn set_pac_key() -> bool {
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
        return false;
    };
    for (i, v) in values.iter().enumerate() {
        if let Some(k) = key.get_mut(i % 2) {
            *k ^= v.rotate_left((i as u32) * 17);
        }
    }
    // SAFETY: PAC is not enabled yet, no signed pointers exist.
    unsafe { pac::set_ia_key(key[0], key[1]) };
    true
}

/// Runs on the kernel's main stack (SP_EL0) with exceptions on SP_EL1.
extern "C" fn kmain_stage2(_arg: u64) -> ! {
    let Some(s) = STAGE2.lock().take() else {
        fatal("stage 2 entered without state");
    };
    vm::retire_early_frames(s.early_frames);
    if let Err(e) = vm::init_heap(s.built.heap_order, s.built.heap_meta_words) {
        fatal_fmt(format_args!("heap init failed: {e:?}"));
    }
    info!(
        "vm: running on kernel stacks (main {} KiB at {:#x}, exception {} KiB), pac={} bti={}",
        layout::MAIN_STACK_SIZE >> 10,
        s.built.main_top,
        layout::EXC_STACK_SIZE >> 10,
        if s.features.pauth {
            "on"
        } else {
            "unsupported"
        },
        if s.features.bti { "on" } else { "unsupported" },
    );

    let (mmio_maps, mmio_bytes) = memory::mmio_stats();
    info!("vm: {mmio_maps} MMIO mapping(s), {} KiB", mmio_bytes >> 10);
    if let Err(msg) = selftest::memory() {
        fatal(msg);
    }
    // Interrupts and time (M3). Device mappings must precede the lock.
    let Some(intr) = s.interrupts else {
        fatal("no GICv3/timer description in DTB or ACPI");
    };
    match irq::init(&intr.gic, s.cpus) {
        Ok(lines) => info!(
            "gic: v3 at gicd={:#x} gicr={:#x}, {lines} lines, msi via {}",
            intr.gic.gicd,
            intr.gic.gicr.0,
            match (intr.gic.its, intr.gic.v2m) {
                (Some(_), _) => "ITS",
                (None, Some(_)) => "GICv2m frame",
                (None, None) => "none",
            }
        ),
        Err(e) => fatal_fmt(format_args!("gic init failed: {e:?}")),
    }
    match vm::lock() {
        Ok(bytes) => info!(
            "vm: page tables locked ({} KiB read-only, no writable alias)",
            bytes >> 10
        ),
        Err(e) => fatal_fmt(format_args!("locking page tables failed: {e:?}")),
    }
    if let Err(msg) = selftest::wx_audit() {
        fatal(msg);
    }

    if let Some(fault) = s.options.test_fault {
        run_test_fault(fault, s.features);
    }

    tick_selftest(intr.timer.virt);

    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if s.options.smoke {
        power::off();
    }
    // SAFETY: vectors and the GIC are initialised; the tick keeps running.
    unsafe { cpu::idle() }
}

/// Tick period (also the watchdog granularity, PROMPT §4.1).
const TICK_NS: u64 = 10_000_000;
const TICK_SELFTEST: u64 = 50;

/// Runs the periodic tick and reports interrupt latency twice: while the
/// core busy-polls and while it sleeps in `wfi` (ADR-022).
fn tick_selftest(timer_intid: u32) {
    let freq = urmqtt_arch_aarch64::timer::frequency();
    info!(
        "timer: counter {freq} Hz, virtual timer PPI {timer_intid}, tick {} ms",
        TICK_NS / 1_000_000
    );
    tick::start(timer_intid, TICK_NS);
    let t0 = urmqtt_arch_aarch64::timer::uptime_ns();
    // SAFETY: vectors, GIC and the tick handler are ready.
    unsafe { cpu::unmask_irq() };
    for (mode, sleep) in [("busy-poll", false), ("wfi", true)] {
        tick::reset_stats();
        let start = tick::ticks();
        let mut reported = start;
        while tick::ticks() < start + TICK_SELFTEST / 2 {
            if sleep {
                cpu::wfi();
            } else {
                core::hint::spin_loop();
            }
            let t = tick::ticks();
            if t >= reported + 10 {
                reported = t - t % 10;
                info!("tick {reported}");
            }
        }
        let l = tick::latency();
        info!(
            "timer: irq latency ({mode}, {} samples) min={} avg={} p99<={} max={} ns",
            l.samples, l.min_ns, l.avg_ns, l.p99_ns, l.max_ns
        );
    }
    let elapsed = urmqtt_arch_aarch64::timer::uptime_ns() - t0;
    info!(
        "timer: {} ticks in {} ms",
        tick::ticks(),
        elapsed / 1_000_000
    );
    let (spurious, unhandled) = irq::stats();
    if unhandled > 0 {
        warn!("irq: {unhandled} interrupt(s) without handler, {spurious} spurious");
    }
}

fn fatal(msg: &str) -> ! {
    error!("fatal: {msg}");
    power::fatal()
}

fn fatal_fmt(args: core::fmt::Arguments<'_>) -> ! {
    error!("fatal: {args}");
    power::fatal()
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

fn run_test_fault(fault: TestFault, features: Features) {
    warn!("test mode: triggering {fault:?}");
    match fault {
        TestFault::DataAbort => trap::probe_read(memory::unmapped_mmio_probe()),
        TestFault::BrkResume => {
            trap::brk_resume();
            info!("test: resumed after brk");
        }
        TestFault::Undefined => trap::undefined_instruction(),
        TestFault::Panic => panic!("test panic requested on the command line"),
        TestFault::WriteText => selftest::write_text(),
        TestFault::ExecHeap => selftest::exec_heap(),
        TestFault::StackOverflow => selftest::stack_overflow(),
        TestFault::NullDeref => trap::probe_read(0x8),
        TestFault::Pac if features.pauth => selftest::pac_violation(),
        TestFault::Bti if features.bti => selftest::bti_violation(),
        TestFault::Pac | TestFault::Bti => info!("test: {fault:?} skipped, CPU lacks the feature"),
    }
}
