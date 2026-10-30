//! Limine entry point and the boot sequence of the bootstrap CPU.

#![allow(unsafe_code)]

use limine::BaseRevision;
use limine::request::{
    BootloaderInfoRequest, DateAtBootRequest, DtbRequest, ExecutableAddressRequest,
    ExecutableCmdlineRequest, ExecutableFileRequest, FramebufferRequest, HhdmRequest,
    MemmapRequest, ModulesRequest, MpRequest, Request, RsdpRequest,
};
use limine::{RequestsEndMarker, RequestsStartMarker};

use urmqtt_arch::features::{self, Features};
use urmqtt_arch::{cpu, time, trap as arch_trap};
use urmqtt_log::{error, info, warn};
use urmqtt_platform::{EarlyPlatform, PsciMethod, Uart};
use urmqtt_sync::sync::SpinLock;

use crate::cmdline::{BootOptions, TestFault};
use crate::{VERSION, console, devices, irq, layout, memory, power, selftest, smp, tick, trap, vm};

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
/// The installation image (the ESP), loaded by the ISO's install entry (S1b).
#[used]
#[unsafe(link_section = ".requests")]
static MODULES: ModulesRequest = ModulesRequest::new();
/// Where the kernel was loaded from: identifies the boot disk (S1).
#[used]
#[unsafe(link_section = ".requests")]
static EXECUTABLE_FILE: ExecutableFileRequest = ExecutableFileRequest::new();

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

// Limine enters at the architecture's `_start` (`arch-aarch64::boot`),
// which enables FP/SIMD, sets up the stack and calls `urmqtt_kmain`.

/// Physical address of the default QEMU `virt` PL011, used only in dev
/// builds when neither the DTB nor SPCR describe a UART.
const DEV_FALLBACK_UART: u64 = 0x0900_0000;

/// State carried across the stack switch into [`kmain_stage2`].
struct Stage2 {
    options: BootOptions,
    platform: Option<urmqtt_platform::PlatformInfo>,
    boot_entropy: [u64; ENTROPY_VALUES as usize],
    pac_key: Option<(u64, u64)>,
    interrupts: Option<urmqtt_platform::Interrupts>,
    cpus: u64,
    built: vm::Built,
    early_frames: (u64, u64),
    features: Features,
    /// Read before the bootloader's memory is reclaimed.
    medium: devices::BootMedium,
    /// The installation image, if the bootloader loaded one.
    install_image: Option<&'static [u8]>,
}

static STAGE2: SpinLock<Option<Stage2>> = SpinLock::new(None);

#[unsafe(no_mangle)]
extern "C" fn urmqtt_kmain() -> ! {
    arch_trap::set_handler(trap::handle);
    arch_trap::install();

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
    let el2 = cpu::privilege_level() == 2;
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
    urmqtt_log::set_cpu(crate::smp::current);
    if urmqtt_config::CONFIG.observability.syslog_udp.is_some() {
        // Kept from the start; sent once the network is up (M16).
        urmqtt_log::enable_records();
    }
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
        cpu::privilege_level(),
        BOOTLOADER.response().map_or("?", |r| r.name()),
        BOOTLOADER.response().map_or("?", |r| r.version()),
    );
    match early {
        Some(e) => {
            info!("platform: discovered via {:?}", e.source);
            info!("platform summary: {e}");
            if e.cpus.len() != cpus {
                warn!(
                    "platform: firmware lists {} CPUs, bootloader started {cpus}",
                    e.cpus.len()
                );
            }
        }
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
    match urmqtt_arch::power::firmware_version() {
        Some((maj, min)) => info!(
            "psci {maj}.{min} via {}",
            urmqtt_arch::power::conduit_name()
        ),
        None => warn!("psci unavailable: power-off and reset will halt instead"),
    }
    // H7 lower bound: the image cannot run before it was built, so an
    // earlier clock (an empty CMOS battery, a broken RTC) is unknown time,
    // and everything that needs the time fails closed.
    match DATE_AT_BOOT.response().map(|d| d.timestamp.max(0) as u64) {
        // `black_box`: a build without SOURCE_DATE_EPOCH has a bound of 0.
        Some(t) if t >= core::hint::black_box(BUILD_UNIX) => {
            info!("date at boot: unix {t} (image built at unix {BUILD_UNIX})");
            BOOT_UNIX.store(t, core::sync::atomic::Ordering::Relaxed);
        }
        Some(t) => warn!(
            "date at boot: unix {t} is before this image was built (unix {BUILD_UNIX}): \
             wall clock unknown, certificate checks and control messages refused \
             (check the RTC battery or the hypervisor clock)"
        ),
        None => warn!("no date at boot: certificate validity checks will be refused (ADR-009)"),
    }
    if BUILD_UNIX == 0 {
        warn!("no build time in this image (SOURCE_DATE_EPOCH unset): no lower bound on the clock");
    }
    // Installed in every case: without a date it answers "unknown".
    urmqtt_tls::set_clock(now_unix);
    console::log_framebuffer();
    mem.log_summary();
    if options.ignored > 0 {
        warn!("ignored {} kernel command line option(s)", options.ignored);
    }

    // Memory management (M2): kernel page tables, frames, stacks, heap.
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
    // Crypto and checksum backends (ADR-041): detection minus the
    // configured opt-out, sealed before any of them runs.
    // The configuration was validated at build time; a dev command line
    // may take more features out (to compare backends).
    let disabled = urmqtt_dispatch::parse_disable(urmqtt_config::CONFIG.cpu.disable)
        .unwrap_or_default()
        .union(options.cpu_disable);
    match crate::cpu_dispatch::seal(features.dispatch(), disabled) {
        Ok(d) => {
            info!(
                "cpu dispatch: detected {}, disabled {}",
                d.detected, d.disabled
            );
            info!("crypto: {}", d.selection);
        }
        Err(e) => fatal_fmt(format_args!("cpu dispatch: {e:?}")),
    }
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

    let pac_key = if features.pauth { set_pac_key() } else { None };
    let pac_on = pac_key.is_some();
    vm::activate();
    info!("vm: switched to kernel tables (TTBR1), lower half disabled, WXN on");
    let (main_top, exc_top) = (built.main_top, built.exc_top);
    *STAGE2.lock() = Some(Stage2 {
        options,
        platform: early,
        boot_entropy: bootloader_entropy(),
        pac_key,
        interrupts: early.and_then(|e| e.interrupts),
        cpus: cpus as u64,
        built,
        early_frames: mem.early_frames_range().unwrap_or((0, 0)),
        features,
        medium: boot_medium(),
        install_image: install_image(),
    });
    // SAFETY: both stacks were mapped by `vm::build` and are 16-byte aligned
    // at the top; this frame (on the bootloader's stack) is abandoned.
    unsafe { cpu::switch_to(main_top, exc_top, 0, kmain_stage2, pac_on) }
}

/// The bootloader's entropy values (zero if none), for the CSPRNG pool.
fn bootloader_entropy() -> [u64; ENTROPY_VALUES as usize] {
    let mut out = [0u64; ENTROPY_VALUES as usize];
    if let Some(r) = ENTROPY.response()
        && !r.values.is_null()
    {
        let n = usize::try_from(r.value_count).unwrap_or(0).min(out.len());
        // SAFETY: Limine provides `value_count` u64s at `values` (HHDM).
        let vals = unsafe { core::slice::from_raw_parts(r.values, n) };
        for (o, v) in out.iter_mut().zip(vals) {
            *o = *v;
        }
    }
    out
}

/// Seeds the IA key from bootloader entropy. Returns the key so the
/// application processors can be given the same one.
fn set_pac_key() -> Option<(u64, u64)> {
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

/// Runs on the kernel's main stack (SP_EL0) with exceptions on SP_EL1.
extern "C" fn kmain_stage2(_arg: u64) -> ! {
    let Some(mut s) = STAGE2.lock().take() else {
        fatal("stage 2 entered without state");
    };
    smp::init_boot_cpu();
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
    vm::enable_heap_caches();
    // Power-on self-test of the backends sealed in stage 1 (X0b), before
    // anything uses them: fail closed.
    match urmqtt_tls::kat::run() {
        Ok(()) if urmqtt_store::crc::crc32c(b"123456789") == 0xe306_9283 => info!(
            "crypto: known-answer tests passed (AES-128-GCM, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256, CRC-32C)"
        ),
        Ok(()) => fatal("crypto: CRC-32C known-answer test failed"),
        Err(name) => fatal_fmt(format_args!("crypto: {name} known-answer test failed")),
    }
    // Interrupts and time (M3). Device mappings must precede the lock.
    let Some(intr) = s.interrupts else {
        fatal("no GIC/timer description in DTB or ACPI");
    };
    match irq::init(&intr.gic, s.cpus) {
        Ok(lines) => info!(
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
        Err(e) => fatal_fmt(format_args!("gic init failed: {e:?}")),
    }
    // The boot volume, for the single-disk model (S1, STORAGE-PLAN §2a).
    let medium = s.medium;
    match (medium.optical, medium.disk_guid) {
        (true, _) => info!("boot: from optical media (CD/ISO)"),
        (false, Some(g)) => info!("boot: from a GPT disk, disk GUID {g}"),
        (false, None) => warn!("boot: the bootloader reported no GPT boot disk"),
    }
    devices::set_boot_medium(medium);
    devices::set_install_mode(s.options.install);
    // PCIe and virtio (M6): all device MMIO must be mapped before the lock.
    if let Some(p) = s.platform.as_ref() {
        match devices::probe(p, &s.boot_entropy) {
            Ok(()) => {}
            Err(devices::ProbeError::NoEntropy) => fatal(
                "no entropy source (virtio-rng, RNDR, or a jitter fallback that passes its health tests): refusing to run",
            ),
            Err(e) => fatal_fmt(format_args!("device probe failed: {e:?}")),
        }
    }
    s.boot_entropy = [0; ENTROPY_VALUES as usize];

    // Application processors need their stacks mapped before the lock.
    smp::register_ipis();
    let ap_count = (s.cpus as usize).clamp(1, smp::MAX_CPUS) - 1;
    for cpu in 1..=ap_count as u64 {
        if let Err(e) = vm::map_stacks(cpu) {
            fatal_fmt(format_args!("mapping stacks of cpu {cpu} failed: {e:?}"));
        }
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
    if s.options.crypto_bench {
        #[cfg(feature = "selftest")]
        crate::crypto_bench::run();
        #[cfg(not(feature = "selftest"))]
        warn!("crypto-bench: not in this image (built without the selftest feature)");
    }

    tick_selftest(intr.timer.virt);
    if s.options.install {
        crate::install::run(
            s.install_image,
            s.options
                .install_countdown_s
                .unwrap_or(crate::install::COUNTDOWN_S),
            s.options.disk_fault,
        );
    }
    if let Err(msg) = devices::prepare_boot_disk(s.options.disk_fault) {
        if urmqtt_config::CONFIG.storage.require_data_disk {
            fatal_fmt(format_args!("storage: {msg}; refusing to serve"));
        }
        error!("storage: {msg}; running WITHOUT persistence (dev configuration)");
    }
    if let Err(msg) = devices::blk_selftest() {
        fatal(msg);
    }
    if let Err(msg) = devices::net_selftest() {
        fatal(msg);
    }
    // Durable storage (M11) opens before the other cores start; the DB
    // core takes the store over afterwards.
    let restored = crate::db::init(s.options.db_test);
    // The identity lifecycle's sets (H1): from the store, or from the image
    // when there is no durable storage (then the control channel refuses).
    let image_revoked: alloc::vec::Vec<alloc::string::String> = urmqtt_config::CONFIG
        .tls
        .revoked_serials
        .iter()
        .map(|s| (*s).into())
        .collect();
    let allowlist_mode = urmqtt_config::CONFIG.registry.allowlist || s.options.allowlist;
    match restored.as_ref() {
        Some(r) => crate::control::init(&r.revoked, &r.allowlist, allowlist_mode),
        None => crate::control::init(&image_revoked, &[], allowlist_mode),
    }
    if allowlist_mode && restored.is_none() {
        warn!(
            "registry: allowlist mode without durable storage: the allowlist is empty and cannot change"
        );
    }
    smp_bringup(&mut s);
    if s.options.simd_irq {
        #[cfg(feature = "selftest")]
        if !crate::simd_irq::run() {
            fatal("simd-irq: FP/SIMD state corrupted by interrupts");
        }
        #[cfg(not(feature = "selftest"))]
        warn!("simd-irq: not in this image (built without the selftest feature)");
    }
    // With durable storage and two or more CPUs, the last CPU is the DB
    // core; every other CPU is a data core (M13, ADR-032).
    let cpus = smp::count().max(1);
    let data_cores = if crate::db::active() && cpus >= 2 {
        cpus - 1
    } else {
        cpus
    };
    crate::db::start(cpus, data_cores);
    if s.options.db_test == Some(crate::cmdline::DbTest::LogCrash) {
        crate::db::start_log_crash(cpus);
    }
    crate::mqtt_service::init_tickets(s.options.ticket_rotate_s);
    crate::dataplane::init(data_cores);
    crate::dataplane::set_heap_reserve(s.options.heap_limit_mb);
    if s.options.db_test == Some(crate::cmdline::DbTest::DpBench) {
        #[cfg(feature = "selftest")]
        {
            if data_cores < 2 {
                fatal(
                    "dp-bench needs at least one worker core besides core 0 (3+ CPUs with storage)",
                );
            }
            crate::dpbench::run(data_cores - 1, s.options.smoke);
        }
        #[cfg(not(feature = "selftest"))]
        warn!("dp-bench: not in this image (built without the selftest feature)");
    }
    crate::netproto::prepare(restored.map(alloc::sync::Arc::new));
    for cpu in 1..data_cores {
        smp::start_data_core(cpu);
    }
    info!(
        "dataplane: {data_cores} data core(s), each with its own network stack, TLS and broker shard"
    );

    if s.options.db_test == Some(crate::cmdline::DbTest::Watchdog) {
        crate::watchdog::self_test();
    }
    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if let Some(level) = s.options.log_level {
        info!("log: level {level:?} from the command line");
        urmqtt_log::set_level(level);
    }
    if s.options.smoke && !s.options.serve {
        power::off();
    }
    crate::netproto::run(
        0,
        urmqtt_config::CONFIG.env == "dev",
        crate::netproto::take_restored(),
    )
}

const AP_TIMEOUT_NS: u64 = 2_000_000_000;

/// Starts every application processor, checks IPIs between all pairs and
/// that every core runs its own tick.
fn smp_bringup(s: &mut Stage2) {
    let Some(mp) = MP.response() else {
        info!("smp: no MP response, running on one CPU");
        return;
    };
    // A GICv2 routes by an 8-bit CPU mask.
    let max = irq::max_cpus().min(smp::MAX_CPUS);
    let started = smp::start_aps(mp.cpus(), mp.bsp_mpidr, s.pac_key, max);
    // The key is now in every core's registers; drop the copies in memory.
    s.pac_key = None;
    let n = smp::count();
    let up = smp::wait_online(n, AP_TIMEOUT_NS);
    info!("smp: {up}/{n} cpus online ({started} application processors started)");
    if up != n {
        fatal("not every CPU came online");
    }
    let (ok, total) = smp::ipi_selftest();
    if ok != total {
        fatal("IPI ping-pong failed for some CPU pairs");
    }
    // Every core must be ticking on its own timer.
    let before: [u64; smp::MAX_CPUS] = core::array::from_fn(|i| {
        smp::CPUS[i]
            .ticks
            .load(core::sync::atomic::Ordering::Relaxed)
    });
    let until = time::uptime_ns() + 5 * TICK_NS;
    while time::uptime_ns() < until {
        cpu::wait_for_interrupt();
    }
    let ticking = (0..n)
        .filter(|&i| {
            smp::CPUS[i]
                .ticks
                .load(core::sync::atomic::Ordering::Relaxed)
                > before[i]
        })
        .count();
    info!("smp: {ticking}/{n} cpus ticking on their own timer");
    if ticking != n {
        fatal("a CPU's local timer is not ticking");
    }
}

/// Tick period (also the watchdog granularity, PROMPT §4.1).
const TICK_NS: u64 = 10_000_000;
const TICK_SELFTEST: u64 = 50;

/// Runs the periodic tick and reports interrupt latency twice: while the
/// core busy-polls and while it sleeps in `wfi` (ADR-022).
fn tick_selftest(timer_intid: u32) {
    let freq = time::frequency();
    info!(
        "timer: counter {freq} Hz, virtual timer PPI {timer_intid}, tick {} ms",
        TICK_NS / 1_000_000
    );
    tick::start(timer_intid, TICK_NS);
    let t0 = time::uptime_ns();
    // SAFETY: vectors, GIC and the tick handler are ready.
    unsafe { cpu::enable_interrupts() };
    for (mode, sleep) in [("busy-poll", false), ("wfi", true)] {
        tick::reset_stats();
        let start = tick::ticks();
        let mut reported = start;
        while tick::ticks() < start + TICK_SELFTEST / 2 {
            if sleep {
                cpu::wait_for_interrupt();
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
    let elapsed = time::uptime_ns() - t0;
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

pub(crate) fn fatal(msg: &str) -> ! {
    error!("fatal: {msg}");
    power::fatal()
}

pub(crate) fn fatal_fmt(args: core::fmt::Arguments<'_>) -> ! {
    error!("fatal: {args}");
    power::fatal()
}

/// The image's build time (`SOURCE_DATE_EPOCH`, the commit time): the
/// wall clock's lower bound (H7). 0 if the build did not set it.
const BUILD_UNIX: u64 = match option_env!("SOURCE_DATE_EPOCH") {
    Some(s) => parse_u64(s),
    None => 0,
};

const fn parse_u64(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut v: u64 = 0;
    let mut i = 0;
    while i < b.len() {
        let d = b[i];
        if d < b'0' || d > b'9' {
            return 0;
        }
        v = v * 10 + (d - b'0') as u64;
        i += 1;
    }
    v
}

/// Unix time at boot from the firmware RTC via Limine (ADR-009).
static BOOT_UNIX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Wall clock for certificate validity: date at boot plus uptime.
pub(crate) fn now_unix() -> Option<u64> {
    // Relaxed: written once before the clock is installed.
    match BOOT_UNIX.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        t => Some(t + uptime_ns() / 1_000_000_000),
    }
}

/// Wall clock in Unix milliseconds (SQLite's `current_timestamp`).
pub(crate) fn now_unix_ms() -> Option<u64> {
    // Relaxed: written once before the clock is used.
    match BOOT_UNIX.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        t => Some(t * 1000 + uptime_ns() / 1_000_000),
    }
}

/// Nanoseconds since the counter started (boot).
fn uptime_ns() -> u64 {
    time::uptime_ns()
}

/// The module whose path ends in `/esp.img` (the ISO's install entry).
/// Its contents live in module memory, which stays mapped; only the
/// descriptor is in reclaimable memory, so this runs in stage 1.
fn install_image() -> Option<&'static [u8]> {
    let r = MODULES.response()?;
    r.modules()
        .iter()
        .find(|m| m.path().ends_with("/esp.img"))
        .map(|m| m.data())
        .filter(|d| !d.is_empty())
}

/// Offsets in Limine's `struct limine_file` (protocol: `media_type` u32,
/// `unused` u32, `tftp_ip`, `tftp_port`, `partition_index`, `mbr_disk_id`,
/// then the GPT disk and partition UUIDs). The `limine` crate 0.6.5 omits
/// `unused`, so its fields after `media_type` are 4 bytes off (checked
/// against a memory dump under QEMU: its `gpt_disk_uuid` read 4 bytes into
/// the real one). These are read from the raw struct instead.
const FILE_MEDIA_TYPE: usize = 40;
const FILE_GPT_DISK_UUID: usize = 64;
const FILE_STRUCT_MIN: usize = FILE_GPT_DISK_UUID + 16;

/// The boot volume Limine reports for the kernel file.
fn boot_medium() -> devices::BootMedium {
    let Some(f) = EXECUTABLE_FILE.response().map(|r| r.executable_file()) else {
        return devices::BootMedium::default();
    };
    // SAFETY: Limine's file structure is at least FILE_STRUCT_MIN bytes in
    // every revision with these fields (revision 0 of the protocol's file
    // has them all), lives in bootloader memory that is still mapped and
    // not reclaimed (stage 1), and is only read.
    let raw = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(f).cast::<u8>(), FILE_STRUCT_MIN)
    };
    let media = raw
        .get(FILE_MEDIA_TYPE..FILE_MEDIA_TYPE + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(u32::MAX, u32::from_le_bytes);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(
        raw.get(FILE_GPT_DISK_UUID..FILE_STRUCT_MIN)
            .unwrap_or(&[0; 16]),
    );
    devices::BootMedium {
        optical: media == limine::file::LIMINE_MEDIA_TYPE_OPTICAL,
        // Already in GPT's on-disk byte order (little-endian fields).
        disk_guid: (guid != [0; 16]).then_some(urmqtt_store::gpt::Guid(guid)),
    }
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
        TestFault::SealedWrite => selftest::write_sealed(),
        TestFault::ExecHeap => selftest::exec_heap(),
        TestFault::StackOverflow => selftest::stack_overflow(),
        TestFault::NullDeref => trap::probe_read(0x8),
        TestFault::Pac if features.pauth => selftest::pac_violation(),
        TestFault::Bti if features.bti => selftest::bti_violation(),
        TestFault::Pac | TestFault::Bti => info!("test: {fault:?} skipped, CPU lacks the feature"),
    }
}
