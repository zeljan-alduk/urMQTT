//! Limine entry point and the boot sequence of the bootstrap CPU.

#![allow(unsafe_code)]

use limine::BaseRevision;
use limine::request::{
    BootloaderInfoRequest, DateAtBootRequest, DtbRequest, ExecutableAddressRequest,
    ExecutableCmdlineRequest, ExecutableFileRequest, FirmwareTypeRequest, FramebufferRequest,
    HhdmRequest, MemmapRequest, ModulesRequest, MpRequest, Request, RsdpRequest,
};
use limine::{RequestsEndMarker, RequestsStartMarker};

use urmqtt_arch::features::Features;
use urmqtt_arch::{cpu, time, trap as arch_trap};
use urmqtt_log::{error, info, warn};
use urmqtt_platform::EarlyPlatform;
use urmqtt_sync::sync::SpinLock;

#[cfg(target_arch = "aarch64")]
use crate::boot_aarch64 as arch;
#[cfg(target_arch = "x86_64")]
use crate::boot_x86 as arch;
use crate::cmdline::{BootOptions, TestFault};
use crate::{VERSION, console, devices, irq, layout, memory, power, selftest, smp, tick, trap, vm};
pub(crate) use arch::{ARCH, PRIVILEGE_LABEL};

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static BASE_REVISION: BaseRevision = BaseRevision::with_revision(6);
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static BOOTLOADER: BootloaderInfoRequest = BootloaderInfoRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static HHDM: HhdmRequest = HhdmRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static MEMMAP: MemmapRequest = MemmapRequest::new();
/// Ask Limine for x2APIC on x86 (all CPUs, if the CPU has it).
#[cfg(target_arch = "x86_64")]
const MP_FLAGS: u64 = limine::mp::MP_FLAG_X2APIC;
#[cfg(target_arch = "aarch64")]
const MP_FLAGS: u64 = 0;
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static MP: MpRequest = MpRequest::new(MP_FLAGS);
#[used]
#[unsafe(link_section = ".requests")]
static DTB: DtbRequest = DtbRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static RSDP: RsdpRequest = RsdpRequest::new();
/// Also read by the x86 entry stub when the CPU is below the baseline
/// (`arch-x86_64::entry`), by this symbol: no Rust has run yet then.
#[used]
#[unsafe(link_section = ".requests")]
#[unsafe(export_name = "urmqtt_limine_framebuffer_request")]
pub(crate) static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static CMDLINE: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
static DATE_AT_BOOT: DateAtBootRequest = DateAtBootRequest::new();
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static EXECUTABLE_ADDRESS: ExecutableAddressRequest = ExecutableAddressRequest::new();
/// The installation image (the ESP), loaded by the ISO's install entry (S1b).
#[used]
#[unsafe(link_section = ".requests")]
static MODULES: ModulesRequest = ModulesRequest::new();
/// BIOS or UEFI (the diagnostic reports it).
#[used]
#[unsafe(link_section = ".requests")]
pub(crate) static FIRMWARE: FirmwareTypeRequest = FirmwareTypeRequest::new();
/// Where the kernel was loaded from: identifies the boot disk (S1).
#[used]
#[unsafe(link_section = ".requests")]
static EXECUTABLE_FILE: ExecutableFileRequest = ExecutableFileRequest::new();

/// Limine "Entropy" response (not yet wrapped by the `limine` crate).
#[repr(C)]
pub struct EntropyRespData {
    pub(crate) value_count: u64,
    pub(crate) values: *const u64,
}
/// Random 64-bit values from the bootloader's best source (EFI RNG, RNDR).
pub(crate) const ENTROPY_VALUES: u64 = 8;
#[used]
#[unsafe(link_section = ".requests")]
// SAFETY: id and response layout follow the Limine protocol's Entropy feature.
pub(crate) static ENTROPY: Request<EntropyRespData, u64> = unsafe {
    Request::new_raw(
        [0x65ea_8025_5d56_82c5, 0x9117_2407_23f4_93eb],
        0,
        ENTROPY_VALUES,
    )
};

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

// Limine enters at the architecture's `_start` (`arch-aarch64::boot`,
// `arch-x86_64::entry`), which enables FP/SIMD, sets up the stack and calls
// `urmqtt_kmain`. What differs per architecture is behind `arch` (the
// `boot_aarch64.rs` / `boot_x86.rs` seams).

/// State carried across the stack switch into [`kmain_stage2`].
struct Stage2 {
    options: BootOptions,
    platform: Option<urmqtt_platform::PlatformInfo>,
    boot_entropy: [u64; ENTROPY_VALUES as usize],
    pac_key: Option<(u64, u64)>,
    cpus: u64,
    built: vm::Built,
    early_frames: (u64, u64),
    features: Features,
    /// Read before the bootloader's memory is reclaimed.
    medium: devices::BootMedium,
    /// The installation image, if the bootloader loaded one.
    install_image: Option<crate::install::Image>,
    /// Where the data lives this boot (`storage.mode` and the `live` word),
    /// and, for RAM, the memory plan made before the heap was sized (O3).
    storage: StoragePlan,
    ram_bytes: u64,
}

/// The storage decision of stage 1.
enum StoragePlan {
    Disk,
    Ram(urmqtt_store::ram::Reservation),
    /// `live` on a `storage.mode = "disk"` image.
    LiveRefused,
    /// The RAM store does not fit this machine.
    RamFails(urmqtt_store::ram::ReserveError),
}

static STAGE2: SpinLock<Option<Stage2>> = SpinLock::new(None);

#[unsafe(no_mangle)]
extern "C" fn urmqtt_kmain() -> ! {
    // The console first on x86, so that every later failure can say why.
    arch::early_console();
    arch_trap::set_handler(trap::handle);
    arch_trap::install();

    if !BASE_REVISION.is_supported() {
        // No console yet on AArch64; nothing better to do than stop.
        error!("the bootloader does not implement Limine base revision 6");
        cpu::halt();
    }
    let Some(hhdm) = HHDM.response().map(|r| r.offset) else {
        error!("no HHDM response from the bootloader");
        cpu::halt();
    };
    let memmap = MEMMAP.response().map_or(&[][..], |r| r.entries());
    let mem = memory::BootMemory::new(hhdm, memmap);

    let dev = urmqtt_config::CONFIG.env == "dev";
    let early = discover(&mem);
    let mmio_ok = memory::init_early_mmio(&mem);
    // The UART (AArch64) or the time base (x86), mapped in the bootloader's
    // tables; both are replayed into the kernel's.
    let hw = arch::early_hw(early.as_ref(), mmio_ok, dev);
    urmqtt_log::set_clock(uptime_ns);
    urmqtt_log::set_cpu(crate::smp::current);
    if urmqtt_config::CONFIG.observability.syslog_udp.is_some() {
        // Kept from the start; sent once the network is up (M16).
        urmqtt_log::enable_records();
    }
    // Kept from the start for the MQTT console (O2): a subscriber sees the
    // boot log, up to the ring's size.
    urmqtt_log::enable_console();
    if let Some(fb) = FRAMEBUFFER
        .response()
        .and_then(|r| r.framebuffers().first().copied())
    {
        console::init_framebuffer(fb);
    }

    let options = BootOptions::parse(CMDLINE.response().map_or("", |r| r.cmdline()), dev);
    power::set_smoke(options.smoke);
    if let Some(us) = options.slow_log_us {
        urmqtt_log::set_sink_delay_us(us);
    }

    let cpus = MP.response().map_or(1, |r| r.cpus().len());
    urmqtt_log::raw(format_args!(
        "URMQTT BOOT {VERSION}{} cpu={cpus} mem={}\n",
        arch::BOOT_TAG,
        mem.ram_bytes() >> 20
    ));
    info!(
        "env={} {}={} bootloader={} {}",
        urmqtt_config::CONFIG.env,
        arch::PRIVILEGE_LABEL,
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
    hw.log(early.as_ref());
    // H7 lower bound: the image cannot run before it was built, so an
    // earlier clock (an empty CMOS battery, a broken RTC) is unknown time,
    // and everything that needs the time fails closed.
    crate::diag::note_rtc(
        DATE_AT_BOOT.response().map(|d| d.timestamp.max(0) as u64),
        BUILD_UNIX,
    );
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
    crate::diag::note_memory(&mem);
    if options.ignored > 0 {
        warn!("ignored {} kernel command line option(s)", options.ignored);
    }

    // Memory management (M2): kernel page tables, frames, stacks, heap.
    let features = arch::cpu_summary();
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
    let configured_heap_mb = urmqtt_config::CONFIG.memory.kernel_heap_mb;
    // Live mode (O3): the RAM store comes out of the same RAM as the heap, so
    // the heap shrinks (to a power of two) if both do not fit.
    let ram_bytes = mem.ram_bytes();
    // The diagnostic entry never uses a data store, whatever storage.mode says.
    let storage = match urmqtt_config::CONFIG
        .storage
        .mode
        .backing(options.live && !options.diag)
    {
        Ok(urmqtt_config::Backing::Disk) => StoragePlan::Disk,
        Ok(urmqtt_config::Backing::Ram) if options.diag => StoragePlan::Disk,
        Ok(urmqtt_config::Backing::Ram) => {
            let cfg = &urmqtt_config::CONFIG;
            match urmqtt_store::ram::plan(
                ram_bytes,
                cfg.storage.ram_percent,
                configured_heap_mb,
                cfg.storage.sqlite_heap_mb,
                (cfg.memory.min_free_mb * 2).max(8),
            ) {
                Ok(p) => StoragePlan::Ram(p),
                Err(e) => StoragePlan::RamFails(e),
            }
        }
        Err(urmqtt_config::LiveRefused) => StoragePlan::LiveRefused,
    };
    let heap_mb = match &storage {
        StoragePlan::Ram(p) => p.heap_mb,
        _ => configured_heap_mb,
    };
    let built = match vm::build(
        &mem,
        exe.physical_base,
        exe.virtual_base,
        arch::bti(&features),
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

    let pac_key = arch::pac_key(&features);
    let pac_on = pac_key.is_some();
    vm::activate();
    info!("vm: switched to kernel tables {}", arch::ACTIVATED);
    let (main_top, exc_top) = (built.main_top, built.exc_top);
    *STAGE2.lock() = Some(Stage2 {
        options,
        platform: early,
        boot_entropy: bootloader_entropy(),
        pac_key,
        cpus: cpus as u64,
        built,
        early_frames: mem.early_frames_range().unwrap_or((0, 0)),
        features,
        medium: boot_medium(),
        install_image: install_image(),
        storage,
        ram_bytes,
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
        "vm: running on kernel stacks (main {} KiB at {:#x}, exception {} KiB), {}",
        layout::MAIN_STACK_SIZE >> 10,
        s.built.main_top,
        layout::EXC_STACK_SIZE >> 10,
        arch::protection_summary(&s.features),
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
        Ok(()) if urmqtt_store::crc::kat() => info!(
            "crypto: known-answer tests passed (AES-128-GCM, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256, CRC-32C)"
        ),
        Ok(()) => fatal("crypto: CRC-32C known-answer test failed"),
        Err(name) => fatal_fmt(format_args!("crypto: {name} known-answer test failed")),
    }
    // Interrupts and time (M3). Device mappings must precede the lock.
    let (timer_line, controller) = arch::init_interrupts(s.platform.as_ref(), s.cpus);
    info!("{controller}");
    // The boot volume, for the single-disk model (S1, STORAGE-PLAN §2a).
    let medium = s.medium;
    match (medium.optical, medium.disk_guid) {
        (true, _) => info!("boot: from optical media (CD/ISO)"),
        (false, Some(g)) => info!("boot: from a GPT disk, disk GUID {g}"),
        (false, None) => warn!("boot: the bootloader reported no GPT boot disk"),
    }
    devices::set_boot_medium(medium);
    power::set_halt_on_fatal(medium.optical);
    // Live mode (O3): decided in stage 1, announced and enforced here.
    let live = match &s.storage {
        StoragePlan::Disk => false,
        StoragePlan::Ram(p) => {
            crate::live::announce_plan(s.ram_bytes, p, urmqtt_config::CONFIG.memory.kernel_heap_mb);
            // A fatal error in live mode is cured by a reset (the menu comes
            // back and boots live again), unlike on the install entry.
            power::set_halt_on_fatal(false);
            true
        }
        StoragePlan::LiveRefused => fatal(
            "live mode (RAM, ephemeral) was requested by the boot menu, but this image's storage.mode is \"disk\": \
             rebuild with storage.mode = \"auto\" or \"ram\" in deploy/<env>/config.toml, or choose the Install entry",
        ),
        StoragePlan::RamFails(e) => fatal_fmt(format_args!(
            "live mode: the RAM store does not fit this machine ({e:?}; storage.ram_percent = {}, {} MiB RAM)",
            urmqtt_config::CONFIG.storage.ram_percent,
            s.ram_bytes >> 20
        )),
    };
    if s.options.diag && !urmqtt_config::CONFIG.storage.diagnostic {
        fatal(
            "the diagnostic entry was requested by the boot menu, but this image's storage.diagnostic is false: \
             set storage.diagnostic = true in deploy/<env>/config.toml and rebuild, or choose another entry",
        );
    }
    // The diagnostic shares install mode's probe: every disk is kept as a
    // candidate and none is chosen, opened for writing or formatted.
    devices::set_install_mode(s.options.install || s.options.diag);
    // PCIe and virtio (M6): all device MMIO must be mapped before the lock.
    if let Some(p) = s.platform.as_ref() {
        match devices::probe(p, &s.boot_entropy) {
            Ok(()) => {}
            Err(devices::ProbeError::NoEntropy) => fatal_fmt(format_args!(
                "no entropy source (virtio-rng, {}, or a jitter fallback that passes its health tests): refusing to run",
                devices::HW_RNG
            )),
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

    // Where a handshake spends its time on this machine (X9), in
    // microseconds, so a real VPS's log shows it. The estimate also sets the
    // watchdog's handshake budget (ADR-071).
    let profile = urmqtt_tls::bench::run(uptime_ns);
    info!("crypto-profile: {profile}");
    let hs_budget = crate::watchdog::calibrate(profile.handshake_ns());
    info!(
        "watchdog: handshake budget {hs_budget} ms ({}), other handlers {} ms, stuck-core reset at {} ms",
        if urmqtt_config::CONFIG.watchdog.handshake_budget_ms == 0 {
            "calibrated"
        } else {
            "configured"
        },
        urmqtt_config::CONFIG.watchdog.handler_budget_ms,
        crate::watchdog::STUCK_MS
            .max(u64::from(urmqtt_config::CONFIG.watchdog.handler_budget_ms) * 100)
    );

    tick_selftest(timer_line);
    if s.options.diag {
        crate::diag::run(&s.options, s.cpus, &s.features, s.medium);
    }
    if s.options.install {
        crate::install::run(
            s.install_image,
            s.options
                .install_countdown_s
                .unwrap_or(crate::install::COUNTDOWN_S),
            s.options.disk_fault,
        );
    }
    if live {
        // No disk is used, written or even opened: the store is RAM.
        if let StoragePlan::Ram(p) = &s.storage
            && let Err(msg) = devices::prepare_ram_disk(p.ram_bytes)
        {
            fatal_fmt(format_args!("storage: {msg}; refusing to serve"));
        }
    } else if let Err(msg) = devices::prepare_boot_disk(s.options.disk_fault) {
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
    if s.options.db_test == Some(crate::cmdline::DbTest::WatchdogHandshake) {
        crate::watchdog::self_test_handshake();
    }
    if live {
        crate::live::banner();
        if !urmqtt_config::CONFIG.control.service_ids.is_empty() {
            warn!(
                "live: the control channel is on, but its replay protection and the revocations it applies \
                 are lost at a reboot (only the image's revocation list is seeded again)"
            );
        }
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
    // A GICv2 routes by an 8-bit CPU mask; an xAPIC by an 8-bit ID.
    let max = irq::max_cpus().min(smp::MAX_CPUS);
    let started = smp::start_aps(mp.cpus(), smp::bsp_hw_id(mp), s.pac_key, max);
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
    info!(
        "{} {} ms",
        arch::timer_log(timer_intid),
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
    let (spurious, unhandled, last) = irq::stats();
    if unhandled > 0 {
        warn!("irq: {unhandled} interrupt(s) without handler (last: {last}), {spurious} spurious");
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
pub(crate) const BUILD_UNIX: u64 = match option_env!("SOURCE_DATE_EPOCH") {
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

/// The module of the ISO's install entry: `/esp.img` (the EFI system
/// partition; the aarch64 ISO) or `/disk.img` (a finished boot disk image;
/// the universal ISO). Its contents live in module memory, which stays
/// mapped; only the descriptor is in reclaimable memory, so this runs in
/// stage 1.
fn install_image() -> Option<crate::install::Image> {
    use crate::install::Image;
    let r = MODULES.response()?;
    r.modules().iter().find_map(|m| {
        let data = m.data();
        let path = m.path();
        if data.is_empty() {
            None
        } else if path.ends_with("/esp.img") {
            Some(Image::Esp(data))
        } else if path.ends_with("/disk.img") {
            Some(Image::Disk(data))
        } else {
            None
        }
    })
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
    if arch::run_fault(fault, &features) {
        return;
    }
    match fault {
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
        // Handled by the architecture's `run_fault`.
        TestFault::DataAbort
        | TestFault::Pac
        | TestFault::Bti
        | TestFault::GeneralProtection
        | TestFault::DoubleFault => {}
    }
}
