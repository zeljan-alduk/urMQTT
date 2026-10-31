//! The diagnostic boot entry (O4, ADR-063): the ISO menu's third entry
//! passes `diag` on the kernel command line. The kernel detects what it
//! runs on, measures RAM, crypto and disks, draws the dashboard on the
//! framebuffer, writes the same figures as one JSON line on the serial
//! port, and then waits for a key (which reboots). The statistics, the
//! free-space computation, the write guard, the JSON and the dashboard
//! layout are `urmqtt-diag` (host tested); this module is the hardware side.
//!
//! Safety of the disks: every disk is only read, except in one place, the
//! write test, which `urmqtt_diag::guard` has to allow and which checks
//! every request against the free extents again before issuing it.

#![allow(unsafe_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::hint::black_box;
use core::sync::atomic::{AtomicU64, Ordering};

use limine::memmap::MEMMAP_USABLE;
use urmqtt_arch::features::Features;
use urmqtt_arch::time;
use urmqtt_diag::dash::{self, Canvas, Rgb, Status};
use urmqtt_diag::guard::{self, Decision, DiskClass, Facts, Probe, Skip};
use urmqtt_diag::keys::{self, Edit, LineEditor, Ps2};
use urmqtt_diag::report::{
    CryptoBench, Disk, Firmware, Memory, Nic, PciFn, RamBench, RandRead, Report, SeqRead,
    WriteState,
};
use urmqtt_diag::space::{self, DataLayout, Extent};
use urmqtt_diag::stats;
use urmqtt_log::{info, warn};
use urmqtt_store::BlockDevice;
use urmqtt_store::gpt;
use urmqtt_store::layout::{self, Layout};

use crate::boot::{BOOTLOADER, BUILD_UNIX, FIRMWARE};
use crate::cmdline::BootOptions;
use crate::devices::{self, DataDisk, KernelBlk};
use crate::{VERSION, memory, power};

/// What the architecture seam reports about the CPU.
pub struct CpuFacts {
    pub vendor: String,
    pub model: String,
    pub identity: String,
    pub features: Vec<String>,
    pub crypto_units: Vec<String>,
    pub hypervisor: String,
}

#[cfg(target_arch = "aarch64")]
use crate::boot_aarch64 as arch;
#[cfg(target_arch = "x86_64")]
use crate::boot_x86 as arch;

static MEM_TOTAL: AtomicU64 = AtomicU64::new(0);
static MEM_USABLE: AtomicU64 = AtomicU64::new(0);
static MEM_RESERVED: AtomicU64 = AtomicU64::new(0);
/// The RTC at boot plus one (0: the bootloader gave none).
static RTC_PLUS_ONE: AtomicU64 = AtomicU64::new(0);

/// Records the memory map's totals (early, before the map is reclaimed).
pub fn note_memory(mem: &memory::BootMemory) {
    let (mut total, mut usable, mut reserved) = (0u64, 0u64, 0u64);
    for e in mem.entries() {
        if memory::is_ram(e.type_) {
            total += e.length;
            if e.type_ == MEMMAP_USABLE {
                usable += e.length;
            }
        } else {
            reserved += e.length;
        }
    }
    // Relaxed: written once on the boot CPU before the diagnostic runs.
    MEM_TOTAL.store(total, Ordering::Relaxed);
    MEM_USABLE.store(usable, Ordering::Relaxed);
    MEM_RESERVED.store(reserved, Ordering::Relaxed);
}

/// Records the firmware clock at boot.
pub fn note_rtc(raw: Option<u64>, _build: u64) {
    // Relaxed: see `note_memory`.
    RTC_PLUS_ONE.store(raw.map_or(0, |t| t + 1), Ordering::Relaxed);
}

/// The dashboard drawn on the log's framebuffer console.
struct Fb<'a>(&'a mut urmqtt_log::fbcon::FbConsole<'static>);

impl Canvas for Fb<'_> {
    fn cols(&self) -> usize {
        self.0.cols()
    }
    fn rows(&self) -> usize {
        self.0.rows()
    }
    fn cell_px(&self) -> usize {
        self.0.cell_px()
    }
    fn fill_px(&mut self, x: usize, y: usize, w: usize, h: usize, c: Rgb) {
        self.0.fill_rect(x, y, w, h, c);
    }
    fn text(&mut self, col: usize, row: usize, s: &str, fg: Rgb, bg: Rgb) {
        self.0.text_at(col, row, s, fg, bg);
    }
}

/// The run's state: the report, the screen and the clock.
struct Run {
    report: Report,
    status: Status,
    screen: bool,
    clock: fn() -> u64,
    clock_name: &'static str,
}

impl Run {
    fn redraw(&self) {
        if self.screen {
            let (r, s) = (&self.report, &self.status);
            urmqtt_log::with_framebuffer(|fb| dash::draw(&mut Fb(fb), r, s));
        }
    }

    fn stage(&mut self, name: &str) {
        self.status.step += 1;
        self.status.stage = format!("Measuring: {name}");
        info!("diag: [{}/{}] {name}", self.status.step, self.status.steps);
        self.redraw();
    }
}

fn now() -> u64 {
    time::uptime_ns()
}

/// Runs `f` repeatedly for about `budget_ns` (at least once); returns the
/// number of runs and the time they took.
fn timed(budget_ns: u64, mut f: impl FnMut()) -> (u64, u64) {
    let t0 = now();
    let mut n = 0u64;
    loop {
        f();
        n += 1;
        let dt = now().saturating_sub(t0);
        if dt >= budget_ns {
            return (n, dt.max(1));
        }
    }
}

/// Entry point: never returns (a key reboots; smoke mode powers off).
pub fn run(
    options: &BootOptions,
    cpus: u64,
    features: &Features,
    medium: devices::BootMedium,
) -> ! {
    let _ = features;
    urmqtt_log::raw(format_args!(
        "\nURMQTT DIAG START {VERSION}: hardware detection and measurements; read-only except a confirmed write test in unallocated space\n"
    ));
    let (clock, clock_name) = time::finest_clock();
    let screen =
        urmqtt_log::with_framebuffer(|fb| fb.cols() >= 40 && fb.rows() >= 12).unwrap_or(false);
    let mut run = Run {
        report: detect(cpus, medium),
        status: Status::default(),
        screen,
        clock,
        clock_name,
    };
    // The dashboard owns the framebuffer from here; the log goes on on the
    // serial port.
    if screen {
        urmqtt_log::set_framebuffer_logging(false);
    } else {
        warn!("diag: no usable framebuffer: the figures go to the serial port only");
    }
    let mut disks = devices::take_diag_disks();
    for d in &disks {
        run.report.disks.push(Disk {
            name: d.name.clone(),
            bus: d.bus.into(),
            sectors: d.sectors,
            read_only: d.read_only,
            boot_medium: d.boot_medium,
            state: "not read".into(),
            unmeasured: d.disk.is_none().then(|| {
                "another LUN of this virtio-scsi controller is measured (one per controller)".into()
            }),
            ..Disk::default()
        });
    }
    let measured = disks.iter().filter(|d| d.disk.is_some()).count();
    run.status.steps = 3 + measured * 2;
    log_detection(&run.report);
    run.status.stage = "Detection complete".into();
    run.redraw();

    ram_throughput(&mut run);
    ram_latency(&mut run);
    crypto(&mut run);
    for (i, d) in disks.iter_mut().enumerate() {
        if let Some(disk) = d.disk.take() {
            disk_tests(&mut run, i, disk, options);
        }
    }

    run.status.stage = "Done".into();
    run.status.step = run.status.steps;
    run.status.done = true;
    run.redraw();
    let json = run.report.to_json();
    urmqtt_log::raw(format_args!("URMQTT-DIAG-JSON {json}\n"));
    info!(
        "diag: complete: {} MiB/s RAM read, {} disk(s), handshake {} us",
        run.report.ram.as_ref().map_or(0, |r| r.read_mib_s),
        run.report.disks.len(),
        run.report
            .crypto
            .as_ref()
            .map_or(0, |c| c.handshake_us_x10 / 10)
    );
    urmqtt_log::raw(format_args!("URMQTT DIAG DONE\n"));
    urmqtt_log::flush();
    // Only a dev image in smoke mode ends by itself; every other run keeps
    // the screen until a key is pressed.
    if crate::power::smoke() {
        power::off()
    }
    let mut ps2 = Ps2::default();
    loop {
        if read_byte(&mut ps2).is_some() {
            urmqtt_log::raw(format_args!("diag: key pressed, rebooting\n"));
            power::reboot()
        }
        core::hint::spin_loop();
    }
}

/// One typed character from the serial port or the keyboard.
fn read_byte(ps2: &mut Ps2) -> Option<u8> {
    if let Some(b) = urmqtt_log::read_serial_byte() {
        return Some(b);
    }
    arch::poll_scancode().and_then(|c| ps2.feed(c))
}

// ---------------------------------------------------------------- detection

fn detect(cpus: u64, medium: devices::BootMedium) -> Report {
    let c = arch::diag_cpu();
    let sealed = crate::cpu_dispatch::sealed();
    let backend = sealed.map_or_else(
        || String::from("unsealed"),
        |s| {
            format!(
                "{} (detected {}, disabled {})",
                s.selection, s.detected, s.disabled
            )
        },
    );
    let mut time = arch::diag_time();
    let rtc = RTC_PLUS_ONE.load(Ordering::Relaxed);
    time.rtc_unix = rtc.checked_sub(1);
    time.rtc_plausible = time.rtc_unix.is_some_and(|t| t >= black_box(BUILD_UNIX));
    let fw = FIRMWARE.response().map_or(0, |r| r.firmware_type);
    let (bl, blv) = BOOTLOADER
        .response()
        .map_or(("?", "?"), |r| (r.name(), r.version()));
    let (nics, other_nics) = {
        let devs = devices::DEVICES.lock();
        let pci = devices::PCI_SEEN.lock();
        let bdf = pci
            .iter()
            .find(|p| p.driver == Some("virtio-net"))
            .map(|p| p.bdf.clone())
            .unwrap_or_default();
        let nics = devs
            .net
            .iter()
            .map(|n| Nic {
                name: format!("virtio-net {bdf}"),
                mac: Some(n.mac),
                link: Some(n.link_up()),
            })
            .collect();
        (nics, devices::OTHER_NICS.lock().clone())
    };
    Report {
        version: VERSION.into(),
        arch: crate::boot::ARCH.into(),
        env: urmqtt_config::CONFIG.env.into(),
        hypervisor: c.hypervisor.clone(),
        cpu: urmqtt_diag::report::Cpu {
            vendor: c.vendor,
            model: c.model,
            identity: c.identity,
            logical: cpus as u32,
            features: c.features,
            crypto_units: c.crypto_units,
            crypto_backend: backend,
        },
        memory: Memory {
            // Relaxed: set once before the diagnostic.
            total: MEM_TOTAL.load(Ordering::Relaxed),
            usable: MEM_USABLE.load(Ordering::Relaxed),
            reserved: MEM_RESERVED.load(Ordering::Relaxed),
        },
        pci: devices::PCI_SEEN
            .lock()
            .iter()
            .map(|p| PciFn {
                bdf: p.bdf.clone(),
                vendor: p.vendor,
                device: p.device,
                class: p.class,
                subclass: p.subclass,
                driver: p.driver,
            })
            .collect(),
        disks: Vec::new(),
        nics,
        other_nics,
        time,
        firmware: Firmware {
            kind: arch::firmware_kind(fw).into(),
            bootloader: format!("{bl} {blv}"),
            medium: if medium.optical {
                "optical media (ISO)".into()
            } else {
                "disk".into()
            },
        },
        ram: None,
        crypto: None,
    }
}

fn log_detection(r: &Report) {
    info!(
        "diag: cpu {} {} ({}), {} logical, units [{}], {}",
        r.cpu.vendor,
        r.cpu.model,
        r.cpu.identity,
        r.cpu.logical,
        r.cpu.crypto_units.join(" "),
        r.cpu.crypto_backend
    );
    info!(
        "diag: memory total {} MiB, usable {} MiB, reserved {} MiB; {} PCI function(s); {} disk(s) to read; {} NIC(s); firmware {}",
        r.memory.total >> 20,
        r.memory.usable >> 20,
        r.memory.reserved >> 20,
        r.pci.len(),
        r.disks.len(),
        r.nics.len(),
        r.firmware.kind
    );
}

// ---------------------------------------------------------------------- RAM

/// A zeroed, contiguous buffer from the frame allocator (not the kernel
/// heap, which is small on a dev image), as large as the machine allows.
fn ram_buffer() -> Option<&'static mut [u64]> {
    for mib in [128usize, 64, 32, 16, 8, 4] {
        if let Some((va, _pa, len)) = crate::vm::dma_alloc(mib << 20) {
            // SAFETY: freshly allocated, zeroed frames reached through the
            // HHDM, owned by the diagnostic for the rest of the run (never
            // freed: the run ends in a reboot).
            return Some(unsafe { core::slice::from_raw_parts_mut(va as *mut u64, len / 8) });
        }
    }
    None
}

static BUF_ADDR: AtomicU64 = AtomicU64::new(0);

fn ram_throughput(run: &mut Run) {
    run.stage("RAM read, write and copy throughput");
    let Some(buf) = ram_buffer() else {
        warn!("diag: no memory for the RAM benchmark");
        return;
    };
    // Relaxed: only the boot CPU runs the diagnostic.
    BUF_ADDR.store(buf.as_ptr() as u64, Ordering::Relaxed);
    let bytes = (buf.len() * 8) as u64;
    let budget = 150_000_000;
    // Read: eight independent sums per pass.
    let (n, dt) = timed(budget, || {
        let mut acc = [0u64; 8];
        for c in buf.as_chunks::<8>().0 {
            for (a, v) in acc.iter_mut().zip(c) {
                *a = a.wrapping_add(*v);
            }
        }
        black_box(acc);
    });
    let read = stats::mib_per_s(bytes * n, dt);
    // Write.
    let mut v = 1u64;
    let (n, dt) = timed(budget, || {
        v = v.wrapping_add(0x9e37_79b9);
        let x = black_box(v);
        for w in buf.iter_mut() {
            *w = x;
        }
    });
    let write = stats::mib_per_s(bytes * n, dt);
    // Copy: one half onto the other.
    let (lo, hi) = buf.split_at_mut(buf.len() / 2);
    let half = (lo.len() * 8) as u64;
    let (n, dt) = timed(budget, || {
        hi[..lo.len()].copy_from_slice(lo);
        black_box(&hi[0]);
    });
    let copy = stats::mib_per_s(half * n, dt);
    info!(
        "diag: RAM {} MiB buffer: read {read} MiB/s, write {write} MiB/s, copy {copy} MiB/s",
        bytes >> 20
    );
    run.report.ram = Some(RamBench {
        buffer: bytes,
        read_mib_s: read,
        write_mib_s: write,
        copy_mib_s: copy,
        latency: Vec::new(),
    });
    run.redraw();
}

/// Builds a single-cycle random permutation over `nodes` cache lines of
/// `buf` (word 0 of each line holds the index of the next one).
fn make_chain(buf: &mut [u64], nodes: usize) {
    for i in 0..nodes {
        buf[i * 8] = i as u64;
    }
    // Sattolo's shuffle yields one cycle through all nodes.
    let mut x = 0x2545_f491_4f6c_dd1du64 ^ nodes as u64;
    for i in (1..nodes).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let j = (x % i as u64) as usize;
        buf.swap(i * 8, j * 8);
    }
}

fn ram_latency(run: &mut Run) {
    run.stage("RAM access latency (pointer chase)");
    let addr = BUF_ADDR.load(Ordering::Relaxed);
    let Some(ram) = run.report.ram.as_ref() else {
        return;
    };
    let len = (ram.buffer / 8) as usize;
    // SAFETY: the buffer `ram_throughput` allocated and never freed; this
    // is the only user now.
    let buf: &mut [u64] = unsafe { core::slice::from_raw_parts_mut(addr as *mut u64, len) };
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut size = 4096usize;
    // Up to 64 MiB: far beyond any cache, and a chain this long has
    // 1M nodes.
    while size <= 64 << 20 && size / 8 <= buf.len() {
        let nodes = size / 64;
        make_chain(buf, nodes);
        let steps = 1u64 << 21;
        let t0 = now();
        let mut p = 0usize;
        for _ in 0..steps {
            p = buf[p * 8] as usize;
        }
        black_box(p);
        let dt = now().saturating_sub(t0);
        out.push((size as u64, stats::div_x10(dt, steps)));
        size *= 2;
    }
    if let Some(r) = run.report.ram.as_mut() {
        if let (Some(first), Some(last)) = (out.first(), out.last()) {
            info!(
                "diag: RAM latency {} ns at {} KiB ... {} ns at {} MiB",
                urmqtt_diag::fmt::x10(first.1),
                first.0 >> 10,
                urmqtt_diag::fmt::x10(last.1),
                last.0 >> 20
            );
        }
        r.latency = out;
    }
    run.redraw();
}

// ------------------------------------------------------------------- crypto

fn crypto(run: &mut Run) {
    run.stage("crypto and TLS handshake cost");
    let Some(p) = urmqtt_tls::probe::Probe::new() else {
        warn!("diag: crypto probe setup failed");
        return;
    };
    let per_x10 = |n: u64, dt: u64| dt / n.max(1) / 100;
    let (n, dt) = timed(80_000_000, || {
        black_box(p.x25519(black_box(1)));
    });
    let x = per_x10(n, dt);
    let (n, dt) = timed(80_000_000, || {
        black_box(p.sign());
    });
    let sign = per_x10(n, dt);
    let (n, dt) = timed(80_000_000, || {
        black_box(p.verify());
    });
    let verify = per_x10(n, dt);
    // One server-side mutual-TLS handshake: two X25519 operations (the key
    // share, fixed-base, and the shared secret, ladder), one signature (CertificateVerify) and
    // two verifications (the client's CertificateVerify and its chain).
    let clock = run.clock;
    let (mut ticks, mut ns, mut reps) = (0u64, 0u64, 0u64);
    let t_end = now() + 120_000_000;
    while reps < 3 || now() < t_end {
        let (a, t0) = (clock(), now());
        black_box(p.x25519_base(2));
        black_box(p.x25519(3));
        black_box(p.sign());
        black_box(p.verify());
        black_box(p.verify_ca());
        ticks += clock().wrapping_sub(a);
        ns += now().saturating_sub(t0);
        reps += 1;
    }
    let mut buf = vec![0x5au8; 64 * 1024];
    let rate = |f: &mut dyn FnMut()| {
        let (n, dt) = timed(100_000_000, f);
        stats::mib_per_s(n * 65_536, dt)
    };
    let aes = rate(&mut || {
        black_box(urmqtt_tls::probe::aes_gcm(&mut buf));
    });
    let mut buf2 = vec![0x5au8; 64 * 1024];
    let chacha = rate(&mut || {
        black_box(urmqtt_tls::probe::chacha(&mut buf2));
    });
    let sha = rate(&mut || {
        black_box(urmqtt_tls::probe::sha256(&buf));
    });
    let crc = rate(&mut || {
        black_box(urmqtt_store::crc::crc32c(&buf));
    });
    let c = CryptoBench {
        x25519_us_x10: x,
        sign_us_x10: sign,
        verify_us_x10: verify,
        handshake_us_x10: ns / reps / 100,
        handshake_ticks: ticks / reps,
        tick_clock: run.clock_name.into(),
        aes_gcm_mib_s: aes,
        chacha_mib_s: chacha,
        sha256_mib_s: sha,
        crc32c_mib_s: crc,
    };
    info!(
        "diag: TLS handshake about {} us ({} ticks of the {}); AES-GCM {aes}, ChaCha20 {chacha}, SHA-256 {sha}, CRC-32C {crc} MiB/s",
        c.handshake_us_x10 / 10,
        c.handshake_ticks,
        c.tick_clock
    );
    run.report.crypto = Some(c);
    run.redraw();
}

// -------------------------------------------------------------------- disks

fn read_range(blk: &mut DataDisk, lba: u64, sectors: u64, buf: &mut [u8]) -> bool {
    let chunk = (blk.max_io().min(buf.len()) / 512).max(1) as u64;
    let mut at = 0u64;
    while at < sectors {
        let n = chunk.min(sectors - at);
        let Some(b) = buf.get_mut(..(n * 512) as usize) else {
            return false;
        };
        if blk.read(lba + at, b).is_err() {
            return false;
        }
        at += n;
    }
    true
}

fn is_zero_range(blk: &mut DataDisk, lba: u64, sectors: u64, buf: &mut [u8]) -> Option<bool> {
    let chunk = (blk.max_io().min(buf.len()) / 512).max(1) as u64;
    let mut at = 0u64;
    let mut zero = true;
    while at < sectors {
        let n = chunk.min(sectors - at);
        let b = buf.get_mut(..(n * 512) as usize)?;
        blk.read(lba + at, b).ok()?;
        zero &= b.iter().all(|&x| x == 0);
        at += n;
    }
    Some(zero)
}

/// What is on the disk and which sectors are free, by reading only.
struct Survey {
    class: DiskClass,
    free: Vec<Extent>,
}

fn survey(blk: DataDisk, sectors: u64, scratch: &mut [u8]) -> (DataDisk, Survey) {
    let mut kb = KernelBlk { blk, flush: true };
    let head = sectors.min(space::HEAD_GUARD);
    let tail = sectors.min(space::TAIL_GUARD);
    let head_zero = is_zero_range(&mut kb.blk, 0, head, scratch);
    let tail_zero = is_zero_range(&mut kb.blk, sectors - tail, tail, scratch);
    let table = gpt::read_table(&mut kb, 1).ok().flatten().or_else(|| {
        gpt::read_table(&mut kb, sectors.saturating_sub(1))
            .ok()
            .flatten()
    });
    let probe = Probe {
        read_ok: head_zero.is_some() && tail_zero.is_some(),
        head_zero: head_zero == Some(true),
        tail_zero: tail_zero == Some(true),
        gpt_valid: table.is_some(),
        has_data_partition: table.as_ref().is_some_and(|t| t.data_partition().is_some()),
    };
    let class = guard::classify(&probe);
    let parts: Vec<Extent> = table
        .as_ref()
        .map(|t| {
            t.entries
                .iter()
                .filter(|e| e.is_used())
                .map(|e| Extent::new(e.first_lba, e.last_lba + 1))
                .collect()
        })
        .unwrap_or_default();
    // The data partition's region table, from its superblock.
    let data = table
        .as_ref()
        .and_then(|t| t.data_partition())
        .and_then(|e| {
            // Both superblock slots; the one in force names the regions. An
            // older layout or a damaged one is unreadable here, so the whole
            // partition counts as taken (the safe answer).
            let mut a = [0u8; layout::BLOCK];
            let mut b = [0u8; layout::BLOCK];
            kb.read(e.first_lba + layout::SB_SLOT_LBA[0], &mut a).ok()?;
            kb.read(e.first_lba + layout::SB_SLOT_LBA[1], &mut b).ok()?;
            let (l, _) = Layout::select(&a, &b, e.sectors()).ok().flatten()?;
            Some(DataLayout {
                partition: Extent::new(e.first_lba, e.last_lba + 1),
                // The header area: both superblock slots, the size tables,
                // the migration blocks and the rest of the first alignment unit.
                header_sectors: u64::from(l.align_sectors).max(layout::HEADER_SECTORS),
                regions: l.regions.iter().map(|r| (r.start, r.sectors)).collect(),
            })
        });
    let taken = match class {
        DiskClass::Blank => Vec::new(),
        _ => space::taken(&parts, data.as_ref()),
    };
    let free = if matches!(
        class,
        DiskClass::Unreadable | DiskClass::Foreign { gpt: false }
    ) {
        Vec::new()
    } else {
        space::free_extents(sectors, &taken)
    };
    (kb.blk, Survey { class, free })
}

fn class_name(c: DiskClass) -> &'static str {
    match c {
        DiskClass::Installed => "installed",
        DiskClass::Blank => "blank",
        DiskClass::Foreign { .. } => "foreign",
        DiskClass::Unreadable => "unreadable",
    }
}

fn disk_tests(run: &mut Run, idx: usize, mut blk: DataDisk, options: &BootOptions) {
    let (name, sectors, read_only, boot_medium) = {
        let d = &run.report.disks[idx];
        (d.name.clone(), d.sectors, d.read_only, d.boot_medium)
    };
    run.stage(&format!("{name}: contents, sequential and random reads"));
    let mut scratch = vec![0u8; 256 << 10];
    let (b, sv) = survey(blk, sectors, &mut scratch);
    blk = b;
    run.report.disks[idx].state = class_name(sv.class).into();
    info!(
        "diag: {name}: {} MiB, contents {}, {} unallocated extent(s), largest {} MiB",
        (sectors * 512) >> 20,
        class_name(sv.class),
        sv.free.len(),
        space::largest(&sv.free).map_or(0, |e| (e.len() * 512) >> 20)
    );
    run.redraw();

    // Sequential read from the start, at most 64 MiB or 2 s.
    let span = sectors.min(64 * 2048);
    let (mut at, t0) = (0u64, now());
    let chunk = (blk.max_io().min(scratch.len()) / 512).max(1) as u64;
    let mut ok = true;
    while at < span && now().saturating_sub(t0) < 2_000_000_000 {
        let n = chunk.min(span - at);
        if !read_range(&mut blk, at, n, &mut scratch) {
            ok = false;
            break;
        }
        at += n;
    }
    let ns = now().saturating_sub(t0).max(1);
    if ok && at > 0 {
        run.report.disks[idx].seq_read = Some(SeqRead {
            bytes: at * 512,
            ns,
            mib_s: stats::mib_per_s(at * 512, ns),
            block: chunk * 512,
        });
    }
    // Random 4 KiB reads over the whole disk, at most 2000 or 2 s.
    if sectors >= 16 {
        let blocks = sectors / 8;
        let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ sectors;
        let mut lat: Vec<u64> = Vec::new();
        let t0 = now();
        let mut b4 = [0u8; 4096];
        while lat.len() < 2000 && now().saturating_sub(t0) < 2_000_000_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let lba = (x % blocks) * 8;
            let a = now();
            if blk.read(lba, &mut b4).is_err() {
                break;
            }
            lat.push(now().saturating_sub(a));
        }
        let total = now().saturating_sub(t0).max(1);
        let ops = lat.len() as u64;
        if let Some(s) = stats::summarize(&mut lat) {
            run.report.disks[idx].rand_read = Some(RandRead {
                ops,
                ns: total,
                iops: stats::per_second(ops, total),
                block: 4096,
                lat: s,
            });
        }
    }
    {
        let d = &run.report.disks[idx];
        info!(
            "diag: {name}: sequential read {} MiB/s, random 4K {} IOPS, p50 {} us, p99 {} us",
            d.seq_read.map_or(0, |s| s.mib_s),
            d.rand_read.map_or(0, |r| r.iops),
            d.rand_read.map_or(0, |r| r.lat.p50 / 1000),
            d.rand_read.map_or(0, |r| r.lat.p99 / 1000)
        );
    }
    run.redraw();

    // The write test, if the guard allows it.
    run.stage(&format!("{name}: sequential write"));
    let facts = Facts {
        class: sv.class,
        read_only,
        boot_medium,
    };
    let state = match guard::decide(&facts, &sv.free, false) {
        Decision::Skip(s) => WriteState::Skipped(s.reason().into()),
        Decision::Run(w) => write_test(&mut blk, w, &sv.free),
        Decision::NeedConfirmation(w) => {
            let ask = format!(
                "{name} holds no urMQTT installation. Type {} + Enter to write {} MiB at LBA {} (unallocated space only), anything else skips",
                keys::CONFIRM_WORD,
                (w.len() * 512) >> 20,
                w.start
            );
            if confirm(run, &ask, options) {
                match guard::decide(&facts, &sv.free, true) {
                    Decision::Run(w) => write_test(&mut blk, w, &sv.free),
                    Decision::Skip(s) => WriteState::Skipped(s.reason().into()),
                    Decision::NeedConfirmation(_) => {
                        WriteState::Skipped(Skip::NotConfirmed.reason().into())
                    }
                }
            } else {
                WriteState::Skipped(Skip::NotConfirmed.reason().into())
            }
        }
    };
    match &state {
        WriteState::Skipped(why) => info!("diag: {name}: write test skipped: {why}"),
        WriteState::Failed(why) => warn!("diag: {name}: write test FAILED: {why}"),
        WriteState::Done { mib_s, bytes, .. } => {
            info!(
                "diag: {name}: sequential write {mib_s} MiB/s over {} MiB",
                bytes >> 20
            )
        }
        WriteState::Pending => {}
    }
    run.report.disks[idx].write = state;
    run.status.prompt = None;
    run.status.typed.clear();
    run.redraw();
}

/// Asks the operator on the serial port and the keyboard; true if the
/// confirmation word was typed in time. Anything else, Escape, or silence
/// until the timeout is a no.
fn confirm(run: &mut Run, question: &str, options: &BootOptions) -> bool {
    if options.diag_auto_confirm {
        warn!("diag: write confirmation given on the kernel command line (dev image)");
        return true;
    }
    let secs = options.diag_confirm_timeout_s.unwrap_or(60);
    urmqtt_log::raw(format_args!(
        "\ndiag: {question} (waiting {secs} s)\ndiag: type {} and press Enter: ",
        keys::CONFIRM_WORD
    ));
    run.status.prompt = Some(format!("{question} [{secs} s]"));
    run.status.typed.clear();
    run.redraw();
    let end = now() + secs * 1_000_000_000;
    let mut ps2 = Ps2::default();
    let mut ed = LineEditor::default();
    while now() < end {
        let Some(b) = read_byte(&mut ps2) else {
            core::hint::spin_loop();
            continue;
        };
        match ed.feed(b) {
            Edit::None => {}
            Edit::Changed => {
                run.status.typed = ed.line().into();
                run.redraw();
            }
            Edit::Line(l) if l.is_empty() => {}
            Edit::Line(l) => {
                let yes = keys::is_confirmation(&l);
                urmqtt_log::raw(format_args!(
                    "\ndiag: {}\n",
                    if yes { "confirmed" } else { "not confirmed" }
                ));
                return yes;
            }
            Edit::Cancelled => {
                urmqtt_log::raw(format_args!("\ndiag: cancelled\n"));
                return false;
            }
        }
    }
    urmqtt_log::raw(format_args!("\ndiag: no answer, write test skipped\n"));
    false
}

/// Sequentially writes a pseudo-random pattern into `window` (which the
/// guard computed from the free extents), reads it back, and puts zeros
/// back. Every request is checked against `free` again before it is sent.
fn write_test(blk: &mut DataDisk, window: Extent, free: &[Extent]) -> WriteState {
    if !space::window_is_free(window, free) {
        return WriteState::Failed(
            "internal: the window is not free space; nothing written".into(),
        );
    }
    let chunk = (blk.max_io().min(256 << 10) / 512).max(1) as u64;
    let mut pat = vec![0u8; (chunk * 512) as usize];
    let mut x = 0xd1b5_4a32_d192_ed03u64;
    for w in pat.as_chunks_mut::<8>().0 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        w.copy_from_slice(&x.to_le_bytes());
    }
    let mut at = window.start;
    let t0 = now();
    let mut err: Option<&str> = None;
    while at + chunk <= window.end && now().saturating_sub(t0) < 3_000_000_000 {
        let w = Extent::span(at, chunk);
        if !space::window_is_free(w, free) {
            err = Some("internal: a request left the free space; stopped");
            break;
        }
        if blk.write(at, &pat).is_err() {
            err = Some("the device refused a write");
            break;
        }
        at += chunk;
    }
    let flushed = blk.flush().is_ok();
    let ns = now().saturating_sub(t0).max(1);
    let written = Extent::new(window.start, at);
    // Read back what was written.
    let mut verified = err.is_none() && flushed;
    if !written.is_empty() {
        let mut back = vec![0u8; pat.len()];
        let mut p = written.start;
        while p < written.end && verified {
            if blk.read(p, &mut back).is_err() || back != pat {
                verified = false;
            }
            p += chunk;
        }
        // Leave the unallocated space as it looked for a blank disk: zeros.
        let zeros = vec![0u8; pat.len()];
        let mut p = written.start;
        while p < written.end {
            let w = Extent::span(p, chunk);
            if space::window_is_free(w, free) && blk.write(p, &zeros).is_err() {
                err = Some("the device refused a write while zeroing the test area");
                break;
            }
            p += chunk;
        }
        let _ = blk.flush();
    }
    match err {
        Some(e) => WriteState::Failed(e.into()),
        None if written.is_empty() => WriteState::Failed("nothing could be written".into()),
        None => WriteState::Done {
            bytes: written.len() * 512,
            ns,
            mib_s: stats::mib_per_s(written.len() * 512, ns),
            first_lba: written.start,
            sectors: written.len(),
            verified,
        },
    }
}
