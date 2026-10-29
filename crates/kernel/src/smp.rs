//! Symmetric multiprocessing: per-CPU data, application-processor bring-up
//! through the Limine MP feature, and SGI-based inter-processor interrupts.
//!
//! `TPIDR_EL1` holds the logical CPU index (0 = boot CPU). An AP enters
//! `urmqtt_ap_entry` in the bootloader's tables; the assembly stub switches
//! it to the kernel's tables, keys, vector table and stacks before any
//! compiled code runs, exactly mirroring the boot CPU's configuration.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use limine::mp::MpInfo;
use urmqtt_arch_aarch64::gic::{self, Redistributor};
use urmqtt_arch_aarch64::sync::OnceCell;
use urmqtt_arch_aarch64::{cpu, regs, timer};
use urmqtt_log::{info, warn};

use crate::{irq, layout, tick};

/// Upper bound on CPUs (stack slots and per-CPU array).
pub const MAX_CPUS: usize = 64;

/// SGI numbers.
pub const SGI_PING: u32 = 1;
pub const SGI_PONG: u32 = 2;
pub const SGI_WAKE: u32 = 3;

pub struct PerCpu {
    pub mpidr: AtomicU64,
    pub rd: OnceCell<Redistributor>,
    pub online: AtomicBool,
    pub ticks: AtomicU64,
    /// Logical CPU that last pinged this one.
    ping_from: AtomicUsize,
    /// Pongs received by this CPU.
    pongs: AtomicU64,
    /// Work requested by the boot CPU (see `Work`).
    work: AtomicUsize,
    /// Round-trip results of this CPU's ping run: (pairs ok, sum ns, max ns).
    rt_ok: AtomicU64,
    rt_sum_ns: AtomicU64,
    rt_max_ns: AtomicU64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            mpidr: AtomicU64::new(0),
            rd: OnceCell::new(),
            online: AtomicBool::new(false),
            ticks: AtomicU64::new(0),
            ping_from: AtomicUsize::new(usize::MAX),
            pongs: AtomicU64::new(0),
            work: AtomicUsize::new(0),
            rt_ok: AtomicU64::new(0),
            rt_sum_ns: AtomicU64::new(0),
            rt_max_ns: AtomicU64::new(0),
        }
    }
}

pub static CPUS: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];
static COUNT: AtomicUsize = AtomicUsize::new(1);
/// While set, idle loops busy-poll instead of sleeping (IPI test).
static POLL: AtomicBool = AtomicBool::new(false);

const WORK_NONE: usize = 0;
const WORK_PING_ALL: usize = 1;
const WORK_DONE: usize = 2;
const WORK_DB: usize = 3;
const WORK_LOG_WRITER: usize = 4;
const WORK_DATAPLANE: usize = 5;

/// Logical index of the executing CPU.
pub fn current() -> usize {
    (regs::tpidr_el1() as usize).min(MAX_CPUS - 1)
}

pub fn this() -> &'static PerCpu {
    // `current` is clamped into range, so this never fails.
    CPUS.get(current()).unwrap_or(&CPUS[0])
}

pub fn count() -> usize {
    // Relaxed: set once on the boot CPU before APs start.
    COUNT.load(Ordering::Relaxed)
}

/// Registers the boot CPU as logical CPU 0.
pub fn init_boot_cpu() {
    // SAFETY: TPIDR_EL1 is reserved for the per-CPU index.
    unsafe { regs::set_tpidr_el1(0) };
    // Relaxed: boot CPU only, before any other CPU runs.
    CPUS[0]
        .mpidr
        .store(regs::mpidr_affinity(), Ordering::Relaxed);
    CPUS[0].online.store(true, Ordering::Release);
}

/// Everything an AP needs to join, read by `urmqtt_ap_entry`.
/// Field offsets are hard-coded in the assembly below.
#[repr(C)]
struct ApBoot {
    mair: u64,
    tcr: u64,
    ttbr1: u64,
    sctlr: u64,
    vbar: u64,
    key_lo: u64,
    key_hi: u64,
    exc_top: u64,
    main_top: u64,
    cpu: u64,
    entry: u64,
}

struct ApBootCell(core::cell::UnsafeCell<[ApBoot; MAX_CPUS]>);
// SAFETY: each slot is written by the boot CPU before the matching AP is
// released (Release store of goto_address) and only read by that AP.
unsafe impl Sync for ApBootCell {}

static AP_BOOT: ApBootCell = ApBootCell(core::cell::UnsafeCell::new(
    [const {
        ApBoot {
            mair: 0,
            tcr: 0,
            ttbr1: 0,
            sctlr: 0,
            vbar: 0,
            key_lo: 0,
            key_hi: 0,
            exc_top: 0,
            main_top: 0,
            cpu: 0,
            entry: 0,
        }
    }; MAX_CPUS],
));

unsafe extern "C" {
    fn urmqtt_ap_entry(info: &MpInfo) -> !;
}

core::arch::global_asm!(
    ".text",
    ".global urmqtt_ap_entry",
    "urmqtt_ap_entry:",
    "hint #34", // bti c
    "mrs x9, cpacr_el1",
    "orr x9, x9, #(3 << 20)", // FP/SIMD on before any compiled code
    "msr cpacr_el1, x9",
    "isb",
    "ldr x1, [x0, #32]", // MpInfo.extra_argument -> &ApBoot
    "ldr x2, [x1, #0]",
    "msr mair_el1, x2",
    "ldr x2, [x1, #8]",
    "msr tcr_el1, x2",
    "isb",
    "ldr x2, [x1, #16]",
    "msr ttbr1_el1, x2", // same VAs for kernel text: execution continues
    "isb",
    "tlbi vmalle1",
    "dsb nsh",
    "isb",
    "ldr x2, [x1, #40]",
    "msr S3_0_C2_C1_0, x2", // APIAKeyLo_EL1
    "ldr x2, [x1, #48]",
    "msr S3_0_C2_C1_1, x2", // APIAKeyHi_EL1
    "ldr x2, [x1, #32]",
    "msr vbar_el1, x2",
    "ldr x2, [x1, #24]",
    "msr sctlr_el1, x2", // WXN, EnIA as on the boot CPU
    "isb",
    "msr spsel, #1",
    "ldr x2, [x1, #56]",
    "mov sp, x2", // SP_EL1: exception stack
    "ldr x2, [x1, #64]",
    "msr sp_el0, x2", // SP_EL0: main stack
    "msr spsel, #0",
    "ldr x0, [x1, #72]",
    "ldr x3, [x1, #80]",
    "mov x29, xzr",
    "mov x30, xzr",
    "blr x3",
    "1: wfi",
    "b 1b",
);

const _: () = {
    assert!(core::mem::offset_of!(ApBoot, sctlr) == 24);
    assert!(core::mem::offset_of!(ApBoot, key_lo) == 40);
    assert!(core::mem::offset_of!(ApBoot, exc_top) == 56);
    assert!(core::mem::offset_of!(ApBoot, entry) == 80);
};

fn sysreg_vbar() -> u64 {
    regs::vbar_el1()
}

/// Releases every AP in `cpus` (the Limine MP response). Their stacks must
/// already be mapped (`vm::map_stacks`). Returns the number started.
pub fn start_aps(cpus: &[&MpInfo], bsp_mpidr: u64, pac_key: (u64, u64)) -> usize {
    let mut next = 1usize;
    for info in cpus.iter().filter(|c| c.mpidr != bsp_mpidr) {
        if next >= MAX_CPUS {
            warn!("smp: more than {MAX_CPUS} CPUs, ignoring the rest");
            break;
        }
        let id = next;
        next += 1;
        CPUS[id].mpidr.store(info.mpidr, Ordering::Relaxed);
        let ((_, exc_top), (_, main_top)) = layout::stacks(id as u64);
        // SAFETY: slot `id` is not yet visible to any AP; the Release store in
        // `bootstrap` publishes it before AP `id` reads it.
        let slot = unsafe { &mut (*AP_BOOT.0.get())[id] };
        *slot = ApBoot {
            mair: regs::mair_el1(),
            tcr: regs::tcr_el1(),
            ttbr1: regs::ttbr1_el1(),
            sctlr: regs::sctlr_el1(),
            vbar: sysreg_vbar(),
            key_lo: pac_key.0,
            key_hi: pac_key.1,
            exc_top,
            main_top,
            cpu: id as u64,
            entry: ap_main as *const () as u64,
        };
        info.bootstrap(urmqtt_ap_entry, core::ptr::from_ref(slot) as u64);
    }
    // Relaxed: APs only read COUNT after reporting online, which the boot
    // CPU observes with Acquire before using the count.
    COUNT.store(next, Ordering::Relaxed);
    next - 1
}

/// Waits (bounded) until `n` CPUs are online.
pub fn wait_online(n: usize, timeout_ns: u64) -> usize {
    let deadline = timer::uptime_ns() + timeout_ns;
    loop {
        // Acquire: pairs with each AP's Release store of `online`.
        let up = CPUS
            .iter()
            .take(n)
            .filter(|c| c.online.load(Ordering::Acquire))
            .count();
        if up == n || timer::uptime_ns() > deadline {
            return up;
        }
        core::hint::spin_loop();
    }
}

extern "C" fn ap_main(id: u64) -> ! {
    // SAFETY: TPIDR_EL1 is reserved for the per-CPU index.
    unsafe { regs::set_tpidr_el1(id) };
    let me = this();
    if let Err(e) = irq::init_secondary(me) {
        warn!("cpu {id}: interrupt setup failed: {e:?}");
        cpu::halt();
    }
    tick::start_secondary();
    // Release: publishes this CPU's per-CPU setup to the boot CPU.
    me.online.store(true, Ordering::Release);
    info!(
        "cpu {id} online (mpidr={:#x}, el={})",
        me.mpidr.load(Ordering::Relaxed),
        regs::current_el()
    );
    // SAFETY: vectors, GIC CPU interface and tick are set up on this core.
    unsafe { cpu::unmask_irq() };
    idle_loop(me)
}

/// Per-core idle loop: run requested work, then sleep (or poll in tests).
pub fn idle_loop(me: &'static PerCpu) -> ! {
    loop {
        // Acquire: pairs with the Release in `request`.
        match me.work.load(Ordering::Acquire) {
            WORK_PING_ALL => {
                ping_all();
                // Release: results above are visible to the boot CPU.
                me.work.store(WORK_DONE, Ordering::Release);
            }
            WORK_DB => crate::db::run_core(),
            WORK_LOG_WRITER => crate::db::log_writer(current()),
            WORK_DATAPLANE => crate::netproto::run_ap(current()),
            _ => {}
        }
        // Relaxed: only selects between sleeping and spinning.
        if POLL.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        } else {
            cpu::wfi();
        }
    }
}

/// Turns `cpu` (an idle application processor) into the DB core.
pub fn start_db_core(cpu: usize) {
    start_work(cpu, WORK_DB);
}

/// Makes `cpu` run the telemetry-log crash-test writer (`test=log-crash`).
pub fn start_log_writer(cpu: usize) {
    start_work(cpu, WORK_LOG_WRITER);
}

/// Makes `cpu` a data core (its own network loop and broker shard).
pub fn start_data_core(cpu: usize) {
    start_work(cpu, WORK_DATAPLANE);
}

fn start_work(cpu: usize, work: usize) {
    let Some(pc) = CPUS.get(cpu) else { return };
    // Release: everything prepared for the work item is visible to it.
    pc.work.store(work, Ordering::Release);
    gic::send_sgi(SGI_WAKE, mpidr_of(cpu));
}

/// Sends the wake-up SGI to `cpu` (its handler does nothing; leaving WFI
/// is the point).
pub fn send_wake(cpu: usize) {
    if cpu < MAX_CPUS {
        gic::send_sgi(SGI_WAKE, mpidr_of(cpu));
    }
}

fn mpidr_of(cpu: usize) -> u64 {
    // Relaxed: written before the CPU was started / the test began.
    CPUS[cpu].mpidr.load(Ordering::Relaxed)
}

fn on_ping(_intid: u32) {
    // Acquire: pairs with the sender's Release store before the SGI
    // (the SGI itself is ordered after it by `dsb ishst`).
    let from = this().ping_from.load(Ordering::Acquire);
    if from < MAX_CPUS {
        gic::send_sgi(SGI_PONG, mpidr_of(from));
    }
}

fn on_pong(_intid: u32) {
    // Release: the pinging core polls this counter with Acquire.
    this().pongs.fetch_add(1, Ordering::Release);
}

fn on_wake(_intid: u32) {}

/// Registers the SGI handlers (once) .
pub fn register_ipis() {
    irq::register(SGI_PING, on_ping);
    irq::register(SGI_PONG, on_pong);
    irq::register(SGI_WAKE, on_wake);
}

const PING_TIMEOUT_NS: u64 = 100_000_000;

/// Pings every other online CPU once and waits for its pong.
fn ping_all() {
    let me_id = current();
    let me = this();
    let (mut ok, mut sum, mut max) = (0u64, 0u64, 0u64);
    for target in (0..count()).filter(|&t| t != me_id) {
        let before = me.pongs.load(Ordering::Acquire);
        // Release: `on_ping` on the target reads it with Acquire.
        CPUS[target].ping_from.store(me_id, Ordering::Release);
        let t0 = timer::now();
        gic::send_sgi(SGI_PING, mpidr_of(target));
        let deadline = timer::uptime_ns() + PING_TIMEOUT_NS;
        // Acquire: pairs with the Release increment in `on_pong`.
        while me.pongs.load(Ordering::Acquire) == before {
            if timer::uptime_ns() > deadline {
                break;
            }
            core::hint::spin_loop();
        }
        if me.pongs.load(Ordering::Acquire) != before {
            let ns = timer::ticks_to_ns(timer::now() - t0);
            ok += 1;
            sum += ns;
            max = max.max(ns);
        }
    }
    // Relaxed: published by the Release store of WORK_DONE.
    me.rt_ok.store(ok, Ordering::Relaxed);
    me.rt_sum_ns.store(sum, Ordering::Relaxed);
    me.rt_max_ns.store(max, Ordering::Relaxed);
}

/// Runs the IPI ping-pong test across all ordered CPU pairs.
/// Returns (pairs ok, pairs total).
pub fn ipi_selftest() -> (u64, u64) {
    let n = count();
    // Relaxed: only affects idle behaviour.
    POLL.store(true, Ordering::Relaxed);
    let (mut ok, mut sum, mut max) = (0u64, 0u64, 0u64);
    for (c, pc) in CPUS.iter().enumerate().take(n) {
        if c == 0 {
            ping_all();
        } else {
            // Release: pairs with the Acquire in `idle_loop`.
            pc.work.store(WORK_PING_ALL, Ordering::Release);
            gic::send_sgi(SGI_WAKE, mpidr_of(c));
            let deadline = timer::uptime_ns() + PING_TIMEOUT_NS * n as u64;
            // Acquire: pairs with the Release of WORK_DONE.
            while pc.work.load(Ordering::Acquire) != WORK_DONE {
                if timer::uptime_ns() > deadline {
                    break;
                }
                core::hint::spin_loop();
            }
            pc.work.store(WORK_NONE, Ordering::Relaxed);
        }
        ok += pc.rt_ok.load(Ordering::Relaxed);
        sum += pc.rt_sum_ns.load(Ordering::Relaxed);
        max = max.max(pc.rt_max_ns.load(Ordering::Relaxed));
    }
    POLL.store(false, Ordering::Relaxed);
    let total = (n * (n - 1)) as u64;
    info!(
        "ipi: {ok}/{total} ordered pairs ping-pong ok, round trip avg={} ns max={max} ns",
        sum / ok.max(1)
    );
    (ok, total)
}
