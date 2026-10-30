//! The x86_64 boot sequence of the bootstrap CPU (X2).
//!
//! `_start` (`arch-x86_64::entry`) has already checked the x86-64-v2
//! baseline and enabled the x87/SSE state; this takes over in
//! `urmqtt_kmain`. It brings up the console (COM1 and the Limine
//! framebuffer), the GDT/IDT with the fault reports, and the CPU summary,
//! then runs the requested test fault or stops. Paging (X3), time and
//! interrupts (X4), SMP (X5), ACPI (X6) and the devices follow in later
//! milestones; what the AArch64 sequence does after the CPU summary is not
//! done here yet.

#![allow(unsafe_code)]

use urmqtt_arch::features::{self, Census, Identity};
use urmqtt_arch::{cpu, power as arch_power, serial, trap as arch_trap};
use urmqtt_log::{error, info, warn};

use crate::boot::{BASE_REVISION, BOOTLOADER, CMDLINE, FRAMEBUFFER, HHDM, MEMMAP, MP};
use crate::cmdline::{BootOptions, TestFault};
use crate::{VERSION, console, memory, power, trap};

#[unsafe(no_mangle)]
extern "C" fn urmqtt_kmain() -> ! {
    // The console first, so that every later failure can say why.
    if serial::init() {
        console::init_serial();
    }
    arch_trap::set_handler(trap::handle);
    arch_trap::install();

    if !BASE_REVISION.is_supported() {
        error!("the bootloader does not implement Limine base revision 6");
        cpu::halt();
    }
    let Some(hhdm) = HHDM.response().map(|r| r.offset) else {
        error!("no HHDM response from the bootloader");
        cpu::halt();
    };
    let memmap = MEMMAP.response().map_or(&[][..], |r| r.entries());
    let mem = memory::BootMemory::new(hhdm, memmap);
    if let Some(fb) = FRAMEBUFFER
        .response()
        .and_then(|r| r.framebuffers().first().copied())
    {
        console::init_framebuffer(fb);
    }

    let dev = urmqtt_config::CONFIG.env == "dev";
    let options = BootOptions::parse(CMDLINE.response().map_or("", |r| r.cmdline()), dev);
    power::set_smoke(options.smoke);
    // Only a dev image in smoke mode may write QEMU's debug-exit port.
    arch_power::set_debug_exit(dev && options.smoke);

    // XSAVE state before CPUID is read: the census reports XCR0.
    let xcr0 = cpu::enable_extended_state();
    let id = features::read_id_regs();
    let cpus = MP.response().map_or(1, |r| r.cpus().len());
    urmqtt_log::raw(format_args!(
        "URMQTT BOOT {VERSION} arch=x86_64 cpu={cpus} mem={}\n",
        mem.ram_bytes() >> 20
    ));
    info!(
        "env={} cpl={} bootloader={} {}",
        urmqtt_config::CONFIG.env,
        cpu::privilege_level(),
        BOOTLOADER.response().map_or("?", |r| r.name()),
        BOOTLOADER.response().map_or("?", |r| r.version()),
    );
    info!("cpu: {}", Identity(&id));
    info!("cpu features: {}", Census(&id));
    if xcr0 == 0 {
        warn!("cpu: no XSAVE, x87/SSE state only");
    }
    let f = features::detect();
    info!(
        "cpu dispatch inputs: aes={} pclmul={} sha={} sse4.2={} avx2={} rdrand={} rdseed={}",
        f.aes, f.pclmul, f.sha, f.sse42, f.avx2, f.rdrand, f.rdseed
    );
    console::log_framebuffer();
    mem.log_summary();
    if options.ignored > 0 {
        warn!("ignored {} kernel command line option(s)", options.ignored);
    }

    if let Some(fault) = options.test_fault {
        run_test_fault(fault);
    }

    // Paging, time, interrupts, SMP, ACPI and the devices are the next
    // milestones' work.
    warn!("x86_64: bring-up only (X2): paging, time, devices and the broker are not started");
    urmqtt_log::raw(format_args!("URMQTT READY\n"));
    if options.smoke {
        power::off();
    }
    cpu::halt()
}

fn run_test_fault(fault: TestFault) {
    warn!("test mode: triggering {fault:?}");
    match fault {
        TestFault::NullDeref => trap::probe_read(0x8),
        TestFault::Undefined => trap::undefined_instruction(),
        TestFault::GeneralProtection => arch_trap::general_protection(),
        TestFault::DoubleFault => arch_trap::double_fault(),
        TestFault::BrkResume => {
            trap::brk_resume();
            info!("test: resumed after brk");
        }
        TestFault::Panic => panic!("test panic requested on the command line"),
        TestFault::DataAbort
        | TestFault::WriteText
        | TestFault::ExecHeap
        | TestFault::StackOverflow
        | TestFault::SealedWrite
        | TestFault::Pac
        | TestFault::Bti => info!("test: {fault:?} skipped, needs the x86_64 paging of X3"),
    }
}
