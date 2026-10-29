//! The facade's API contract (ADR-040).
//!
//! Each line binds a facade item to the exact signature the kernel relies
//! on. A second architecture must provide every item with the same shape,
//! or this module fails to compile for it. Types that differ by
//! architecture by nature (the trap frame, the controller handle) are bound
//! by the operations the kernel performs on them.

#![allow(dead_code)]
// The signatures are spelled out on purpose: they are the contract.
#![allow(clippy::type_complexity)]

use crate::{barrier, cpu, entropy, features, ipi, irq, msi, paging, percpu, power, time, trap};

// barrier
const BARRIER_DOORBELL: fn() = barrier::doorbell;

// cpu
const CPU_HALT: fn() -> ! = cpu::halt;
const CPU_WAIT: fn() = cpu::wait_for_interrupt;
const CPU_ENABLE_INTERRUPTS: unsafe fn() = cpu::enable_interrupts;
const CPU_IRQ_SAVE: fn() -> u64 = cpu::irq_save;
const CPU_IRQ_RESTORE: fn(u64) = cpu::irq_restore;
const CPU_PRIVILEGE_LEVEL: fn() -> u8 = cpu::privilege_level;
const CPU_SET_RA_KEY: unsafe fn(u64, u64) = cpu::set_return_address_key;
const CPU_SWITCH_TO: unsafe fn(u64, u64, u64, cpu::Continuation, bool) -> ! = cpu::switch_to;

// irq
const IRQ_LINES: fn(&irq::Controller) -> u32 = irq::Controller::lines;
const IRQ_MAX_CPUS: fn(&irq::Controller) -> usize = irq::Controller::max_cpus;
const IRQ_INIT_LOCAL: fn(&irq::Controller) -> Result<irq::Local, irq::Error> =
    irq::Controller::init_local;
const IRQ_ENABLE_PRIVATE: fn(&irq::Controller, Option<&irq::Local>, u32) =
    irq::Controller::enable_private;
const IRQ_ENABLE_SPI: fn(&irq::Controller, u32, u64, Option<&irq::Local>) =
    irq::Controller::enable_spi;
const IRQ_SEND_IPI: fn(&irq::Controller, u32, u64, Option<&irq::Local>) = irq::Controller::send_ipi;
const IRQ_ACK: fn(&irq::Controller) -> irq::Ack = irq::Controller::ack;
const IRQ_EOI: fn(&irq::Controller, irq::Ack) = irq::Controller::eoi;
const IRQ_ACK_NONE: fn(&irq::Ack) -> bool = irq::Ack::is_none;
const IRQ_ACK_SPURIOUS: fn(&irq::Ack) -> bool = irq::Ack::is_spurious;

// ipi
const IPI_VECTORS: [u32; 3] = [ipi::PING, ipi::PONG, ipi::WAKE];

// msi
const MSI_FROM_TYPER: fn(u64, u32) -> msi::Frame = msi::Frame::from_typer;
const MSI_ALLOC: fn(&mut msi::Frame) -> Option<u32> = msi::Frame::alloc;
const MSI_COMPOSE: fn(&msi::Frame, u32) -> (u64, u32) = msi::Frame::compose;

// percpu
const PERCPU_CURRENT: fn() -> usize = percpu::current;
const PERCPU_SET_CURRENT: unsafe fn(usize) = percpu::set_current;
const PERCPU_HW_ID: fn() -> u64 = percpu::hw_id;
const PERCPU_AP_CAPTURE: fn(
    &mut percpu::ApBoot,
    usize,
    u64,
    u64,
    percpu::ApEntry,
    Option<(u64, u64)>,
) = percpu::ApBoot::capture;

// time
const TIME_UPTIME_NS: fn() -> u64 = time::uptime_ns;
const TIME_NOW: fn() -> u64 = time::now;
const TIME_FREQUENCY: fn() -> u64 = time::frequency;
const TIME_TICKS_TO_NS: fn(u64) -> u64 = time::ticks_to_ns;
const TIME_NS_TO_TICKS: fn(u64) -> u64 = time::ns_to_ticks;
const TIME_SET_DEADLINE: fn(u64) = time::set_deadline;
const TIME_DEADLINE: fn() -> u64 = time::deadline;
const TIME_FINEST_CLOCK: fn() -> (fn() -> u64, &'static str) = time::finest_clock;

// paging
const PAGING_PAGE_SIZE: u64 = paging::PAGE_SIZE;
const PAGING_ACTIVATE: unsafe fn(u64) = paging::activate;
const PAGING_KERNEL_ROOT: fn() -> u64 = paging::kernel_root;
const PAGING_MERGE_ATTRS: fn() = paging::merge_memory_attributes;
const PAGING_PUBLISH: fn() = paging::publish;
const PAGING_FLUSH_ALL: fn() = paging::tlb_flush_all;
const PAGING_FLUSH_VA: fn(u64) = paging::tlb_flush_va;
const PAGING_INDEX: fn(u64, u8) -> usize = paging::index;

// trap
const TRAP_INSTALL: fn() = trap::install;
const TRAP_SET_HANDLER: fn(fn(&mut trap::TrapFrame, trap::Vector)) = trap::set_handler;
const TRAP_CLASSIFY: fn(&trap::TrapFrame, trap::Vector) -> trap::Event = trap::TrapFrame::classify;
const TRAP_PC: fn(&trap::TrapFrame) -> u64 = trap::TrapFrame::pc;
const TRAP_SKIP: fn(&mut trap::TrapFrame) = trap::TrapFrame::skip_breakpoint;
const TRAP_FAULT_ADDRESS: fn(&trap::TrapFrame, trap::Vector) -> Option<u64> =
    trap::TrapFrame::fault_address;
const TRAP_NAME: fn(trap::Vector) -> &'static str = trap::Vector::name;
const TRAP_BREAKPOINT: fn() = trap::breakpoint;
const TRAP_UNDEFINED: fn() = trap::undefined_instruction;
const TRAP_FORGED_RETURN: fn() -> bool = trap::forged_return;
const TRAP_BAD_BRANCH: fn() -> bool = trap::branch_to_non_landing_pad;
const TRAP_RET_INSN: u32 = trap::RET_INSN;

// entropy
const ENTROPY_HW_RANDOM: fn() -> Option<[u8; 64]> = entropy::hw_random;

// power
const POWER_OFF: fn() -> ! = power::off;
const POWER_RESET: fn() -> ! = power::reset;
const POWER_FIRMWARE_VERSION: fn() -> Option<(u16, u16)> = power::firmware_version;
const POWER_SET_CONDUIT: fn(power::Conduit) = power::set_conduit;
const POWER_CONDUIT_NAME: fn() -> &'static str = power::conduit_name;

// features
const FEATURES_DETECT: fn() -> features::Features = features::detect;
const FEATURES_DISPATCH: fn(&features::Features) -> urmqtt_dispatch::CpuFeatures =
    features::Features::dispatch;
