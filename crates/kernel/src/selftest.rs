//! Boot-time self-tests (always run) and deliberate faults (dev test mode).

#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use urmqtt_arch::paging::PAGE_SIZE;
use urmqtt_arch::trap;
use urmqtt_log::info;

use crate::{layout, vm};

/// Exercises the frame allocator and the heap; everything is returned.
pub fn memory() -> Result<(), &'static str> {
    const N: usize = 1000;
    let mut guard = vm::FRAMES.lock();
    let fa = guard.as_mut().ok_or("frame allocator missing")?;
    let before = fa.free_frames();
    let mut got = Vec::with_capacity(N);
    for _ in 0..N {
        let f = fa.alloc().ok_or("frame allocation failed")?;
        if f % PAGE_SIZE != 0 {
            return Err("misaligned frame");
        }
        got.push(f);
    }
    got.sort_unstable();
    if got.windows(2).any(|w| w[0] == w[1]) {
        return Err("frame handed out twice");
    }
    let run = fa
        .alloc_contiguous(16, 16)
        .ok_or("contiguous allocation failed")?;
    if run % (16 * PAGE_SIZE) != 0 {
        return Err("contiguous run misaligned");
    }
    fa.free_contiguous(run, 16)
        .map_err(|_| "contiguous free failed")?;
    for f in got.drain(..) {
        fa.free(f).map_err(|_| "frame free failed")?;
    }
    if fa.free_frames() != before || fa.free(run).is_ok() {
        return Err("frame accounting mismatch or double free accepted");
    }
    drop(guard);

    let (heap_before, cap) = vm::HEAP.stats().ok_or("heap missing")?;
    {
        let v: Vec<u64> = (0..10_000).collect();
        let b = Box::new([0u8; 4096]);
        if v.iter().sum::<u64>() != 49_995_000 || b.len() != 4096 {
            return Err("heap contents corrupted");
        }
    }
    let (heap_after, _) = vm::HEAP.stats().ok_or("heap missing")?;
    if heap_after != heap_before {
        return Err("heap did not coalesce after frees");
    }
    info!(
        "selftest: frames ok ({N} single + 16 contiguous allocated and freed, {} free), heap ok ({} KiB free of {} KiB)",
        before,
        heap_after >> 10,
        cap >> 10
    );
    Ok(())
}

/// Walks every leaf of the locked tables: no W+X, nothing executable
/// outside kernel text, and spot checks of the important aliases.
pub fn wx_audit() -> Result<(), &'static str> {
    let a = vm::audit().ok_or("no kernel address space")?;
    if a.writable_and_executable != 0 {
        return Err("W^X violated: writable and executable mapping found");
    }
    if a.executable_outside_text != 0 {
        return Err("executable mapping outside kernel text");
    }
    let text = write_text as *const () as u64;
    let [_, _, (sealed_start, _, _, _), (data_start, _, _, _)] = vm::kernel_sections();
    let checks: [(&str, u64, bool, bool); 5] = [
        ("text", text, false, true),
        ("sealed", sealed_start, false, false),
        ("data", data_start, true, false),
        ("heap", layout::HEAP_BASE, true, false),
        ("stack", layout::stacks(0).1.0, true, false),
    ];
    for (name, va, want_w, want_x) in checks {
        let leaf = vm::leaf_at(va).ok_or("expected mapping missing")?;
        if leaf.writable != want_w || leaf.executable != want_x {
            info!(
                "selftest: {name} at {va:#x}: writable={} executable={}",
                leaf.writable, leaf.executable
            );
            return Err("unexpected permissions");
        }
    }
    if vm::kernel_alias_writable() {
        return Err("HHDM alias of the kernel image is writable");
    }
    if vm::leaf_at(layout::PT_ALIAS_BASE).is_some() {
        return Err("page-table alias still mapped after lock");
    }
    if vm::leaf_at(layout::stacks(0).1.0 - PAGE_SIZE).is_some() {
        return Err("stack guard page is mapped");
    }
    info!(
        "selftest: W^X ok ({} leaf mappings audited, 0 W+X, text-only execute, guards unmapped, tables read-only)",
        a.leaves
    );
    Ok(())
}

/// Stores into kernel text: must fault with a permission fault.
pub fn write_text() {
    let p = write_text as *const () as *mut u32;
    // SAFETY: deliberately faulting store (test mode only).
    unsafe { p.write_volatile(0) };
}

/// Stores into the sealed CPU dispatch page: must fault with a permission
/// fault (X0b, ADR-041).
pub fn write_sealed() {
    let p = crate::cpu_dispatch::sealed_addr() as *mut u64;
    info!("test: writing the sealed cpu dispatch at {:#x}", p as u64);
    // SAFETY: deliberately faulting store (test mode only).
    unsafe { p.write_volatile(0) };
}

/// Branches into a heap buffer holding `ret`: must fault (PXN).
pub fn exec_heap() {
    let code: Box<[u32; 4]> = Box::new([trap::RET_INSN; 4]);
    // SAFETY: deliberately faulting branch (test mode only); the code is a
    // valid `ret` should the mapping ever be executable.
    let f: extern "C" fn() = unsafe { core::mem::transmute(code.as_ptr()) };
    f();
    core::hint::black_box(code);
}

/// Recurses until the main stack's guard page faults.
pub fn stack_overflow() {
    // Unbounded on purpose: the guard page ends it.
    #[allow(unconditional_recursion)]
    fn recurse(depth: u64) -> u64 {
        let buf = core::hint::black_box([depth as u8; 1024]);
        recurse(depth + 1) + u64::from(buf[0])
    }
    core::hint::black_box(recurse(0));
}

pub fn pac_violation() {
    if trap::forged_return() {
        urmqtt_log::error!("test: forged return address was NOT detected");
    }
}

pub fn bti_violation() {
    if trap::branch_to_non_landing_pad() {
        urmqtt_log::error!("test: branch to non-landing-pad was NOT detected");
    }
}
