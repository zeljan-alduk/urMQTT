//! The host of the unprivileged database worker (ADR-210, ADR-211): its
//! address space, its image, the calls into it, the system calls it makes
//! and what happens when it faults.
//!
//! One worker exists, owned by whichever core owns the store (the boot CPU
//! while it opens the store, then the DB core); calls are serialised by a
//! lock. The kernel never dereferences an address the worker supplies: all
//! data crosses in the shared window, which the kernel reaches through its
//! own alias of the same frames.

#![allow(unsafe_code)]
// Used by the dev self-test only until the store is moved in (ADR-210, step 2).
#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use urmqtt_arch::paging::{self, FrameSource, UserAccess};
use urmqtt_arch::time;
use urmqtt_arch::user::{self, Exit, UserEvent};
use urmqtt_log::{error, info, warn};
use urmqtt_sync::sync::SpinLock;
use urmqtt_usys::abi::{hdr, sys};
use urmqtt_usys::layout::{
    HEAP_BASE, IMAGE_BASE, IMAGE_LIMIT, SHM_BASE, SHM_HEADER, SHM_IO, SHM_LEN, STACK_BASE,
    STACK_LEN, STACK_TOP,
};

use crate::memory::HhdmTables;
use crate::vm;

/// The worker's image, built by this crate's `build.rs`.
static IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dbworker.elf"));

const PAGE: usize = 4096;
/// Wall-clock budget of one call into the worker (ADR-210).
static BUDGET_NS: AtomicU64 = AtomicU64::new(30_000_000_000);
/// More restarts than this within [`STORM_WINDOW_NS`] mean the worker is
/// broken, not unlucky: it is not started again.
static STORM_LIMIT: AtomicUsize = AtomicUsize::new(5);
const STORM_WINDOW_NS: u64 = 60_000_000_000;

/// Worker restarts since boot (for `$SYS` and statsd).
pub static RESTARTS: AtomicU64 = AtomicU64::new(0);
/// Calls since boot.
pub static CALLS: AtomicU64 = AtomicU64::new(0);
/// Worker calls ended by a fault or a timeout.
pub static FAULTS: AtomicU64 = AtomicU64::new(0);
/// VFS system calls served for the worker since boot.
pub static SYSCALLS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds spent inside calls (entry to return, system calls included).
pub static WORKER_NS: AtomicU64 = AtomicU64::new(0);

/// Length of the SQLite heap of the worker, for the store's transport.
static HEAP_LEN: AtomicUsize = AtomicUsize::new(0);

/// Kernel alias of the shared window, for the exception handler (it must not
/// take the lock the caller holds). 0: no worker.
static SHM_KVA: AtomicU64 = AtomicU64::new(0);
/// When the call in progress must be over, in uptime nanoseconds.
static DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);
static TIMED_OUT: AtomicBool = AtomicBool::new(false);

/// Why a call did not return a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// The worker faulted; it was restarted.
    Fault,
    /// The worker exceeded its budget; it was restarted.
    Timeout,
    /// The worker ended the call with an error code of its own (a panic, a
    /// failed stack check, an unknown operation); it was restarted.
    Exit(u64),
    /// Too many restarts in a row: the worker is not run any more.
    Failed,
    /// No worker was created.
    Absent,
}

/// The answer of a call: the two result words and the length of the data in
/// the I/O area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub ret: u64,
    pub ret2: u64,
    pub len: usize,
}

/// A piece of RAM the worker's pages are backed by, reached through the
/// kernel's own alias (the direct map). Every access is bounds-checked.
#[derive(Clone, Copy)]
struct Ram {
    kva: usize,
    len: usize,
}

impl Ram {
    const NONE: Self = Self { kva: 0, len: 0 };

    fn zero(self) {
        // SAFETY: `kva` covers `len` bytes of RAM the worker owns.
        unsafe { core::ptr::write_bytes(self.kva as *mut u8, 0, self.len) };
    }

    fn write(self, off: usize, data: &[u8]) -> bool {
        if off.checked_add(data.len()).is_none_or(|e| e > self.len) {
            return false;
        }
        // SAFETY: inside the region (checked); a distinct source slice.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), (self.kva + off) as *mut u8, data.len());
        }
        true
    }

    fn read(self, off: usize, out: &mut [u8]) -> bool {
        if off.checked_add(out.len()).is_none_or(|e| e > self.len) {
            return false;
        }
        // SAFETY: inside the region (checked); a distinct destination slice.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.kva + off) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
        true
    }

    fn put(self, off: usize, v: u64) {
        let _ = self.write(off, &v.to_le_bytes());
    }

    fn get(self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        let _ = self.read(off, &mut b);
        u64::from_le_bytes(b)
    }
}

/// A loadable piece of the image: where it goes, what to copy, how big.
struct Segment {
    file: (usize, usize),
    ram: Ram,
}

struct Worker {
    root: u64,
    entry: u64,
    segments: Vec<Segment>,
    stack: Ram,
    heap: Ram,
    shm: Ram,
    restarts: Vec<u64>,
    failed: bool,
    /// The stack protector's guard for this life of the worker.
    seed: u64,
}

/// `(vaddr, file offset, file size, memory size, flags)` of a `PT_LOAD`.
type Load = (u64, usize, usize, usize, u32);

static WORKER: SpinLock<Option<Worker>> = SpinLock::new(None);

struct Frames;

impl FrameSource for Frames {
    fn alloc_frame(&mut self) -> Option<u64> {
        vm::FRAMES.lock().as_mut().and_then(|f| f.alloc())
    }
}

#[derive(Debug)]
#[allow(dead_code)] // read through `Debug` in the boot message
pub enum CreateError {
    BadImage(&'static str),
    OutOfMemory,
    Map(paging::MapError),
}

fn le16(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u16::from_le_bytes(
        b.get(at..at + 2)?.try_into().ok()?,
    )))
}

fn le32(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from(u32::from_le_bytes(
        b.get(at..at + 4)?.try_into().ok()?,
    )))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Reads the program headers of a statically linked ELF64 image: the entry
/// point and every `PT_LOAD` segment as `(vaddr, file offset, file size,
/// memory size, flags)`. Rejects anything outside the worker's window and
/// any segment that is both writable and executable.
fn parse(image: &[u8]) -> Result<(u64, Vec<Load>), CreateError> {
    let bad = CreateError::BadImage;
    if image.get(..4) != Some(b"\x7fELF") || image.get(4) != Some(&2) {
        return Err(bad("not an ELF64 file"));
    }
    let entry = le64(image, 24).ok_or(bad("short header"))?;
    let phoff = le64(image, 32).ok_or(bad("short header"))? as usize;
    let phentsize = le16(image, 54).ok_or(bad("short header"))? as usize;
    let phnum = le16(image, 56).ok_or(bad("short header"))? as usize;
    let mut out = Vec::new();
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        if le32(image, at) != Some(1) {
            continue; // not PT_LOAD
        }
        let flags = le32(image, at + 4).ok_or(bad("short program header"))? as u32;
        let off = le64(image, at + 8).ok_or(bad("short program header"))? as usize;
        let vaddr = le64(image, at + 16).ok_or(bad("short program header"))?;
        let filesz = le64(image, at + 32).ok_or(bad("short program header"))? as usize;
        let memsz = le64(image, at + 40).ok_or(bad("short program header"))? as usize;
        if !vaddr.is_multiple_of(PAGE as u64)
            || vaddr < IMAGE_BASE
            || vaddr.saturating_add(memsz as u64) > IMAGE_LIMIT
            || filesz > memsz
            || off.checked_add(filesz).is_none_or(|e| e > image.len())
        {
            return Err(bad("segment outside the worker window"));
        }
        if flags & 1 != 0 && flags & 2 != 0 {
            return Err(bad("segment is both writable and executable"));
        }
        out.push((vaddr, off, filesz, memsz, flags));
    }
    if out.is_empty() || !(IMAGE_BASE..IMAGE_LIMIT).contains(&entry) {
        return Err(bad("no segments or entry outside the window"));
    }
    Ok((entry, out))
}

/// Allocates zeroed, contiguous RAM; returns the kernel alias and the
/// physical address.
fn alloc(bytes: usize) -> Result<(usize, u64), CreateError> {
    let (va, pa, _) = vm::dma_alloc(bytes).ok_or(CreateError::OutOfMemory)?;
    Ok((va, pa))
}

/// Builds the worker's address space and loads its image. `heap_bytes` is
/// the SQLite heap (`storage.sqlite_heap_mb`).
pub fn create(heap_bytes: usize) -> Result<(), CreateError> {
    let (entry, loads) = parse(IMAGE)?;
    let hhdm = vm::hhdm();
    let mut tables = HhdmTables { hhdm };
    let mut frames = Frames;
    let bti = urmqtt_arch::features::detect().bti;
    let root = paging::user_new_root(&mut tables, &mut frames, paging::kernel_root())
        .ok_or(CreateError::OutOfMemory)?;
    let map = |tables: &mut HhdmTables,
               frames: &mut Frames,
               va: u64,
               pa: u64,
               len: usize,
               access: UserAccess|
     -> Result<(), CreateError> {
        for p in 0..len.div_ceil(PAGE) {
            let off = (p * PAGE) as u64;
            paging::user_map_page(tables, root, va + off, pa + off, access, bti, frames)
                .map_err(CreateError::Map)?;
        }
        Ok(())
    };

    let mut segments = Vec::new();
    for (vaddr, off, filesz, memsz, flags) in loads {
        let access = if flags & 1 != 0 {
            UserAccess::Code
        } else if flags & 2 != 0 {
            UserAccess::ReadWrite
        } else {
            UserAccess::ReadOnly
        };
        let (kva, pa) = alloc(memsz.max(PAGE))?;
        map(&mut tables, &mut frames, vaddr, pa, memsz, access)?;
        segments.push(Segment {
            file: (off, filesz),
            ram: Ram {
                kva,
                len: memsz.div_ceil(PAGE) * PAGE,
            },
        });
    }
    let (stack_kva, stack_pa) = alloc(STACK_LEN)?;
    map(
        &mut tables,
        &mut frames,
        STACK_BASE,
        stack_pa,
        STACK_LEN,
        UserAccess::ReadWrite,
    )?;
    let (shm_kva, shm_pa) = alloc(SHM_LEN)?;
    map(
        &mut tables,
        &mut frames,
        SHM_BASE,
        shm_pa,
        SHM_LEN,
        UserAccess::ReadWrite,
    )?;
    let heap_len = heap_bytes.div_ceil(PAGE) * PAGE;
    let (heap_kva, heap_pa) = if heap_len > 0 {
        alloc(heap_len)?
    } else {
        (0, 0)
    };
    let (stack, shm, heap) = (
        Ram {
            kva: stack_kva,
            len: STACK_LEN,
        },
        Ram {
            kva: shm_kva,
            len: SHM_LEN,
        },
        Ram {
            kva: heap_kva,
            len: heap_len,
        },
    );
    if heap_len > 0 {
        map(
            &mut tables,
            &mut frames,
            HEAP_BASE,
            heap_pa,
            heap_len,
            UserAccess::ReadWrite,
        )?;
    }
    paging::publish();
    let mut w = Worker {
        root,
        entry,
        segments,
        stack,
        heap,
        shm,
        restarts: Vec::new(),
        failed: false,
        seed: 0,
    };
    w.load();
    // Relaxed: read by the exception handler on the core that runs a call.
    SHM_KVA.store(shm_kva as u64, Ordering::Relaxed);
    HEAP_LEN.store(heap_len, Ordering::Relaxed);
    info!(
        "dbworker: address space built: {} KiB image, {} KiB stack, {} MiB heap, {} KiB shared window",
        w.segments.iter().map(|s| s.ram.len / 1024).sum::<usize>(),
        STACK_LEN >> 10,
        heap_len >> 20,
        SHM_LEN >> 10,
    );
    *WORKER.lock() = Some(w);
    Ok(())
}

impl Worker {
    /// Puts the worker in its initial state: image copied, everything else
    /// zeroed. Used at creation and after a fault.
    fn load(&mut self) {
        for s in &self.segments {
            s.ram.zero();
            let (off, len) = s.file;
            if let Some(bytes) = IMAGE.get(off..off + len) {
                let _ = s.ram.write(0, bytes);
            }
        }
        self.stack.zero();
        self.shm.zero();
        let mut seed = [0u8; 8];
        if urmqtt_tls::rng::fill_global(&mut seed).is_err() {
            seed = [1; 8];
        }
        self.seed = u64::from_le_bytes(seed);
        if self.heap.len > 0 {
            self.heap.zero();
        }
        user::sync_code();
    }
}

/// Whether a worker exists and has not been given up on.
#[allow(dead_code)]
pub fn available() -> bool {
    WORKER.lock().as_ref().is_some_and(|w| !w.failed)
}

/// Runs one operation in the worker. `input` is copied to the I/O area
/// first; on success `output` receives the result bytes the worker left
/// there (at most `output.len()`).
///
/// On any failure of the worker the worker is restarted (its state is
/// gone: the caller reopens what it had open) and the error says why.
pub fn call(op: u64, args: [u64; 6], input: &[u8], output: &mut [u8]) -> Result<Reply, CallError> {
    let mut guard = WORKER.lock();
    let w = guard.as_mut().ok_or(CallError::Absent)?;
    if w.failed {
        return Err(CallError::Failed);
    }
    if input.len() > SHM_IO {
        return Err(CallError::Exit(u64::MAX));
    }
    // Relaxed: counters.
    CALLS.fetch_add(1, Ordering::Relaxed);
    let shm = w.shm;
    shm.put(hdr::OP, op);
    for (i, a) in args.iter().enumerate() {
        shm.put(hdr::ARG + 8 * i, *a);
    }
    shm.put(hdr::RET, 0);
    shm.put(hdr::RET2, 0);
    shm.put(hdr::LEN, input.len() as u64);
    shm.put(hdr::SEED, w.seed);
    let _ = shm.write(SHM_HEADER, input);
    TIMED_OUT.store(false, Ordering::Relaxed);
    DEADLINE.store(
        time::uptime_ns().saturating_add(BUDGET_NS.load(Ordering::Relaxed)),
        Ordering::Relaxed,
    );
    let t0 = time::uptime_ns();
    // SAFETY: tables built by `create`, entry and stack inside them; calls
    // are serialised by the lock and the kernel tables do not change.
    let exit = unsafe { user::enter(w.root, w.entry, STACK_TOP) };
    WORKER_NS.fetch_add(time::uptime_ns().saturating_sub(t0), Ordering::Relaxed);
    DEADLINE.store(u64::MAX, Ordering::Relaxed);
    let failure = match exit {
        Exit::Done(0) => None,
        Exit::Done(code) => {
            warn!("dbworker: call {op} ended with error code {code:#x}");
            Some(CallError::Exit(code))
        }
        Exit::Fault(f) => {
            warn!("dbworker: call {op} faulted: {f}");
            Some(CallError::Fault)
        }
        Exit::Timeout => {
            warn!(
                "dbworker: call {op} exceeded its budget of {} ms",
                BUDGET_NS.load(Ordering::Relaxed) / 1_000_000
            );
            Some(CallError::Timeout)
        }
    };
    if let Some(e) = failure {
        FAULTS.fetch_add(1, Ordering::Relaxed);
        let now = time::uptime_ns();
        w.restarts
            .retain(|t| now.saturating_sub(*t) < STORM_WINDOW_NS);
        w.restarts.push(now);
        let n = RESTARTS.fetch_add(1, Ordering::Relaxed) + 1;
        if w.restarts.len() > STORM_LIMIT.load(Ordering::Relaxed) {
            w.failed = true;
            error!(
                "dbworker: {} restarts within {} s: giving up on the database worker",
                w.restarts.len(),
                STORM_WINDOW_NS / 1_000_000_000
            );
            return Err(CallError::Failed);
        }
        w.load();
        warn!("dbworker: restarted (restart #{n})");
        return Err(e);
    }
    // The worker finished; the window is ours again. Every word is untrusted:
    // lengths are clamped.
    let (ret, ret2, len) = (shm.get(hdr::RET), shm.get(hdr::RET2), shm.get(hdr::LEN));
    let len = usize::try_from(len).unwrap_or(usize::MAX).min(SHM_IO);
    let n = len.min(output.len());
    let _ = shm.read(SHM_HEADER, output.get_mut(..n).unwrap_or(&mut []));
    Ok(Reply { ret, ret2, len })
}

/// How the store reaches the worker (ADR-211).
pub fn transport() -> urmqtt_store::remote::Transport {
    use urmqtt_store::remote::{Failure, Reply as StoreReply, Transport};

    fn via(
        op: u64,
        args: [u64; 6],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<StoreReply, Failure> {
        match call(op, args, input, output) {
            Ok(r) => Ok(StoreReply {
                ret: r.ret,
                ret2: r.ret2,
                len: r.len,
            }),
            Err(CallError::Absent) => Err(Failure::Absent),
            Err(_) => Err(Failure::Died),
        }
    }

    fn epoch() -> u64 {
        // Relaxed: a counter.
        RESTARTS.load(Ordering::Relaxed)
    }

    Transport {
        call: via,
        epoch,
        heap: (HEAP_BASE, HEAP_LEN.load(Ordering::Relaxed)),
    }
}

/// An exception taken from the worker: serves system calls and interrupts,
/// ends the call on anything else. Called from the exception handler.
pub fn on_exception(frame: &mut urmqtt_arch::trap::TrapFrame, vector: urmqtt_arch::trap::Vector) {
    match user::decode(frame, vector) {
        UserEvent::Syscall { nr, args } => match nr {
            sys::EXIT => {
                // SAFETY: an exception taken from the worker.
                unsafe { user::leave(Exit::Done(args[0])) }
            }
            sys::LOG => {
                let n = (args[0] as usize).min(200);
                let shm = Ram {
                    kva: SHM_KVA.load(Ordering::Relaxed) as usize,
                    len: SHM_LEN,
                };
                let mut line = [0u8; 200];
                if shm.kva != 0 && shm.read(SHM_HEADER, line.get_mut(..n).unwrap_or(&mut [])) {
                    // The text is the worker's: shown as printable ASCII only.
                    for b in line.iter_mut() {
                        if !(b.is_ascii_graphic() || *b == b' ') {
                            *b = b'?';
                        }
                    }
                    info!(
                        "{}",
                        core::str::from_utf8(line.get(..n).unwrap_or(&[])).unwrap_or("?")
                    );
                }
                user::set_return(frame, 0);
            }
            n if n >= urmqtt_usys::proto::vfs::OPEN => {
                let kva = SHM_KVA.load(Ordering::Relaxed) as usize;
                SYSCALLS.fetch_add(1, Ordering::Relaxed);
                let r = if kva == 0 {
                    u64::MAX
                } else {
                    // SAFETY: the I/O area of the shared window, which the
                    // worker is not using while it waits for this call; the
                    // window exists once the first call is made.
                    let io = unsafe {
                        core::slice::from_raw_parts_mut((kva + SHM_HEADER) as *mut u8, SHM_IO)
                    };
                    urmqtt_store::vfs::syscall(n, args, io).unwrap_or(u64::MAX)
                };
                user::set_return(frame, r);
            }
            _ => user::set_return(frame, u64::MAX),
        },
        UserEvent::Irq => {
            crate::irq::dispatch();
            if time::uptime_ns() > DEADLINE.load(Ordering::Relaxed) {
                TIMED_OUT.store(true, Ordering::Relaxed);
                // SAFETY: an exception taken from the worker.
                unsafe { user::leave(Exit::Timeout) }
            }
        }
        UserEvent::Fault(f) => {
            // SAFETY: an exception taken from the worker.
            unsafe { user::leave(Exit::Fault(f)) }
        }
    }
}

/// `test=worker-contain` (dev images): the fault-containment scenario.
///
/// Every way the worker can misbehave must end in a failed call and a
/// restart, never in a kernel fault: reads, writes and jumps into kernel
/// memory, a privileged instruction, writes to its own code, a jump into its
/// data, a null read, and an endless loop. After each, a hello call proves
/// the restarted worker works, and the kernel word the worker tried to
/// overwrite is checked.
#[cfg(feature = "selftest")]
pub fn contain_selftest() {
    use urmqtt_usys::abi::{MAGIC, op};

    // A short budget for the endless loop.
    BUDGET_NS.store(300_000_000, Ordering::Relaxed);
    STORM_LIMIT.store(100, Ordering::Relaxed);
    if let Err(e) = create(1 << 20) {
        crate::boot::fatal_fmt(format_args!(
            "worker-contain: cannot create the worker: {e:?}"
        ));
    }
    let hello = |tag: &str| -> bool {
        let ok = matches!(
            call(op::HELLO, [0x1234, 0, 0, 0, 0, 0], &[], &mut []),
            Ok(r) if r.ret == 0x1234 ^ MAGIC
        );
        info!(
            "worker-contain: hello {tag}: {}",
            if ok { "ok" } else { "FAILED" }
        );
        ok
    };
    let mut good = hello("before");
    // What entering and leaving user mode costs: a call that does nothing.
    {
        const N: u64 = 20_000;
        let t0 = time::uptime_ns();
        for _ in 0..N {
            let _ = call(op::NOP, [1, 0, 0, 0, 0, 0], &[], &mut []);
        }
        let ns = time::uptime_ns() - t0;
        info!(
            "worker-contain: {N} empty calls, {} ns per round trip (enter user mode, exit)",
            ns / N
        );
    }
    info!(
        "worker-contain: kernel/user separation: {}",
        user::protections()
    );
    // A word of kernel data the worker will try to overwrite, and kernel text.
    static CANARY: AtomicU64 = AtomicU64::new(0x600d_c0de_600d_c0de);
    let data = core::ptr::addr_of!(CANARY) as u64;
    let handler: fn(&mut urmqtt_arch::trap::TrapFrame, urmqtt_arch::trap::Vector) = on_exception;
    let text = handler as usize as u64;
    let cases: [(&str, u64, u64, CallError); 8] = [
        (
            "read-kernel-data",
            op::FAULT_READ_KERNEL,
            data,
            CallError::Fault,
        ),
        (
            "write-kernel-data",
            op::FAULT_WRITE_KERNEL,
            data,
            CallError::Fault,
        ),
        (
            "exec-kernel-text",
            op::FAULT_EXEC_KERNEL,
            text,
            CallError::Fault,
        ),
        (
            "privileged-instruction",
            op::FAULT_PRIVILEGED,
            0,
            CallError::Fault,
        ),
        ("write-own-code", op::FAULT_WRITE_TEXT, 0, CallError::Fault),
        ("exec-own-data", op::FAULT_EXEC_DATA, 0, CallError::Fault),
        ("null-read", op::FAULT_NULL, 0, CallError::Fault),
        ("endless-loop", op::SPIN, 0, CallError::Timeout),
    ];
    let mut contained = 0;
    for (name, o, a0, want) in cases {
        let got = call(o, [a0, 0, 0, 0, 0, 0], &[], &mut []);
        if got == Err(want) {
            contained += 1;
            info!("worker-contain: {name}: contained ({want:?}), worker restarted");
        } else {
            error!("worker-contain: {name}: NOT contained, call returned {got:?}");
        }
        good &= hello("after restart");
    }
    let intact = CANARY.load(Ordering::Relaxed) == 0x600d_c0de_600d_c0de;
    info!(
        "worker-contain: kernel data {}",
        if intact { "intact" } else { "OVERWRITTEN" }
    );
    info!(
        "worker-contain: {contained}/{} contained, {} restart(s), kernel still running{}",
        cases.len(),
        RESTARTS.load(Ordering::Relaxed),
        if good && intact {
            ""
        } else {
            " (WITH FAILURES)"
        }
    );
    BUDGET_NS.store(30_000_000_000, Ordering::Relaxed);
    STORM_LIMIT.store(5, Ordering::Relaxed);
    *WORKER.lock() = None;
}
