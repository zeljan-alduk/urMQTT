//! virtio-balloon (ADR-258, `devices.virtio_balloon`): memory statistics
//! for the host, and a balloon that never inflates.
//!
//! The boot CPU's tick (interrupt context) looks once a second whether the
//! device asked for fresh statistics and what it asks for: the heap's
//! numbers are only tried (its lock may be held by the code the tick
//! interrupted), and a changed request is logged after the device lock is
//! released.

#[cfg(feature = "virtio-balloon")]
mod imp {
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    use alloc::string::String;

    use urmqtt_arch::time;
    use urmqtt_log::{info, warn};
    use urmqtt_pci::Bdf;
    use urmqtt_sync::sync::SpinLock;
    use urmqtt_virtio::balloon::{MemStats, PAGE, VirtioBalloon};
    use urmqtt_virtio::{Transport, VirtioCaps};

    use crate::devices::{Cfg, KernelEnv, transport};

    static DEV: SpinLock<Option<VirtioBalloon<Transport>>> = SpinLock::new(None);
    static NEXT_NS: AtomicU64 = AtomicU64::new(0);
    /// The last request logged.
    static LOGGED: AtomicU32 = AtomicU32::new(0);
    const PERIOD_NS: u64 = 1_000_000_000;

    /// The numbers the host sees: usable RAM, and the heap's free bytes as
    /// both free and available (the heap is all the kernel allocates from
    /// after boot). `None` while the heap lock is busy.
    fn stats(blocking: bool) -> Option<MemStats> {
        let (free, _) = if blocking {
            crate::vm::HEAP.stats()?
        } else {
            crate::vm::HEAP.try_stats()?
        };
        let total = crate::diag::memory_usable();
        Some(MemStats {
            total,
            free: free as u64,
            available: free as u64,
        })
    }

    pub fn init(
        cfg: &mut Cfg,
        env: &KernelEnv,
        bdf: Bdf,
        caps: &VirtioCaps,
    ) -> Result<String, String> {
        let t = transport(cfg, bdf, caps, false)
            .map_err(|e| alloc::format!("mapping failed ({e:?})"))?;
        let now = stats(true).unwrap_or_default();
        let b = VirtioBalloon::new(t, env, &now).map_err(|e| alloc::format!("{e:?}"))?;
        let detail = alloc::format!(
            "{}; never inflates (fixed heap){}",
            if b.has_stats() {
                "memory statistics for the host"
            } else {
                "the device offers no statistics queue"
            },
            if b.requested > 0 {
                alloc::format!(
                    ", the host asks for {} MiB, not given",
                    (u64::from(b.requested) * PAGE) >> 20
                )
            } else {
                String::new()
            }
        );
        LOGGED.store(b.requested, Ordering::Relaxed);
        *DEV.lock() = Some(b);
        Ok(detail)
    }

    pub fn tick() {
        let now = time::uptime_ns();
        // Relaxed: only the boot CPU's tick reads and writes it.
        if now < NEXT_NS.load(Ordering::Relaxed) {
            return;
        }
        NEXT_NS.store(now + PERIOD_NS, Ordering::Relaxed);
        let Some(s) = stats(false) else { return };
        let changed = match DEV.try_lock() {
            Some(mut g) => g.as_mut().and_then(|b| b.poll(&s)),
            None => None,
        };
        if let Some(n) = changed
            && LOGGED.swap(n, Ordering::Relaxed) != n
        {
            warn!(
                "virtio-balloon: the host asks for {n} page(s) ({} MiB); this kernel never inflates (fixed heap, ADR-258)",
                (u64::from(n) * PAGE) >> 20
            );
        }
    }

    pub fn report() {
        let Some((sent, errors)) = DEV
            .lock()
            .as_ref()
            .map(|b| (b.stats_sent, b.protocol_errors))
        else {
            return;
        };
        info!("virtio-balloon: {sent} statistics answer(s), {errors} protocol error(s)");
    }
}

#[cfg(feature = "virtio-balloon")]
pub const INIT: Option<super::Init> = Some(imp::init);
#[cfg(not(feature = "virtio-balloon"))]
pub const INIT: Option<super::Init> = None;

pub fn tick() {
    #[cfg(feature = "virtio-balloon")]
    imp::tick();
}

pub fn report() {
    #[cfg(feature = "virtio-balloon")]
    imp::report();
}
