//! virtio-console port 0 (ADR-258, `devices.virtio_console`): a log sink
//! beside the UART and the framebuffer, and a byte source for the
//! Diagnostic entry's prompts.
//!
//! The log calls the sink with its own lock held and IRQs masked, so the
//! sink only tries the device lock: a line that meets the lock held on
//! another core (a prompt polling for keys) is not written there and is
//! counted. It never waits for the host.

#[cfg(feature = "virtio-console")]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering};

    use alloc::string::String;

    use urmqtt_log::info;
    use urmqtt_pci::Bdf;
    use urmqtt_sync::sync::SpinLock;
    use urmqtt_virtio::console::VirtioConsole;
    use urmqtt_virtio::{Transport, VirtioCaps};

    use crate::devices::{Cfg, KernelEnv, transport};

    static DEV: SpinLock<Option<VirtioConsole<Transport>>> = SpinLock::new(None);
    /// Writes that found the device lock held.
    static MISSED: AtomicU64 = AtomicU64::new(0);

    pub fn init(
        cfg: &mut Cfg,
        env: &KernelEnv,
        bdf: Bdf,
        caps: &VirtioCaps,
    ) -> Result<String, String> {
        let t = transport(cfg, bdf, caps, false)
            .map_err(|e| alloc::format!("mapping failed ({e:?})"))?;
        let mut c = VirtioConsole::new(t, env).map_err(|e| alloc::format!("{e:?}"))?;
        c.write(b"urMQTT: the log continues on this virtio-console (port 0)\n");
        *DEV.lock() = Some(c);
        urmqtt_log::set_extra_sink(sink);
        Ok("port 0: the log goes here too; its input reaches the Diagnostic prompts".into())
    }

    fn sink(bytes: &[u8]) {
        match DEV.try_lock() {
            Some(mut g) => {
                if let Some(c) = g.as_mut() {
                    c.write(bytes);
                }
            }
            // Relaxed: a statistic.
            None => {
                MISSED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn read_byte() -> Option<u8> {
        let mut g = DEV.try_lock()?;
        let c = g.as_mut()?;
        c.poll();
        c.read_byte()
    }

    pub fn report() {
        let Some((tx, dropped, rx, errors)) = DEV
            .lock()
            .as_ref()
            .map(|c| (c.tx_bytes, c.tx_dropped, c.rx_bytes, c.protocol_errors))
        else {
            return;
        };
        // Relaxed: a statistic.
        let missed = MISSED.load(Ordering::Relaxed);
        info!(
            "virtio-console: {tx} byte(s) written, {dropped} dropped (host not reading), {missed} write(s) skipped \
             (device busy), {rx} received, {errors} protocol error(s)"
        );
    }
}

#[cfg(feature = "virtio-console")]
pub const INIT: Option<super::Init> = Some(imp::init);
#[cfg(not(feature = "virtio-console"))]
pub const INIT: Option<super::Init> = None;

pub fn read_byte() -> Option<u8> {
    #[cfg(feature = "virtio-console")]
    return imp::read_byte();
    #[cfg(not(feature = "virtio-console"))]
    None
}

pub fn report() {
    #[cfg(feature = "virtio-console")]
    imp::report();
}
