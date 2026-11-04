//! virtio-vsock (ADR-258, `devices.virtio_vsock`): the Diagnostic report,
//! read-only, to a host that connects to vsock port
//! [`urmqtt_virtio::vsock::DIAG_PORT`] (2883). The document is the JSON of
//! `$SYS/diag/report` once a Diagnostic run made one (`diag-serve`, or the
//! Diagnostic entry while it waits for a key); before that, a one-line JSON
//! that says there is none.
//!
//! Served from the boot CPU's tick (every 10 ms, interrupt context): one
//! bounded pass of the stack, the device lock only tried.
//!
//! **Untested against a real device** (vhost-vsock on a Linux host): the
//! driver's tests use a fake device.

/// The document before a Diagnostic run made a report.
#[cfg_attr(not(feature = "virtio-vsock"), allow(dead_code))]
pub const NO_REPORT: &str = "{\"urmqtt_diag\":null,\"error\":\"no diagnostic report in this boot: boot the Diagnostic \
entry or the diag-serve word\"}\n";

#[cfg(feature = "virtio-vsock")]
mod imp {
    use alloc::string::String;

    use urmqtt_arch::time;
    use urmqtt_log::info;
    use urmqtt_pci::Bdf;
    use urmqtt_sync::sync::SpinLock;
    use urmqtt_virtio::vsock::{DIAG_PORT, VirtioVsock};
    use urmqtt_virtio::{Transport, VirtioCaps};

    use crate::devices::{Cfg, KernelEnv, transport};

    static DEV: SpinLock<Option<VirtioVsock<Transport>>> = SpinLock::new(None);

    pub fn init(
        cfg: &mut Cfg,
        env: &KernelEnv,
        bdf: Bdf,
        caps: &VirtioCaps,
    ) -> Result<String, String> {
        let t = transport(cfg, bdf, caps, false)
            .map_err(|e| alloc::format!("mapping failed ({e:?})"))?;
        let v = VirtioVsock::new(t, env, DIAG_PORT).map_err(|e| alloc::format!("{e:?}"))?;
        let detail = alloc::format!(
            "guest CID {}, the Diagnostic report (read-only) on port {DIAG_PORT}",
            v.stack.guest_cid
        );
        *DEV.lock() = Some(v);
        Ok(detail)
    }

    pub fn tick() {
        let Some(mut g) = DEV.try_lock() else { return };
        let Some(v) = g.as_mut() else { return };
        let doc = crate::diag::served_report().unwrap_or(super::NO_REPORT);
        v.poll(doc.as_bytes(), time::uptime_ns());
    }

    pub fn report() {
        let Some((s, resets, errors)) = DEV
            .lock()
            .as_ref()
            .map(|v| (v.stack.stats, v.transport_resets, v.protocol_errors))
        else {
            return;
        };
        info!(
            "virtio-vsock: {} connection(s) accepted, {} served, {} refused, {} timed out, {resets} transport reset(s), \
             {errors} protocol error(s)",
            s.accepted, s.served, s.refused, s.timeouts
        );
    }
}

#[cfg(feature = "virtio-vsock")]
pub const INIT: Option<super::Init> = Some(imp::init);
#[cfg(not(feature = "virtio-vsock"))]
pub const INIT: Option<super::Init> = None;

pub fn tick() {
    #[cfg(feature = "virtio-vsock")]
    imp::tick();
}

pub fn report() {
    #[cfg(feature = "virtio-vsock")]
    imp::report();
}
