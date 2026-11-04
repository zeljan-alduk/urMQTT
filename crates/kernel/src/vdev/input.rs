//! virtio-input (ADR-258, `devices.virtio_input`): keyboards for the
//! Diagnostic entry's prompts, the same path as PS/2 and the serial port.
//! A provider's VNC console may have a virtio keyboard and a virtio tablet;
//! up to [`MAX_DEVICES`] are driven, pointer events only counted.

pub const MAX_DEVICES: usize = 4;

#[cfg(feature = "virtio-input")]
mod imp {
    use alloc::string::String;

    use urmqtt_log::info;
    use urmqtt_pci::Bdf;
    use urmqtt_sync::sync::SpinLock;
    use urmqtt_virtio::input::VirtioInput;
    use urmqtt_virtio::{Transport, VirtioCaps};

    use super::MAX_DEVICES;
    use crate::devices::{Cfg, KernelEnv, transport};

    static DEVS: SpinLock<[Option<VirtioInput<Transport>>; MAX_DEVICES]> =
        SpinLock::new([const { None }; MAX_DEVICES]);

    pub fn init(
        cfg: &mut Cfg,
        env: &KernelEnv,
        bdf: Bdf,
        caps: &VirtioCaps,
    ) -> Result<String, String> {
        let t = transport(cfg, bdf, caps, false)
            .map_err(|e| alloc::format!("mapping failed ({e:?})"))?;
        let d = VirtioInput::new(t, env).map_err(|e| alloc::format!("{e:?}"))?;
        let detail = alloc::format!("\"{}\", {}", d.name(), d.class.name());
        let mut devs = DEVS.lock();
        let slot = devs
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or_else(|| String::from("too many input devices"))?;
        *slot = Some(d);
        Ok(detail)
    }

    pub fn read_byte() -> Option<u8> {
        let mut devs = DEVS.try_lock()?;
        for d in devs.iter_mut().flatten() {
            d.poll();
            if let Some(b) = d.read_byte() {
                return Some(b);
            }
        }
        None
    }

    pub fn report() {
        let devs = DEVS.lock();
        let lines: alloc::vec::Vec<String> = devs
            .iter()
            .flatten()
            .map(|d| {
                alloc::format!(
                    "virtio-input \"{}\": {} key(s), {} pointer event(s), {} other, {} protocol error(s)",
                    d.name(),
                    d.keys,
                    d.pointer_events,
                    d.other_events,
                    d.protocol_errors
                )
            })
            .collect();
        drop(devs);
        for l in lines {
            info!("{l}");
        }
    }
}

#[cfg(feature = "virtio-input")]
pub const INIT: Option<super::Init> = Some(imp::init);
#[cfg(not(feature = "virtio-input"))]
pub const INIT: Option<super::Init> = None;

pub fn read_byte() -> Option<u8> {
    #[cfg(feature = "virtio-input")]
    return imp::read_byte();
    #[cfg(not(feature = "virtio-input"))]
    None
}

pub fn report() {
    #[cfg(feature = "virtio-input")]
    imp::report();
}
