//! virtio-rng (entropy device, virtio 1.x §5.4).

use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::transport::Transport;
use crate::{Env, F_VERSION_1, VirtioError, wait_used};

const QUEUE_SIZE: u16 = 8;
const BUF: usize = 64;
const TIMEOUT_NS: u64 = 1_000_000_000;

pub struct VirtioRng {
    t: Transport,
    q: SplitQueue,
    notify_off: usize,
    buf: DmaRegion,
}

impl VirtioRng {
    pub fn new<E: Env>(t: Transport, env: &E) -> Result<Self, VirtioError> {
        t.init(env, 0, F_VERSION_1)?;
        let size = QUEUE_SIZE.min(t.queue_max(0));
        let mem = env
            .dma_alloc(crate::queue::Layout::new(size).total)
            .ok_or(VirtioError::NoDma)?;
        // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
        #[allow(unsafe_code)]
        let q = unsafe { SplitQueue::new(mem, size) }?;
        let notify_off = t.setup_queue(0, &q, None)?;
        let buf = env.dma_alloc(BUF).ok_or(VirtioError::NoDma)?;
        t.driver_ok()?;
        Ok(Self {
            t,
            q,
            notify_off,
            buf,
        })
    }

    /// Fills `out` with device entropy. Returns the bytes produced.
    pub fn fill<E: Env>(&mut self, env: &E, out: &mut [u8]) -> Result<usize, VirtioError> {
        let mut done = 0usize;
        while done < out.len() {
            let want = (out.len() - done).min(BUF);
            self.q.add(&[Buf {
                pa: self.buf.pa,
                len: want as u32,
                device_writes: true,
            }])?;
            self.t.notify(self.notify_off, 0);
            let (_, len) = wait_used(env, &mut self.q, TIMEOUT_NS, "rng")?;
            let got = (len as usize).min(want);
            #[allow(unsafe_code)]
            // SAFETY: the device wrote `got <= BUF` bytes into our DMA buffer.
            let src = unsafe { core::slice::from_raw_parts(self.buf.va as *const u8, got) };
            if let Some(dst) = out.get_mut(done..done + got) {
                dst.copy_from_slice(src);
            }
            if got == 0 {
                return Err(VirtioError::Io(0));
            }
            done += got;
        }
        Ok(done)
    }
}
