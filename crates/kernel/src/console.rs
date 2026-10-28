//! Wires the log sinks to the discovered UART and the Limine framebuffer.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use limine::framebuffer::Framebuffer;
use urmqtt_log::fbcon::{FbConsole, PixelFormat};
use urmqtt_log::pl011::Pl011;
use urmqtt_log::{info, warn};

/// Framebuffer geometry for the boot log: width << 32 | height.
static FB_GEOMETRY: AtomicU64 = AtomicU64::new(0);

pub fn init_uart(va: u64) {
    // SAFETY: `va` was just mapped as device memory covering the PL011
    // register block and stays mapped for the kernel's lifetime.
    let uart = unsafe { Pl011::new(va as usize) };
    urmqtt_log::set_uart(uart, va as usize);
}

pub fn init_framebuffer(fb: &Framebuffer) {
    if fb.bpp != 32 || fb.memory_model != limine::framebuffer::FRAMEBUFFER_RGB {
        return;
    }
    let (w, h, pitch) = (fb.width as usize, fb.height as usize, fb.pitch as usize);
    // SAFETY: Limine maps the framebuffer (pitch * height bytes) into the
    // HHDM for the kernel's lifetime, and nothing else aliases it.
    let buf: &'static mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(fb.address().cast::<u8>(), fb.size()) };
    let format = PixelFormat {
        red_shift: fb.red_mask_shift,
        green_shift: fb.green_mask_shift,
        blue_shift: fb.blue_mask_shift,
    };
    if let Some(con) = FbConsole::new(buf, w, h, pitch, format) {
        urmqtt_log::set_framebuffer(con);
        // Relaxed: informational only.
        FB_GEOMETRY.store(((w as u64) << 32) | h as u64, Ordering::Relaxed);
    }
}

pub fn log_framebuffer() {
    // Relaxed: informational only.
    match FB_GEOMETRY.load(Ordering::Relaxed) {
        0 => warn!("framebuffer: none (text log on serial only)"),
        g => info!("framebuffer: {}x{} text console", g >> 32, g & 0xffff_ffff),
    }
}
