//! Text console on a linear 32-bpp framebuffer, for providers whose web
//! console only shows video. Output only.

use font8x8::legacy::BASIC_LEGACY;

const GLYPH: usize = 8;

/// Pixel format of a 32-bpp framebuffer, from the bootloader's masks.
#[derive(Debug, Clone, Copy)]
pub struct PixelFormat {
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    fn pack(&self, r: u8, g: u8, b: u8) -> u32 {
        (u32::from(r) << self.red_shift)
            | (u32::from(g) << self.green_shift)
            | (u32::from(b) << self.blue_shift)
    }
}

/// A console drawing into `buf` (`pitch * height` bytes, 4 bytes per pixel).
pub struct FbConsole<'a> {
    buf: &'a mut [u8],
    width: usize,
    height: usize,
    pitch: usize,
    scale: usize,
    cols: usize,
    rows: usize,
    col: usize,
    row: usize,
    fg: u32,
    bg: u32,
}

impl<'a> FbConsole<'a> {
    /// Returns `None` if the geometry does not fit the buffer or holds no text.
    pub fn new(
        buf: &'a mut [u8],
        width: usize,
        height: usize,
        pitch: usize,
        format: PixelFormat,
    ) -> Option<Self> {
        if pitch < width.checked_mul(4)? || buf.len() < pitch.checked_mul(height)? {
            return None;
        }
        let scale = if width >= 1600 { 2 } else { 1 };
        let cell = GLYPH * scale;
        let (cols, rows) = (width / cell, height / cell);
        if cols == 0 || rows == 0 {
            return None;
        }
        let mut con = Self {
            buf,
            width,
            height,
            pitch,
            scale,
            cols,
            rows,
            col: 0,
            row: 0,
            fg: format.pack(0xd0, 0xd0, 0xd0),
            bg: format.pack(0x10, 0x10, 0x18),
        };
        con.clear();
        Some(con)
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    fn put_pixel(&mut self, x: usize, y: usize, color: u32) {
        let off = y * self.pitch + x * 4;
        if let Some(px) = self.buf.get_mut(off..off + 4) {
            px.copy_from_slice(&color.to_le_bytes());
        }
    }

    pub fn clear(&mut self) {
        let bg = self.bg.to_le_bytes();
        for y in 0..self.height {
            let start = y * self.pitch;
            if let Some(line) = self.buf.get_mut(start..start + self.width * 4) {
                for px in line.as_chunks_mut::<4>().0 {
                    *px = bg;
                }
            }
        }
        self.col = 0;
        self.row = 0;
    }

    fn draw_glyph(&mut self, c: u8) {
        let glyph = BASIC_LEGACY.get(usize::from(c)).copied().unwrap_or([0; 8]);
        let cell = GLYPH * self.scale;
        let (x0, y0) = (self.col * cell, self.row * cell);
        for (gy, bits) in glyph.iter().enumerate() {
            for gx in 0..GLYPH {
                let color = if bits & (1 << gx) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                for sy in 0..self.scale {
                    for sx in 0..self.scale {
                        self.put_pixel(x0 + gx * self.scale + sx, y0 + gy * self.scale + sy, color);
                    }
                }
            }
        }
    }

    fn scroll(&mut self) {
        let line_bytes = GLYPH * self.scale * self.pitch;
        let total = self.rows * line_bytes;
        if total <= self.buf.len() && line_bytes <= total {
            self.buf.copy_within(line_bytes..total, 0);
        }
        let bg = self.bg;
        let y_start = (self.rows - 1) * GLYPH * self.scale;
        for y in y_start..y_start + GLYPH * self.scale {
            for x in 0..self.width {
                self.put_pixel(x, y, bg);
            }
        }
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.scroll();
        }
    }

    pub fn write_byte(&mut self, b: u8) {
        match b {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            b'\t' => {
                let next = (self.col / 8 + 1) * 8;
                while self.col < next.min(self.cols) {
                    self.write_byte(b' ');
                }
            }
            0x20..=0x7e => {
                if self.col >= self.cols {
                    self.newline();
                }
                self.draw_glyph(b);
                self.col += 1;
            }
            _ => self.write_byte(b'?'),
        }
    }
}

impl core::fmt::Write for FbConsole<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            self.write_byte(b);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    const FMT: PixelFormat = PixelFormat {
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    fn pixel(buf: &[u8], pitch: usize, x: usize, y: usize) -> u32 {
        let o = y * pitch + x * 4;
        u32::from_le_bytes(buf[o..o + 4].try_into().unwrap())
    }

    #[test]
    fn rejects_bad_geometry() {
        let mut buf = vec![0u8; 100];
        assert!(FbConsole::new(&mut buf, 64, 64, 256, FMT).is_none());
        let mut buf = vec![0u8; 4 * 4 * 4];
        assert!(
            FbConsole::new(&mut buf, 4, 4, 16, FMT).is_none(),
            "smaller than one glyph"
        );
        let mut buf = vec![0u8; 64 * 64 * 4];
        assert!(
            FbConsole::new(&mut buf, 64, 64, 100, FMT).is_none(),
            "pitch < width*4"
        );
    }

    #[test]
    fn draws_glyph_pixels() {
        let (w, h) = (64, 32);
        let mut buf = vec![0u8; w * h * 4];
        let mut con = FbConsole::new(&mut buf, w, h, w * 4, FMT).unwrap();
        assert_eq!((con.cols(), con.rows()), (8, 4));
        con.write_str("|").unwrap();
        let _ = con;
        // '|' in font8x8 has its column lit at x = 3 and 4 on row 0.
        let fg = FMT.pack(0xd0, 0xd0, 0xd0);
        let lit = (0..8).filter(|&x| pixel(&buf, w * 4, x, 0) == fg).count();
        assert!(lit > 0, "glyph must light some pixels");
        assert_ne!(pixel(&buf, w * 4, 0, 0), fg);
    }

    #[test]
    fn wraps_and_scrolls_without_panicking() {
        let (w, h) = (64, 32);
        let mut buf = vec![0u8; w * h * 4];
        let mut con = FbConsole::new(&mut buf, w, h, w * 4, FMT).unwrap();
        for i in 0..200 {
            writeln!(con, "line {i}\twith\ttabs and a long tail that wraps").unwrap();
        }
        con.write_byte(0xff);
        assert_eq!(con.row, 3);
    }
}
