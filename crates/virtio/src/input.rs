//! virtio-input (virtio 1.x §5.8), keyboards for the Diagnostic entry's
//! prompts (ADR-258): a provider's VNC console on a VPS may send its key
//! events to a virtio keyboard instead of a PS/2 controller.
//!
//! The driver reads the device's name and which event types and keys it
//! has (the configuration's `select`/`subsel` interface), keeps the event
//! queue full of 8-byte buffers and turns key presses into the bytes the
//! prompts read: letters, digits, the punctuation of a US layout, Enter
//! (`\n`), Backspace (`\x08`), Escape (`\x1b`), with Shift and Caps Lock.
//! Pointer events (a tablet or a mouse) are only counted. The status queue
//! (LEDs) is not used.

use crate::bus::{Bus, ByteRing, cfg_consistent, dma_read, make_queue};
use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::{Env, F_VERSION_1, VirtioError};

// Configuration layout.
pub const CFG_SELECT: usize = 0;
pub const CFG_SUBSEL: usize = 1;
pub const CFG_SIZE: usize = 2;
pub const CFG_DATA: usize = 8;
pub const CFG_DATA_LEN: usize = 128;

pub const ID_NAME: u8 = 0x01;
pub const ID_SERIAL: u8 = 0x02;
pub const ID_DEVIDS: u8 = 0x03;
pub const PROP_BITS: u8 = 0x10;
pub const EV_BITS: u8 = 0x11;
pub const ABS_INFO: u8 = 0x12;

// evdev event types and the key codes the prompts need.
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const KEY_ESC: u16 = 1;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_A: u16 = 30;
pub const KEY_KPENTER: u16 = 96;

pub const EVENT_LEN: usize = 8;
const EVENTQ: u16 = 0;
/// Event buffers kept posted.
pub const EVENT_BUFS: usize = 64;
const QMAX: u16 = 64;

/// One event as the device writes it: type le16, code le16, value le32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub ty: u16,
    pub code: u16,
    pub value: u32,
}

impl Event {
    /// `None` unless `b` holds a whole event.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let w = |at: usize| -> Option<u16> {
            Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
        };
        Some(Self {
            ty: w(0)?,
            code: w(2)?,
            value: u32::from_le_bytes(b.get(4..8)?.try_into().ok()?),
        })
    }
}

/// evdev key events to ASCII (US layout).
#[derive(Debug, Default, Clone, Copy)]
pub struct Keymap {
    shift_left: bool,
    shift_right: bool,
    caps: bool,
}

impl Keymap {
    /// A character for a key press (value 1) or auto-repeat (2) that has
    /// one; tracks Shift (both) and Caps Lock.
    pub fn feed(&mut self, e: Event) -> Option<u8> {
        if e.ty != EV_KEY {
            return None;
        }
        let down = e.value != 0;
        match e.code {
            KEY_LEFTSHIFT => {
                self.shift_left = down;
                return None;
            }
            KEY_RIGHTSHIFT => {
                self.shift_right = down;
                return None;
            }
            KEY_CAPSLOCK => {
                if e.value == 1 {
                    self.caps = !self.caps;
                }
                return None;
            }
            _ => {}
        }
        if !down {
            return None;
        }
        let shift = self.shift_left || self.shift_right;
        let pick = |table: &[u8], first: u16| -> Option<u8> {
            table.get(usize::from(e.code.checked_sub(first)?)).copied()
        };
        let letter = |c: u8| {
            if shift ^ self.caps {
                c.to_ascii_uppercase()
            } else {
                c
            }
        };
        let (lower, upper): (u8, u8) = match e.code {
            KEY_ESC => (0x1b, 0x1b),
            2..=11 => (pick(b"1234567890", 2)?, pick(b"!@#$%^&*()", 2)?),
            12 => (b'-', b'_'),
            13 => (b'=', b'+'),
            KEY_BACKSPACE => (0x08, 0x08),
            15 => (b'\t', b'\t'),
            16..=25 => return pick(b"qwertyuiop", 16).map(letter),
            26 => (b'[', b'{'),
            27 => (b']', b'}'),
            KEY_ENTER | KEY_KPENTER => (b'\n', b'\n'),
            30..=38 => return pick(b"asdfghjkl", 30).map(letter),
            39 => (b';', b':'),
            40 => (b'\'', b'"'),
            41 => (b'`', b'~'),
            43 => (b'\\', b'|'),
            44..=50 => return pick(b"zxcvbnm", 44).map(letter),
            51 => (b',', b'<'),
            52 => (b'.', b'>'),
            53 => (b'/', b'?'),
            KEY_SPACE => (b' ', b' '),
            _ => return None,
        };
        Some(if shift { upper } else { lower })
    }
}

/// What a device is, from its event bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Has letter keys.
    Keyboard,
    /// Relative or absolute axes and no letter keys (mouse, tablet).
    Pointer,
    Other,
}

impl Class {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Pointer => "pointer",
            Self::Other => "other",
        }
    }
}

/// Classifies from the `EV_KEY` bitmap and whether `EV_REL`/`EV_ABS` exist.
pub fn classify(key_bits: &[u8], axes: bool) -> Class {
    let has = |code: u16| {
        key_bits
            .get(usize::from(code / 8))
            .is_some_and(|b| b & (1 << (code % 8)) != 0)
    };
    if has(KEY_A) && has(KEY_ENTER) {
        Class::Keyboard
    } else if axes {
        Class::Pointer
    } else {
        Class::Other
    }
}

/// Reads one configuration item (`select`, `subsel`) into `out`; returns
/// its length as the device reports it, clamped to the 128-byte union.
pub fn query<B: Bus>(bus: &B, select: u8, subsel: u8, out: &mut [u8; CFG_DATA_LEN]) -> usize {
    bus.cfg_write8(CFG_SELECT, select);
    bus.cfg_write8(CFG_SUBSEL, subsel);
    cfg_consistent(bus, |b| {
        let n = usize::from(b.cfg_read8(CFG_SIZE)).min(CFG_DATA_LEN);
        for (i, x) in out.iter_mut().enumerate() {
            *x = if i < n { b.cfg_read8(CFG_DATA + i) } else { 0 };
        }
        n
    })
}

pub struct VirtioInput<B: Bus> {
    bus: B,
    q: SplitQueue,
    off: usize,
    mem: DmaRegion,
    /// Event slot of each descriptor head (u8::MAX: none).
    slot: [u8; QMAX as usize],
    name: [u8; 32],
    name_len: usize,
    pub class: Class,
    keymap: Keymap,
    input: ByteRing,
    pub keys: u64,
    pub pointer_events: u64,
    pub other_events: u64,
    pub protocol_errors: u64,
}

impl<B: Bus> VirtioInput<B> {
    pub fn new<E: Env>(bus: B, env: &E) -> Result<Self, VirtioError> {
        bus.init(env, 0, F_VERSION_1)?;
        let mut buf = [0u8; CFG_DATA_LEN];
        let n = query(&bus, ID_NAME, 0, &mut buf);
        let mut name = [0u8; 32];
        let mut name_len = 0;
        for &c in buf.iter().take(n.min(name.len())) {
            if c == 0 {
                break;
            }
            if let Some(slot) = name.get_mut(name_len) {
                // Printable ASCII only: the name goes into the log.
                *slot = if (0x20..0x7f).contains(&c) { c } else { b'?' };
                name_len += 1;
            }
        }
        let mut keys = [0u8; CFG_DATA_LEN];
        query(&bus, EV_BITS, EV_KEY as u8, &mut keys);
        let axes = query(&bus, EV_BITS, EV_REL as u8, &mut buf) > 0
            || query(&bus, EV_BITS, EV_ABS as u8, &mut buf) > 0;
        let class = classify(&keys, axes);
        let (q, off) = make_queue(&bus, env, EVENTQ, QMAX)?;
        let mem = env
            .dma_alloc(EVENT_BUFS * EVENT_LEN)
            .ok_or(VirtioError::NoDma)?;
        let mut d = Self {
            bus,
            q,
            off,
            mem,
            slot: [u8::MAX; QMAX as usize],
            name,
            name_len,
            class,
            keymap: Keymap::default(),
            input: ByteRing::default(),
            keys: 0,
            pointer_events: 0,
            other_events: 0,
            protocol_errors: 0,
        };
        for s in 0..EVENT_BUFS.min(usize::from(d.q.size())) {
            d.post(s)?;
        }
        d.bus.driver_ok()?;
        d.bus.notify(d.off, EVENTQ);
        Ok(d)
    }

    /// The device's name (ID_NAME), printable ASCII, at most 32 bytes.
    pub fn name(&self) -> &str {
        core::str::from_utf8(self.name.get(..self.name_len).unwrap_or(&[])).unwrap_or("?")
    }

    fn post(&mut self, s: usize) -> Result<(), VirtioError> {
        let head = self
            .q
            .next_free()
            .ok_or(VirtioError::Queue(crate::QueueError::NoDescriptors))?;
        self.q.add(&[Buf {
            pa: self.mem.pa + (s * EVENT_LEN) as u64,
            len: EVENT_LEN as u32,
            device_writes: true,
        }])?;
        if let Some(x) = self.slot.get_mut(usize::from(head)) {
            *x = s as u8;
        }
        Ok(())
    }

    /// Handles what the device sent: key presses become bytes for
    /// [`read_byte`](Self::read_byte). Bounded by the queue size.
    pub fn poll(&mut self) {
        let mut reposted = false;
        for _ in 0..self.q.size() {
            let (head, len) = match self.q.pop_used() {
                Ok(Some(d)) => d,
                Ok(None) => break,
                Err(_) => {
                    self.protocol_errors += 1;
                    break;
                }
            };
            let Some(s) = self
                .slot
                .get_mut(usize::from(head))
                .map(|x| core::mem::replace(x, u8::MAX))
                .filter(|&s| usize::from(s) < EVENT_BUFS)
            else {
                self.protocol_errors += 1;
                continue;
            };
            let mut b = [0u8; EVENT_LEN];
            if (len as usize) < EVENT_LEN
                || !dma_read(&self.mem, usize::from(s) * EVENT_LEN, &mut b)
            {
                self.protocol_errors += 1;
            } else if let Some(e) = Event::parse(&b) {
                self.event(e);
            }
            if self.post(usize::from(s)).is_ok() {
                reposted = true;
            }
        }
        if reposted {
            self.bus.notify(self.off, EVENTQ);
        }
    }

    fn event(&mut self, e: Event) {
        match e.ty {
            EV_KEY => {
                if let Some(c) = self.keymap.feed(e) {
                    self.keys += 1;
                    self.input.push(c);
                }
            }
            EV_REL | EV_ABS => self.pointer_events += 1,
            EV_SYN => {}
            _ => self.other_events += 1,
        }
    }

    /// One typed byte, if any (call [`poll`](Self::poll) first).
    pub fn read_byte(&mut self) -> Option<u8> {
        self.input.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeBus, FakeEnv};

    fn key(code: u16, value: u32) -> Event {
        Event {
            ty: EV_KEY,
            code,
            value,
        }
    }

    fn bytes(e: Event) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&e.ty.to_le_bytes());
        b[2..4].copy_from_slice(&e.code.to_le_bytes());
        b[4..8].copy_from_slice(&e.value.to_le_bytes());
        b
    }

    #[test]
    fn the_confirmation_word_types_with_shift_and_with_caps_lock() {
        let mut k = Keymap::default();
        let mut typed = Vec::new();
        // Shift held, W I P E, Shift released, Enter.
        for e in [
            key(KEY_LEFTSHIFT, 1),
            key(17, 1),
            key(17, 0),
            key(23, 1),
            key(25, 1),
            key(18, 1),
            key(KEY_LEFTSHIFT, 0),
            key(KEY_ENTER, 1),
        ] {
            typed.extend(k.feed(e));
        }
        assert_eq!(typed, b"WIPE\n");
        typed.clear();
        for e in [
            key(KEY_CAPSLOCK, 1),
            key(KEY_CAPSLOCK, 0),
            key(17, 1),
            key(KEY_CAPSLOCK, 1),
        ] {
            typed.extend(k.feed(e));
        }
        // Caps Lock off again (one toggle per press, not per release).
        typed.extend(k.feed(key(17, 1)));
        assert_eq!(typed, b"Ww");
        // Digits, Backspace, Escape, auto-repeat, right Shift.
        typed.clear();
        for e in [
            key(2, 1),
            key(11, 2),
            key(KEY_BACKSPACE, 1),
            key(KEY_ESC, 1),
            key(KEY_RIGHTSHIFT, 1),
            key(2, 1),
            key(KEY_RIGHTSHIFT, 0),
            key(KEY_SPACE, 1),
            key(KEY_KPENTER, 1),
        ] {
            typed.extend(k.feed(e));
        }
        assert_eq!(typed, b"10\x08\x1b! \n");
        // Unknown codes, relative events and huge codes give nothing.
        assert_eq!(k.feed(key(0xffff, 1)), None);
        assert_eq!(k.feed(key(200, 1)), None);
        assert_eq!(
            k.feed(Event {
                ty: EV_REL,
                code: 0,
                value: 5
            }),
            None
        );
    }

    #[test]
    fn events_parse_only_whole() {
        assert_eq!(Event::parse(&bytes(key(30, 1))), Some(key(30, 1)));
        assert_eq!(Event::parse(&[1, 0, 30, 0, 1, 0, 0]), None);
    }

    #[test]
    fn devices_are_classified() {
        let mut k = [0u8; 16];
        k[usize::from(KEY_A / 8)] |= 1 << (KEY_A % 8);
        assert_eq!(classify(&k, false), Class::Other);
        k[usize::from(KEY_ENTER / 8)] |= 1 << (KEY_ENTER % 8);
        assert_eq!(classify(&k, true), Class::Keyboard);
        assert_eq!(classify(&[0; 16], true), Class::Pointer);
        assert_eq!(classify(&[], false), Class::Other);
    }

    /// A fake keyboard whose configuration answers select/subsel queries
    /// the way QEMU's virtio-keyboard does (name and EV_KEY bits).
    fn keyboard() -> FakeBus {
        let bus = FakeBus::new(F_VERSION_1, &[64, 8], 8 + CFG_DATA_LEN);
        bus.set_cfg(CFG_SIZE, &[0]);
        bus
    }

    #[test]
    fn key_presses_from_the_device_become_bytes() {
        let bus = keyboard();
        let env = FakeEnv::default();
        let mut d = VirtioInput::new(&bus, &env).unwrap();
        // The fake answers every query with size 0: nameless, class other.
        assert_eq!((d.name(), d.class), ("", Class::Other));
        for e in [
            key(KEY_LEFTSHIFT, 1),
            key(17, 1),
            Event {
                ty: EV_SYN,
                code: 0,
                value: 0,
            },
            key(KEY_LEFTSHIFT, 0),
            Event {
                ty: EV_ABS,
                code: 0,
                value: 100,
            },
            key(KEY_ENTER, 1),
        ] {
            let (head, segs) = bus.pop(EVENTQ).unwrap();
            let n = FakeBus::fill(&segs, &bytes(e));
            bus.complete(EVENTQ, u32::from(head), n);
        }
        d.poll();
        assert_eq!(d.read_byte(), Some(b'W'));
        assert_eq!(d.read_byte(), Some(b'\n'));
        assert_eq!(d.read_byte(), None);
        assert_eq!((d.keys, d.pointer_events, d.protocol_errors), (2, 1, 0));
        // A short event and a completion for an unknown head are counted.
        let (head, _) = bus.pop(EVENTQ).unwrap();
        bus.complete(EVENTQ, u32::from(head), 3);
        d.poll();
        assert_eq!(d.protocol_errors, 1);
        bus.complete(EVENTQ, 200, 8);
        d.poll();
        assert_eq!(d.protocol_errors, 2);
    }

    #[test]
    fn the_name_is_read_and_sanitised() {
        // A fake whose union always holds a name with a control byte and a
        // size claim past the union.
        let bus = keyboard();
        let mut name = b"QEMU Virtio\x07Keyboard".to_vec();
        name.resize(CFG_DATA_LEN, b'Z');
        bus.set_cfg(CFG_DATA, &name);
        bus.set_cfg(CFG_SIZE, &[255]);
        let d = VirtioInput::new(&bus, &FakeEnv::default()).unwrap();
        assert_eq!(d.name(), "QEMU Virtio?KeyboardZZZZZZZZZZZZ");
        // Every bit set in the fake's "EV_KEY" answer: a keyboard.
        assert_eq!(d.class, Class::Keyboard);
    }
}
