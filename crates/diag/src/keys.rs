//! Keyboard input for the confirmation prompt: PS/2 scancodes (set 1, what
//! the i8042 delivers on a PC with its default translation) to ASCII, and a
//! line editor shared with the serial port.

use alloc::string::String;

/// What the user must type before the diagnostic writes to a disk that is
/// not installed.
pub const CONFIRM_WORD: &str = "WIPE";

/// Longest line the editor keeps.
pub const MAX_LINE: usize = 24;

/// Translates scancode set 1 into ASCII characters.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ps2 {
    shift: bool,
    caps: bool,
    extended: bool,
}

impl Ps2 {
    /// Feeds one byte from the controller; returns a character for a key
    /// press that has one (Enter is `\n`, Backspace `\x08`, Esc `\x1b`).
    pub fn feed(&mut self, code: u8) -> Option<u8> {
        if code == 0xe0 || code == 0xe1 {
            self.extended = true;
            return None;
        }
        if self.extended {
            // The byte after an extended prefix: arrows, keypad Enter, ...
            // ignored (a Pause key sends several; each is consumed here).
            self.extended = false;
            return None;
        }
        let release = code & 0x80 != 0;
        let make = code & 0x7f;
        if matches!(make, 0x2a | 0x36) {
            self.shift = !release;
            return None;
        }
        if release {
            return None;
        }
        if make == 0x3a {
            self.caps = !self.caps;
            return None;
        }
        let upper = self.shift;
        let (lower, shifted): (u8, u8) = match make {
            0x01 => (0x1b, 0x1b),
            0x02 => (b'1', b'!'),
            0x03 => (b'2', b'@'),
            0x04 => (b'3', b'#'),
            0x05 => (b'4', b'$'),
            0x06 => (b'5', b'%'),
            0x07 => (b'6', b'^'),
            0x08 => (b'7', b'&'),
            0x09 => (b'8', b'*'),
            0x0a => (b'9', b'('),
            0x0b => (b'0', b')'),
            0x0e => (0x08, 0x08),
            0x1c => (b'\n', b'\n'),
            0x39 => (b' ', b' '),
            0x10..=0x19 => {
                let c = b"qwertyuiop".get(usize::from(make - 0x10)).copied()?;
                return Some(self.letter(c));
            }
            0x1e..=0x26 => {
                let c = b"asdfghjkl".get(usize::from(make - 0x1e)).copied()?;
                return Some(self.letter(c));
            }
            0x2c..=0x32 => {
                let c = b"zxcvbnm".get(usize::from(make - 0x2c)).copied()?;
                return Some(self.letter(c));
            }
            _ => return None,
        };
        Some(if upper { shifted } else { lower })
    }

    fn letter(&self, lower: u8) -> u8 {
        if self.shift ^ self.caps {
            lower.to_ascii_uppercase()
        } else {
            lower
        }
    }
}

/// What a typed byte did to the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Nothing visible changed.
    None,
    /// The line changed (a character added or removed).
    Changed,
    /// Enter: the finished line.
    Line(String),
    /// Escape: the line was abandoned.
    Cancelled,
}

/// A one-line editor: printable ASCII, backspace, Enter, Escape.
#[derive(Debug, Default, Clone)]
pub struct LineEditor {
    line: String,
}

impl LineEditor {
    pub fn line(&self) -> &str {
        &self.line
    }

    pub fn feed(&mut self, b: u8) -> Edit {
        match b {
            b'\r' | b'\n' => {
                // A CR LF pair from a terminal is one Enter; the empty
                // second one is reported as an empty line only if the
                // first was already taken.
                Edit::Line(core::mem::take(&mut self.line))
            }
            0x08 | 0x7f => {
                if self.line.pop().is_some() {
                    Edit::Changed
                } else {
                    Edit::None
                }
            }
            0x1b => {
                self.line.clear();
                Edit::Cancelled
            }
            0x20..=0x7e if self.line.len() < MAX_LINE => {
                self.line.push(char::from(b));
                Edit::Changed
            }
            _ => Edit::None,
        }
    }
}

/// Whether a finished line is the confirmation: exactly [`CONFIRM_WORD`]
/// (case-sensitive, surrounding blanks ignored).
pub fn is_confirmation(line: &str) -> bool {
    line.trim() == CONFIRM_WORD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_codes(codes: &[u8]) -> String {
        let mut k = Ps2::default();
        codes
            .iter()
            .filter_map(|&c| k.feed(c))
            .map(char::from)
            .collect()
    }

    #[test]
    fn wipe_with_shift_and_with_caps() {
        // Shift down, W I P E, shift up, Enter (make + break codes).
        let shift = [
            0x2a, 0x11, 0x91, 0x17, 0x97, 0x19, 0x99, 0x12, 0x92, 0xaa, 0x1c, 0x9c,
        ];
        assert_eq!(type_codes(&shift), "WIPE\n");
        let caps = [0x3a, 0xba, 0x11, 0x17, 0x19, 0x12, 0x1c];
        assert_eq!(type_codes(&caps), "WIPE\n");
        // Without shift it is lower case.
        assert_eq!(type_codes(&[0x11, 0x17, 0x19, 0x12]), "wipe");
    }

    #[test]
    fn releases_prefixes_and_unknown_keys_give_nothing() {
        assert_eq!(type_codes(&[0x91, 0xe0, 0x48, 0xe0, 0xc8, 0x3b, 0x58]), "");
        // The byte after E0 is swallowed even if it is a letter's code.
        assert_eq!(type_codes(&[0xe0, 0x11, 0x11]), "w");
        assert_eq!(type_codes(&[0x02, 0x0b, 0x39, 0x0e, 0x01]), "10 \x08\x1b");
        assert_eq!(type_codes(&[0x2a, 0x02, 0x03]), "!@");
    }

    #[test]
    fn the_line_editor() {
        let mut e = LineEditor::default();
        for b in *b"WIPX" {
            assert_eq!(e.feed(b), Edit::Changed);
        }
        assert_eq!(e.feed(0x08), Edit::Changed);
        assert_eq!(e.feed(b'E'), Edit::Changed);
        assert_eq!(e.line(), "WIPE");
        assert_eq!(e.feed(b'\r'), Edit::Line("WIPE".into()));
        assert_eq!(e.line(), "");
        assert_eq!(e.feed(0x08), Edit::None);
        assert_eq!(e.feed(0x01), Edit::None, "control bytes are ignored");
        e.feed(b'a');
        assert_eq!(e.feed(0x1b), Edit::Cancelled);
        assert_eq!(e.line(), "");
        for _ in 0..100 {
            e.feed(b'x');
        }
        assert_eq!(e.line().len(), MAX_LINE);
    }

    #[test]
    fn only_the_exact_word_confirms() {
        assert!(is_confirmation("WIPE"));
        assert!(is_confirmation("  WIPE "));
        for no in ["wipe", "WIPE!", "WIP", "yes", "", "WIPE WIPE", "Y"] {
            assert!(!is_confirmation(no), "{no:?}");
        }
    }
}
