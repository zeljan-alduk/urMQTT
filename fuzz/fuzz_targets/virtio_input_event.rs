//! virtio-input events (ADR-258): every 8 bytes are one event as a device
//! writes it (type, code, value), fed to the key map the Diagnostic
//! prompts read. Nothing panics, only whole events parse, and what comes
//! out is a character the prompts know: printable ASCII, Enter, Tab,
//! Backspace or Escape. The same bytes as an EV_KEY bitmap classify the
//! device without reading past it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::input::{Event, Keymap, classify};

fuzz_target!(|data: &[u8]| {
    let mut k = Keymap::default();
    for chunk in data.chunks(8) {
        match Event::parse(chunk) {
            Some(e) => {
                assert_eq!(chunk.len(), 8);
                if let Some(c) = k.feed(e) {
                    assert!(
                        (0x20..0x7f).contains(&c) || matches!(c, b'\n' | b'\t' | 0x08 | 0x1b),
                        "{c:#x} from {e:?}"
                    );
                }
            }
            None => assert!(chunk.len() < 8),
        }
    }
    let _ = classify(data, data.first().is_some_and(|b| b & 1 != 0));
});
