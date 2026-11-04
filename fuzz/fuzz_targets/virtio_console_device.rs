//! virtio-console port 0 against a hostile device (ADR-258): the fake
//! device of the driver's tests plays the hypervisor, and every 4 bytes of
//! input choose what happens next: the device completes a receive buffer
//! (with fuzzer bytes, any length it claims, possibly a head it was never
//! given), completes a transmit buffer (same), or the driver writes or reads.
//! Nothing may panic, what is read back came from the device, and every
//! byte written is either sent or counted as dropped.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::F_VERSION_1;
use urmqtt_virtio::bus::BYTE_RING;
use urmqtt_virtio::console::VirtioConsole;
use urmqtt_virtio::fake::{FakeBus, FakeEnv};

fuzz_target!(|data: &[u8]| {
    let bus = FakeBus::new(F_VERSION_1, &[8, 8], 12);
    let env = FakeEnv::default();
    let Ok(mut c) = VirtioConsole::new(&bus, &env) else {
        return;
    };
    let mut written = 0u64;
    let mut held = 0usize;
    for op in data.chunks(4) {
        let [kind, a, b, d] = [0, 1, 2, 3].map(|i| op.get(i).copied().unwrap_or(0));
        match kind % 5 {
            0 => match bus.pop(0) {
                Some((head, segs)) => {
                    let n = FakeBus::fill(&segs, &[a, b, d]);
                    let claim = if kind & 0x80 != 0 {
                        u32::from(a) * 977
                    } else {
                        n
                    };
                    bus.complete(0, u32::from(head), claim);
                }
                None => bus.complete(0, u32::from(a), u32::from(b)),
            },
            1 => match bus.pop(1) {
                Some((head, _)) if kind & 0x80 == 0 => bus.complete(1, u32::from(head), 0),
                _ => bus.complete(1, u32::from(a) << (b % 16), 0),
            },
            2 => {
                let line = vec![b'x'; usize::from(a) * 7 + usize::from(b & 3)];
                c.write(&line);
                written += line.len() as u64;
            }
            3 => {
                c.poll();
                while c.read_byte().is_some() {
                    held += 1;
                }
            }
            _ => c.flush(),
        }
    }
    assert_eq!(c.tx_bytes + c.tx_dropped, written);
    assert!(held as u64 <= c.rx_bytes);
    c.poll();
    let mut left = 0;
    while c.read_byte().is_some() {
        left += 1;
    }
    assert!(left <= BYTE_RING);
});
