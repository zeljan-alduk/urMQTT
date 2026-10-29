//! Ethernet frames from the NIC (M14, M16): ARP, IPv4 (options and
//! fragments refused), ICMP echo, UDP and the DHCP client's replies. Every
//! byte comes from the network, so decoding must never panic, before and
//! after the interface has an address.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_net::iface::Iface;

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

fuzz_target!(|data: &[u8]| {
    let mut i = Iface::new(MAC, true, Some(0x1234_5678), 0);
    let mut now = 0u64;
    let mut rest = data;
    // Frames are length-prefixed (one byte); the first half arrives before
    // an address is configured, the rest after.
    let mut n = 0;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len).min(tail.len());
        let (frame, tail) = tail.split_at(len);
        rest = tail;
        now += 7;
        let _ = i.receive(now, frame, &mut |_| {});
        let _ = i.poll(now, &mut |_| {});
        n += 1;
        if n == 4 {
            i.set_addr(Some(([10, 0, 2, 15], 24)), Some([10, 0, 2, 2]));
        }
        let _ = i.send_udp([10, 0, 2, 2], 40514, 514, frame, &mut |_| {});
    }
});
