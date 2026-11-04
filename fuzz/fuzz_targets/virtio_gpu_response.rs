//! virtio-gpu control-queue responses (ADR-256): the device is the
//! hypervisor, trusted to show the screen, not to keep our parser safe. The
//! first 13 bytes choose what the driver expected (a selector byte), the
//! length the device claims it wrote (u32) and the request's fence (u64, or
//! none); the rest is the response buffer. Parsing must never panic, a
//! display info is only accepted whole, and the mode chosen from it stays
//! inside the bounds whatever the device prefers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_virtio::gpu::{
    AutoChoice, DISPLAY_INFO_LEN, HDR_LEN, MAX_HEIGHT, MAX_WIDTH, MIN_HEIGHT, MIN_WIDTH,
    RESP_OK_DISPLAY_INFO, RESP_OK_NODATA, Reply, auto_choice, choose_mode, parse_response,
};

fuzz_target!(|data: &[u8]| {
    let Some((head, buf)) = data.split_first_chunk::<13>() else {
        return;
    };
    let expect = if head[0] & 1 == 0 {
        RESP_OK_NODATA
    } else {
        RESP_OK_DISPLAY_INFO
    };
    let written = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let fence =
        (head[0] & 2 != 0).then(|| u64::from_le_bytes(head[5..13].try_into().unwrap_or([0; 8])));
    let n = (written as usize).min(buf.len());
    match parse_response(buf, written, expect, fence) {
        Ok(Reply::NoData) => assert!(n >= HDR_LEN && expect == RESP_OK_NODATA),
        Ok(Reply::DisplayInfo(info)) => {
            assert!(n >= DISPLAY_INFO_LEN && expect == RESP_OK_DISPLAY_INFO);
            let budget = u64::from(written) << 4;
            if let Some((w, h)) = choose_mode(Some(&info), budget) {
                assert!(
                    (MIN_WIDTH..=MAX_WIDTH).contains(&w) && (MIN_HEIGHT..=MAX_HEIGHT).contains(&h)
                );
                assert!(u64::from(w) * u64::from(h) * 4 <= budget);
            }
            // The rectangles, taken as BARs, never make the decision panic.
            let bars: Vec<(u8, u64, u64)> = info
                .modes
                .iter()
                .flatten()
                .map(|r| {
                    (
                        0,
                        (u64::from(r.x) << 32) | u64::from(r.y),
                        u64::from(r.width) * u64::from(r.height),
                    )
                })
                .collect();
            let fb = Some((u64::from(written) << 20, u64::from(head[4]) << 12));
            if let AutoChoice::BootFramebufferInBar { index, .. } = auto_choice(fb, &[&bars]) {
                assert_eq!(index, 0);
            }
        }
        Err(_) => {}
    }
});
