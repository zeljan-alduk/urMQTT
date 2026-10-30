//! X0b differential test: CRC-32C with the ARMv8 CRC32 instructions (the
//! kernel's dispatched backend) against the store's table, from any start
//! value and alignment. A no-op on other host architectures.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("crc") || data.len() < 5 {
            return;
        }
        let init = u32::from_le_bytes(data[..4].try_into().unwrap());
        let skip = usize::from(data[4]) % 8;
        let d = &data[5 + skip.min(data.len() - 5)..];
        // SAFETY: the feature was detected above.
        let hw = unsafe { urmqtt_arch_aarch64::crc::crc32c_update(init, d) };
        assert_eq!(hw, urmqtt_store::crc::table_update(init, d));
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = data;
});
