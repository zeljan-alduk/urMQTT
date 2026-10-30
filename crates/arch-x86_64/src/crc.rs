//! CRC-32C with SSE4.2 `crc32` (X8).

#![allow(unsafe_code)]

/// Continues a CRC-32C computation, as `urmqtt_store::crc::update`.
///
/// # Safety
/// The CPU must implement SSE4.2.
pub unsafe fn crc32c_update(_crc: u32, _data: &[u8]) -> u32 {
    unimplemented_until!("X8 (SSE4.2 CRC-32C)")
}
