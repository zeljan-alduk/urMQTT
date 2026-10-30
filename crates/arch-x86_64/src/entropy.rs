//! The CPU's own random source (RDSEED/RDRAND, X4).

pub fn hw_random() -> Option<[u8; 64]> {
    None
}
