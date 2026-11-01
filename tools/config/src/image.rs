//! Configuring ISO and raw images in place (C1d, ADR-218).

use crate::{blob_of, describe, verify_blob};

/// A patched image and a short report of what changed.
pub struct Patched {
    pub bytes: Vec<u8>,
    pub report: String,
}

pub fn configure_iso(_iso: &[u8], _blob: &[u8]) -> Result<Patched, String> {
    Err("configuring an ISO is not implemented yet".into())
}

pub fn configure_raw(_img: &[u8], _blob: &[u8]) -> Result<Patched, String> {
    Err("configuring a raw image is not implemented yet".into())
}

pub fn show(data: &[u8], all: bool) -> Result<String, String> {
    describe(blob_of(data)?, all)
}

pub fn verify(data: &[u8], dev: bool) -> Result<String, String> {
    verify_blob(blob_of(data)?, dev)
}
