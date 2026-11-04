//! SHA-256 for the TLS 1.3 transcript and key schedule.

use alloc::boxed::Box;

use rustls::crypto::hash;
use sha2::Digest;

use crate::stages::{Stage, timed};

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        timed(Stage::Transcript, || Box::new(Ctx(sha2::Sha256::new())))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        timed(Stage::Transcript, || {
            hash::Output::new(&sha2::Sha256::digest(data)[..])
        })
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Ctx(sha2::Sha256);

impl hash::Context for Ctx {
    fn fork_finish(&self) -> hash::Output {
        timed(Stage::Transcript, || {
            hash::Output::new(&self.0.clone().finalize()[..])
        })
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        timed(Stage::Transcript, || Box::new(Self(self.0.clone())))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        timed(Stage::Transcript, || {
            hash::Output::new(&self.0.finalize()[..])
        })
    }

    fn update(&mut self, data: &[u8]) {
        timed(Stage::Transcript, || self.0.update(data));
    }
}
