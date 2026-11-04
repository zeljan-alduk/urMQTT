//! Where the server's CPU time goes inside one handshake, stage by stage
//! (host profiling only, PERF; `cargo run --release -p urmqtt-tls --features
//! stage-profile --example handshake_profile`).
//!
//! Without the `stage-profile` feature (the kernel never enables it)
//! [`timed`] is `f()` and nothing else is compiled. With it, the calls the
//! provider and the session make for one connection are timed while the
//! current thread is [`armed`]; times are *exclusive* (a stage nested in
//! another, such as a signature check inside the certificate path
//! validation, is subtracted from the outer one), so the stages and the
//! unattributed rest add up to the armed total.

/// A part of the server's handshake work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// Key share: secret from the RNG and the X25519 public key.
    X25519Keygen,
    /// X25519 shared secret with the client's share.
    X25519Shared,
    /// The P-256 key exchange (only if a client offers no X25519).
    P256Kx,
    /// ECDSA signature of our CertificateVerify (SHA-256 and RFC 6979 inside).
    Sign,
    /// ECDSA verification of the client's CertificateVerify (a key without
    /// a table).
    VerifyCertificateVerify,
    /// ECDSA verification of the client certificate by a registered issuer
    /// (`KeyTable`).
    VerifyCertificate,
    /// The verification memo: digest of (key, message, signature) and lookup.
    VerifyMemo,
    /// webpki: certificate parsing, path building, validity and usage checks
    /// (exclusive of the signature checks it calls).
    CertPath,
    /// Our checks after webpki: serial present, revocation list, role record.
    CertChecks,
    /// Transcript and other SHA-256 hashing through the provider.
    Transcript,
    /// HMAC-SHA-256 (HKDF of the key schedule, Finished).
    Hkdf,
    /// AEAD of the handshake records (key setup included).
    Aead,
    /// Session ticket sealing.
    Ticket,
    /// Random bytes from the CSPRNG (outside the key share).
    Rng,
    /// After rustls: identity, serial, role, record layer keys and checks.
    Finish,
}

impl Stage {
    pub const ALL: [Self; 15] = [
        Self::X25519Keygen,
        Self::X25519Shared,
        Self::P256Kx,
        Self::Sign,
        Self::VerifyCertificateVerify,
        Self::VerifyCertificate,
        Self::VerifyMemo,
        Self::CertPath,
        Self::CertChecks,
        Self::Transcript,
        Self::Hkdf,
        Self::Aead,
        Self::Ticket,
        Self::Rng,
        Self::Finish,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::X25519Keygen => "x25519 key share (keygen)",
            Self::X25519Shared => "x25519 shared secret",
            Self::P256Kx => "p256 key exchange",
            Self::Sign => "ecdsa sign (CertificateVerify)",
            Self::VerifyCertificateVerify => "ecdsa verify, client CertificateVerify",
            Self::VerifyCertificate => "ecdsa verify, client cert by CA table",
            Self::VerifyMemo => "verify memo (digest + lookup)",
            Self::CertPath => "webpki path: x509/DER parse, checks",
            Self::CertChecks => "serial, revocation, role",
            Self::Transcript => "sha-256 (transcript)",
            Self::Hkdf => "hmac-sha-256 (hkdf, finished)",
            Self::Aead => "aead (handshake records)",
            Self::Ticket => "session ticket seal",
            Self::Rng => "rng",
            Self::Finish => "finish: identity, record keys",
        }
    }

    #[cfg(feature = "stage-profile")]
    fn index(self) -> usize {
        self as usize
    }
}

#[cfg(not(feature = "stage-profile"))]
#[inline(always)]
pub(crate) fn timed<R>(_stage: Stage, f: impl FnOnce() -> R) -> R {
    f()
}

#[cfg(feature = "stage-profile")]
pub(crate) use imp::timed;
#[cfg(feature = "stage-profile")]
pub use imp::{Report, armed, take};

#[cfg(feature = "stage-profile")]
mod imp {
    extern crate std;

    use core::cell::{Cell, RefCell};
    use std::time::Instant;

    use super::Stage;

    /// Accumulated exclusive nanoseconds and calls per stage, plus the armed
    /// total.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Report {
        pub ns: [u64; Stage::ALL.len()],
        pub calls: [u64; Stage::ALL.len()],
        pub total_ns: u64,
    }

    impl Report {
        /// The armed time no stage accounts for (rustls's state machine,
        /// message encoding and parsing, copies, allocation).
        pub fn rest_ns(&self) -> u64 {
            self.total_ns.saturating_sub(self.ns.iter().sum())
        }
    }

    std::thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        /// Time spent in nested stages of the innermost running stage.
        static CHILD: Cell<u64> = const { Cell::new(0) };
        static ACC: RefCell<Report> = RefCell::new(Report::default());
    }

    fn ns(t0: Instant) -> u64 {
        u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    pub(crate) fn timed<R>(stage: Stage, f: impl FnOnce() -> R) -> R {
        if !ARMED.with(Cell::get) {
            return f();
        }
        let saved = CHILD.with(|c| c.replace(0));
        let t0 = Instant::now();
        let r = f();
        let el = ns(t0);
        let inner = CHILD.with(Cell::get);
        ACC.with(|a| {
            let mut a = a.borrow_mut();
            a.ns[stage.index()] += el.saturating_sub(inner);
            a.calls[stage.index()] += 1;
        });
        CHILD.with(|c| c.set(saved + el));
        r
    }

    /// Runs `f` with the stages of this thread recorded, its whole time
    /// counted as the total.
    pub fn armed<R>(f: impl FnOnce() -> R) -> R {
        ARMED.with(|a| a.set(true));
        CHILD.with(|c| c.set(0));
        let t0 = Instant::now();
        let r = f();
        let el = ns(t0);
        ARMED.with(|a| a.set(false));
        ACC.with(|a| a.borrow_mut().total_ns += el);
        r
    }

    /// The report so far, and a fresh start.
    pub fn take() -> Report {
        ACC.with(|a| core::mem::take(&mut *a.borrow_mut()))
    }
}
