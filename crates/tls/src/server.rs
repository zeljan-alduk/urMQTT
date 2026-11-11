//! TLS 1.3 server: rustls (unbuffered, no_std) for the handshake with mutual
//! authentication, then the in-house record layer (ADR-029).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{UnbufferedServerConnection, WebPkiClientVerifier};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::{
    CertificateError, ConnectionTrafficSecrets, DigitallySignedStruct, DistinguishedName,
    HandshakeKind, KeyLog, RootCertStore, ServerConfig, SignatureScheme,
};
use urmqtt_sync::sync::SpinLock;
use zeroize::Zeroize;

use crate::identity::{self, IdentityField};
use crate::record::{self, Opened, RecordError, RecordLayer, Suite};
use crate::stages::{Stage, timed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Config(&'static str),
    Handshake(String),
    /// Handshake complete but no usable identity in the client certificate.
    NoIdentity,
    Record(RecordError),
    /// Bytes arrived that are not a TLS 1.3 ClientHello.
    NotTls,
    Internal(&'static str),
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        Self::Handshake(alloc::format!("{e}"))
    }
}

impl From<RecordError> for TlsError {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}

// --- time -----------------------------------------------------------------

/// Returns Unix seconds, or `None` if the wall clock is unknown.
pub type WallClock = fn() -> Option<u64>;

static CLOCK: SpinLock<Option<WallClock>> = SpinLock::new(None);

/// Installs the wall clock (Unix seconds) used for certificate validity.
/// Without one, every handshake fails (ADR-009).
pub fn set_clock(now_unix: WallClock) {
    *CLOCK.lock() = Some(now_unix);
}

#[derive(Debug)]
pub(crate) struct KernelTime;

impl TimeProvider for KernelTime {
    fn current_time(&self) -> Option<UnixTime> {
        let f = (*CLOCK.lock())?;
        f().map(UnixTime::since_unix_epoch_secs)
    }
}

trait SinceSecs {
    fn since_unix_epoch_secs(s: u64) -> Self;
}

impl SinceSecs for UnixTime {
    fn since_unix_epoch_secs(s: u64) -> Self {
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(s))
    }
}

// --- traffic secret capture (for our own KeyUpdate) -----------------------

/// One handshake's application traffic secrets, as rustls logs them. Each
/// session has its own capture (ADR-340): rustls's key log is a field of
/// the `ServerConfig`, so [`TlsServer::accept`] gives every connection a
/// copy of the shared config whose key log writes into that session's
/// capture and nowhere else. The secrets live exactly as long as the
/// handshake: they are taken (and wiped) when it completes, and wiped on
/// drop whichever way it ends (error, TCP close, reset, timeout). There is
/// no shared table to fill, and no lookup by the attacker-chosen
/// ClientHello random, which a ClientHello fragmented over several records
/// would also have made unreliable (CRYPTO-1, CRYPTO-2 of the v0.6.0
/// review).
#[derive(Default)]
struct Captured {
    client: Option<[u8; 32]>,
    server: Option<[u8; 32]>,
}

impl Captured {
    /// Overwrites both secrets (volatile, not elided).
    fn wipe(&mut self) {
        if let Some(c) = self.client.as_mut() {
            c.zeroize();
        }
        if let Some(c) = self.server.as_mut() {
            c.zeroize();
        }
        self.client = None;
        self.server = None;
    }

    /// Both secrets, copied out (client, server); the capture is wiped.
    fn take(&mut self) -> Option<([u8; 32], [u8; 32])> {
        let out = self.client.zip(self.server);
        self.wipe();
        out
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The key log of one session (see [`Captured`]).
struct SecretCapture(SpinLock<Captured>);

impl Default for SecretCapture {
    fn default() -> Self {
        Self(SpinLock::new(Captured::default()))
    }
}

impl fmt::Debug for SecretCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretCapture")
    }
}

impl SecretCapture {
    fn take(&self) -> Option<([u8; 32], [u8; 32])> {
        self.0.lock().take()
    }

    fn wipe(&self) {
        self.0.lock().wipe();
    }
}

impl KeyLog for SecretCapture {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let Ok(s) = <[u8; 32]>::try_from(secret) else {
            return;
        };
        let mut g = self.0.lock();
        match label {
            "CLIENT_TRAFFIC_SECRET_0" => g.client = Some(s),
            "SERVER_TRAFFIC_SECRET_0" => g.server = Some(s),
            _ => {}
        }
    }

    fn will_log(&self, label: &str) -> bool {
        label == "CLIENT_TRAFFIC_SECRET_0" || label == "SERVER_TRAFFIC_SECRET_0"
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn wiped(c: &Captured) -> bool {
        c.client.is_none() && c.server.is_none()
    }

    /// Replaces the tests of the former global table (taken or dropped
    /// entries leave nothing behind): the capture is now one per session.
    #[test]
    fn a_taken_or_dropped_capture_leaves_nothing_behind() {
        let cap = SecretCapture::default();
        cap.log("CLIENT_TRAFFIC_SECRET_0", &[1; 32], &[0xc0; 32]);
        cap.log("SERVER_TRAFFIC_SECRET_0", &[1; 32], &[0xd0; 32]);
        // Other labels and wrong lengths are ignored.
        cap.log("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &[1; 32], &[0xee; 32]);
        cap.log("SERVER_TRAFFIC_SECRET_0", &[1; 32], &[0xee; 48]);
        assert_eq!(cap.take(), Some(([0xc0; 32], [0xd0; 32])));
        assert_eq!(cap.take(), None, "taken once");
        assert!(wiped(&cap.0.lock()));
        // Only one secret yields nothing and is still wiped.
        cap.log("CLIENT_TRAFFIC_SECRET_0", &[2; 32], &[0xc1; 32]);
        assert_eq!(cap.take(), None);
        assert!(wiped(&cap.0.lock()));
        // What Drop runs (the abandoned-handshake path) clears both.
        let mut c = Captured {
            client: Some([0xaa; 32]),
            server: Some([0xbb; 32]),
        };
        c.wipe();
        assert!(wiped(&c));
    }

    /// The client random plays no part: two sessions that log under the
    /// same random (an attacker can copy a victim's) keep their own secrets.
    #[test]
    fn sessions_do_not_share_secrets_even_with_the_same_random() {
        let (a, b) = (SecretCapture::default(), SecretCapture::default());
        for (cap, v) in [(&a, 1u8), (&b, 2u8)] {
            cap.log("CLIENT_TRAFFIC_SECRET_0", &[7; 32], &[v; 32]);
            cap.log("SERVER_TRAFFIC_SECRET_0", &[7; 32], &[v + 0x10; 32]);
        }
        assert_eq!(a.take(), Some(([1; 32], [0x11; 32])));
        assert_eq!(b.take(), Some(([2; 32], [0x12; 32])));
    }
}

// --- client certificate verification: roles and revocation ----------------

/// Which trust anchor role validated a client certificate (H1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    /// Normal device or service rights.
    Operational,
    /// Provisioning only: the broker restricts it to `provision/{id}/#`.
    Bootstrap,
}

/// The revoked serials, shared by every core's server and replaced at
/// runtime by the control channel (H1). Serials are normalised (no sign
/// byte, no leading zeros) and kept sorted.
pub struct RevocationList {
    list: SpinLock<Arc<Vec<Vec<u8>>>>,
}

impl RevocationList {
    pub fn new(serials: Vec<Vec<u8>>) -> Self {
        let mut serials: Vec<Vec<u8>> = serials.iter().map(|s| normalize_serial(s)).collect();
        serials.sort();
        serials.dedup();
        Self {
            list: SpinLock::new(Arc::new(serials)),
        }
    }

    /// From hex strings (the configuration's form); invalid entries are
    /// skipped (the build already rejected them).
    pub fn from_hex(hex: &[&str]) -> Self {
        Self::new(hex.iter().filter_map(|h| decode_hex(h)).collect())
    }

    /// Replaces the whole list.
    pub fn replace(&self, serials: Vec<Vec<u8>>) {
        let fresh = Self::new(serials);
        let list = fresh.snapshot();
        *self.list.lock() = list;
    }

    /// The current list (cheap: one reference count).
    pub fn snapshot(&self) -> Arc<Vec<Vec<u8>>> {
        self.list.lock().clone()
    }

    pub fn len(&self) -> usize {
        self.list.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `cert`'s serial is listed (a certificate without a readable
    /// serial counts as revoked).
    pub fn is_revoked(&self, cert: &[u8]) -> bool {
        let list = self.snapshot();
        identity::serial(cert).is_none_or(|s| list.binary_search(&normalize_serial(&s)).is_ok())
    }
}

/// A short, stable tag of a serial number, kept per connection so a newly
/// revoked serial finds its live connections without storing the serial
/// itself (8 bytes instead of up to 20). Equal serials give equal tags; a
/// collision only closes an unrelated connection, which then reconnects
/// and is verified in full.
pub fn serial_tag(serial: &[u8]) -> u64 {
    use sha2::Digest;
    let d = sha2::Sha256::digest(normalize_serial(serial));
    let mut b = [0u8; 8];
    for (o, i) in b.iter_mut().zip(d.iter()) {
        *o = *i;
    }
    u64::from_le_bytes(b)
}

/// Roles of recently verified end-entity certificates, by SHA-256 of the
/// DER, from verification until the handshake completes, bounded by
/// [`MAX_ROLES`]. A role that is evicted or missing is not trusted: the
/// chain is verified again at the end of the handshake (`client_identity`).
static ROLES: SpinLock<Vec<([u8; 32], CertRole)>> = SpinLock::new(Vec::new());

/// Bound on remembered roles (admission control keeps the real number of
/// handshakes in flight far lower).
const MAX_ROLES: usize = 4096;

fn cert_hash(der: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let d = sha2::Sha256::digest(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn record_role(der: &[u8], role: CertRole) {
    let h = cert_hash(der);
    let mut g = ROLES.lock();
    if let Some(e) = g.iter_mut().find(|e| e.0 == h) {
        e.1 = role;
        return;
    }
    if g.len() >= MAX_ROLES {
        g.remove(0);
    }
    g.push((h, role));
}

fn take_role(der: &[u8]) -> Option<CertRole> {
    let h = cert_hash(der);
    let mut g = ROLES.lock();
    let i = g.iter().position(|e| e.0 == h)?;
    Some(g.swap_remove(i).1)
}

#[derive(Debug)]
struct RoleVerifiers {
    operational: Arc<dyn ClientCertVerifier>,
    bootstrap: Option<Arc<dyn ClientCertVerifier>>,
    hints: Vec<DistinguishedName>,
}

impl RoleVerifiers {
    /// Verifies the chain against the operational anchors, then the
    /// bootstrap anchors. The first that accepts decides the role.
    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(ClientCertVerified, CertRole), rustls::Error> {
        match self
            .operational
            .verify_client_cert(end_entity, intermediates, now)
        {
            Ok(v) => Ok((v, CertRole::Operational)),
            Err(e) => match &self.bootstrap {
                Some(b) => b
                    .verify_client_cert(end_entity, intermediates, now)
                    .map(|v| (v, CertRole::Bootstrap))
                    // The operational error is the more useful one to log.
                    .map_err(|_| e),
                None => Err(e),
            },
        }
    }
}

struct RevocationAware {
    roles: Arc<RoleVerifiers>,
    revoked: Arc<RevocationList>,
}

impl fmt::Debug for RevocationAware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RevocationAware")
    }
}

impl ClientCertVerifier for RevocationAware {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.roles.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (ok, role) = timed(Stage::CertPath, || {
            self.roles.verify(end_entity, intermediates, now)
        })?;
        timed(Stage::CertChecks, || {
            if identity::serial(end_entity).is_none() {
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::BadEncoding,
                ));
            }
            if self.revoked.is_revoked(end_entity) {
                return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
            }
            record_role(end_entity, role);
            Ok(ok)
        })
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roles.operational.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.roles.operational.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.roles.operational.supported_verify_schemes()
    }
}

/// Constant-time equality for secrets (H2): the time depends only on the
/// lengths, never on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// --- server ------------------------------------------------------------------

/// Everything needed to build the server, typically from the build config.
pub struct ServerSetup<'a> {
    /// CA certificates (PEM, each may hold several) granting operational
    /// rights. At least one certificate in all.
    pub operational_ca_pems: &'a [&'a [u8]],
    /// CA certificates granting only the bootstrap role (may be empty).
    pub bootstrap_ca_pems: &'a [&'a [u8]],
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
    pub identity_field: IdentityField,
    pub resumption: bool,
    /// Revoked serials, shared with the control channel.
    pub revocations: Arc<RevocationList>,
    /// Session-ticket keys, shared by every core's server (H2).
    pub tickets: Arc<crate::ticket::TicketKeys>,
}

pub struct TlsServer {
    config: Arc<ServerConfig>,
    identity_field: IdentityField,
    revoked: Arc<RevocationList>,
    roles: Arc<RoleVerifiers>,
    /// A client certificate is required (mutual TLS). False only for
    /// [`TlsServer::new_server_only`].
    client_auth: bool,
}

/// Every certificate in `pems`, into one root store.
fn roots(pems: &[&[u8]]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for pem in pems {
        for c in CertificateDer::pem_slice_iter(pem) {
            let c = c.map_err(|_| TlsError::Config("CA PEM is invalid"))?;
            roots
                .add(c)
                .map_err(|_| TlsError::Config("CA certificate rejected"))?;
        }
    }
    // Certificates signed by a trust anchor are verified against a fixed-base
    // table of its key (ADR-111); an anchor that is not P-256 just has none.
    for anchor in &roots.roots {
        crate::provider::register_issuer(anchor.subject_public_key_info.as_ref());
    }
    Ok(roots)
}

/// Builds the verification tables of every trust anchor in `pems` (both roles)
/// now, once, instead of in the first `TlsServer::new` of whichever core comes
/// first, and returns the registry's (tables, heap bytes requested). The boot
/// calls it before it measures the heap the reserve is set against, so the
/// tables are part of the idle heap it reports (ADR-261). Invalid PEMs are
/// left to `TlsServer::new` to report.
pub fn prepare_trust_anchors(pems: &[&[&[u8]]]) -> (usize, usize) {
    for p in pems {
        let _ = roots(p);
    }
    crate::provider::issuer_tables()
}

/// Serial numbers compare without the DER sign byte / leading zeros
/// (OpenSSL prints them that way).
fn normalize_serial(s: &[u8]) -> Vec<u8> {
    let first = s.iter().position(|&b| b != 0).unwrap_or(s.len());
    s.get(first..).unwrap_or(&[]).to_vec()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| {
            s.get(2 * i..2 * i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

impl TlsServer {
    /// The mutual-TLS server: every client proves an identity with a
    /// certificate of a configured trust anchor.
    pub fn new(setup: &ServerSetup<'_>) -> Result<Self, TlsError> {
        Self::build(setup, true)
    }

    /// A server that asks for no client certificate (ADR-272), for the
    /// WebSocket listener's password mode, where a browser logs in with an
    /// MQTT user name and password inside the TLS session instead. The
    /// session reports [`Event::EstablishedServerOnly`], never an identity;
    /// the caller must authenticate the client some other way. No session
    /// tickets are issued (a ticket of this server must never resume on the
    /// mutual-TLS one, and resumption is not worth a second key set here).
    pub fn new_server_only(setup: &ServerSetup<'_>) -> Result<Self, TlsError> {
        Self::build(setup, false)
    }

    fn build(setup: &ServerSetup<'_>, client_auth: bool) -> Result<Self, TlsError> {
        let provider = Arc::new(crate::provider::provider());
        let operational = roots(setup.operational_ca_pems)?;
        if operational.is_empty() {
            return Err(TlsError::Config("no operational CA certificate"));
        }
        let bootstrap = roots(setup.bootstrap_ca_pems)?;
        let mut hints: Vec<DistinguishedName> = operational.subjects();
        hints.extend(bootstrap.subjects());
        let verifier_of = |r: RootCertStore| {
            WebPkiClientVerifier::builder_with_provider(Arc::new(r), provider.clone())
                .build()
                .map_err(|_| TlsError::Config("client verifier"))
        };
        let roles = Arc::new(RoleVerifiers {
            operational: verifier_of(operational)?,
            bootstrap: if bootstrap.is_empty() {
                None
            } else {
                Some(verifier_of(bootstrap)?)
            },
            hints,
        });
        let revoked = setup.revocations.clone();
        let verifier = Arc::new(RevocationAware {
            roles: roles.clone(),
            revoked: revoked.clone(),
        });
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(setup.cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| TlsError::Config("server certificate PEM is invalid"))?;
        let key = PrivateKeyDer::from_pem_slice(setup.key_pem)
            .map_err(|_| TlsError::Config("server key PEM is invalid"))?;
        let versions = ServerConfig::builder_with_details(provider, Arc::new(KernelTime))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsError::Config("protocol versions"))?;
        let with_auth = if client_auth {
            versions.with_client_cert_verifier(verifier)
        } else {
            versions.with_no_client_auth()
        };
        let mut config = with_auth
            .with_single_cert(chain, key)
            .map_err(|_| TlsError::Config("server certificate/key mismatch or unsupported key"))?;
        config.enable_secret_extraction = true;
        // Each session installs its own capture (`accept`, ADR-340).
        config.max_early_data_size = 0;
        if setup.resumption && client_auth {
            config.ticketer = Arc::new(crate::ticket::Ticketer(setup.tickets.clone()));
            config.send_tls13_tickets = 1;
        } else {
            config.send_tls13_tickets = 0;
        }
        Ok(Self {
            config: Arc::new(config),
            identity_field: setup.identity_field,
            revoked,
            roles,
            client_auth,
        })
    }

    pub fn accept(&self) -> Result<TlsSession, TlsError> {
        // A shallow copy of the shared config (reference counts and a few
        // empty vectors) whose key log is this session's own (ADR-340).
        let capture = Arc::new(SecretCapture::default());
        let mut config = ServerConfig::clone(&self.config);
        config.key_log = capture.clone();
        let conn = UnbufferedServerConnection::new(Arc::new(config))?;
        Ok(TlsSession {
            state: State::Handshake(Box::new(Hs {
                conn,
                inbuf: Vec::new(),
                checked: false,
                capture,
                revoked: self.revoked.clone(),
                roles: self.roles.clone(),
            })),
            identity_field: self.identity_field,
            client_auth: self.client_auth,
        })
    }
}

/// Emits what rustls queued after a handshake error (its fatal alert).
fn flush_alert(conn: &mut UnbufferedServerConnection, inbuf: &mut Vec<u8>, tx: &mut Vec<u8>) {
    for _ in 0..4 {
        let UnbufferedStatus { discard, state } = conn.process_tls_records(inbuf);
        let Ok(ConnectionState::EncodeTlsData(mut s)) = state else {
            return;
        };
        let mut buf = [0u8; 64];
        let n = s.encode(&mut buf).ok();
        drop(s);
        inbuf.drain(..discard.min(inbuf.len()));
        match n {
            Some(n) => tx.extend_from_slice(buf.get(..n).unwrap_or(&[])),
            None => return,
        }
    }
}

struct Hs {
    conn: UnbufferedServerConnection,
    inbuf: Vec<u8>,
    /// The first record header looked like a ClientHello.
    checked: bool,
    /// This handshake's traffic secrets, wiped when `Hs` is dropped.
    capture: Arc<SecretCapture>,
    /// For resumed sessions: no certificate is verified then, so the one
    /// in the ticket is checked against the list here.
    revoked: Arc<RevocationList>,
    /// For resumed sessions: the role is decided again.
    roles: Arc<RoleVerifiers>,
}

struct Open {
    rec: RecordLayer,
    /// An incomplete record, if any (absent on an idle connection).
    #[allow(clippy::box_collection)]
    inbuf: Option<Box<Vec<u8>>>,
}

/// The record state of an established session lives inline (M15): the
/// session sits in its owner's slab entry, so it costs its exact size
/// instead of a separate heap block rounded up to 128 bytes. Handshakes are
/// transient and stay boxed.
#[allow(clippy::large_enum_variant)]
enum State {
    Handshake(Box<Hs>),
    Open(Open),
    Closed,
}

/// What happened while processing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    None,
    Established {
        identity: String,
        suite: &'static str,
        resumed: bool,
        role: CertRole,
        /// [`serial_tag`] of the client certificate's serial.
        serial_tag: u64,
    },
    /// The handshake of a [`TlsServer::new_server_only`] session finished:
    /// the channel is encrypted and the server authenticated, the client is
    /// not (ADR-272).
    EstablishedServerOnly {
        suite: &'static str,
    },
    /// The peer closed the TLS session (close_notify).
    PeerClosed,
}

pub struct TlsSession {
    state: State,
    identity_field: IdentityField,
    /// A client certificate was required ([`TlsServer::client_auth`]).
    client_auth: bool,
}

/// Whether the input starts like a ClientHello: a handshake record (type
/// 22, version 3.x) whose body starts with a ClientHello (type 1), or `None`
/// until the first 6 bytes are in. Only the first fragment's first byte is
/// looked at; the ClientHello itself may be fragmented over several
/// records (RFC 8446 §5.1), which rustls reassembles.
fn looks_like_client_hello(buf: &[u8]) -> Option<bool> {
    if buf.len() < 6 {
        return None;
    }
    Some(buf.first() == Some(&22) && buf.get(1) == Some(&3) && buf.get(5) == Some(&1))
}

impl TlsSession {
    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Open(_))
    }

    /// Bytes buffered for an incomplete record or handshake flight.
    pub fn buffered(&self) -> usize {
        match &self.state {
            State::Handshake(h) => h.inbuf.len(),
            State::Open(o) => o.inbuf.as_ref().map_or(0, |b| b.len()),
            State::Closed => 0,
        }
    }

    /// Feeds network bytes. TLS output goes to `tx`, decrypted application
    /// data to `app`.
    pub fn input(
        &mut self,
        data: &[u8],
        tx: &mut Vec<u8>,
        app: &mut Vec<u8>,
    ) -> Result<Event, TlsError> {
        match &mut self.state {
            State::Handshake(hs) => {
                hs.inbuf.extend_from_slice(data);
                if hs.inbuf.len() > record::HEADER + record::MAX_CIPHERTEXT * 4 {
                    return Err(TlsError::Handshake("handshake flight too large".into()));
                }
                if !hs.checked {
                    match looks_like_client_hello(&hs.inbuf) {
                        Some(true) => hs.checked = true,
                        Some(false) => return Err(TlsError::NotTls),
                        None => return Ok(Event::None),
                    }
                }
                self.drive_handshake(tx, app)
            }
            State::Open(o) => {
                o.inbuf
                    .get_or_insert_with(Default::default)
                    .extend_from_slice(data);
                let ev = match drain_records(o, tx, app) {
                    Ok(ev) => ev,
                    Err(e) => {
                        // A fatal alert naming the error (RFC 8446 §5, §6),
                        // then nothing more: `close` sends no close_notify.
                        if let TlsError::Record(r) = &e
                            && let Some(desc) = r.alert()
                        {
                            let _ = o.rec.alert(desc, tx);
                        }
                        self.state = State::Closed;
                        return Err(e);
                    }
                };
                // On close_notify the state stays open until `close`, which
                // answers with our own close_notify (RFC 8446 §6.1).
                Ok(ev)
            }
            State::Closed => Ok(Event::PeerClosed),
        }
    }

    fn drive_handshake(&mut self, tx: &mut Vec<u8>, app: &mut Vec<u8>) -> Result<Event, TlsError> {
        let State::Handshake(hs) = &mut self.state else {
            return Ok(Event::None);
        };
        let mut done = false;
        loop {
            let UnbufferedStatus { mut discard, state } =
                hs.conn.process_tls_records(&mut hs.inbuf);
            let state = match state {
                Ok(s) => s,
                Err(e) => {
                    hs.capture.wipe();
                    // rustls queued its fatal alert; it comes out on the
                    // next call (RFC 8446 §6: the peer learns why). The
                    // consumed input goes first, as rustls expects.
                    hs.inbuf.drain(..discard.min(hs.inbuf.len()));
                    flush_alert(&mut hs.conn, &mut hs.inbuf, tx);
                    return Err(e.into());
                }
            };
            let mut blocked = false;
            match state {
                ConnectionState::EncodeTlsData(mut s) => {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match s.encode(&mut buf) {
                            Ok(n) => {
                                tx.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                                break;
                            }
                            Err(EncodeError::InsufficientSize(need)) => {
                                buf.resize(need.required_size, 0)
                            }
                            Err(_) => return Err(TlsError::Internal("encode")),
                        }
                    }
                }
                ConnectionState::TransmitTlsData(s) => s.done(),
                ConnectionState::BlockedHandshake => blocked = true,
                ConnectionState::ReadTraffic(mut s) => {
                    while let Some(r) = s.next_record() {
                        let r = r?;
                        app.extend_from_slice(r.payload);
                        discard += r.discard;
                    }
                }
                ConnectionState::WriteTraffic(_) => done = true,
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Ok(Event::PeerClosed);
                }
                _ => return Err(TlsError::Handshake("unexpected state".into())),
            }
            if discard > 0 {
                hs.inbuf.drain(..discard.min(hs.inbuf.len()));
            }
            if done || blocked {
                break;
            }
        }
        if !done {
            return Ok(Event::None);
        }
        timed(Stage::Finish, || self.finish_handshake(tx, app))
    }

    fn finish_handshake(&mut self, tx: &mut Vec<u8>, app: &mut Vec<u8>) -> Result<Event, TlsError> {
        let State::Handshake(hs) = core::mem::replace(&mut self.state, State::Closed) else {
            return Err(TlsError::Internal("state"));
        };
        let Hs {
            conn,
            inbuf,
            checked,
            capture,
            revoked,
            roles,
        } = *hs;
        if !checked {
            return Err(TlsError::NotTls);
        }
        // Every exit below drops `capture`, which wipes the secrets.
        let resumed = conn.handshake_kind() == Some(HandshakeKind::Resumed);
        // Without client authentication (ADR-272) there is no certificate to
        // check; a session of such a server never resumes (no tickets).
        let client = if self.client_auth {
            Some(Self::client_identity(
                &conn,
                resumed,
                &revoked,
                &roles,
                self.identity_field,
            )?)
        } else {
            None
        };
        let (secrets, kernel) = conn.dangerous_into_kernel_connection()?;
        drop(kernel);
        let (rx_secret, tx_secret) = capture
            .take()
            .ok_or(TlsError::Internal("traffic secrets not captured"))?;
        let (suite, rx_key, rx_iv, tx_key, tx_iv) = match (&secrets.rx.1, &secrets.tx.1) {
            (
                ConnectionTrafficSecrets::Aes128Gcm { key: rk, iv: ri },
                ConnectionTrafficSecrets::Aes128Gcm { key: tk, iv: ti },
            ) => (
                Suite::Aes128Gcm,
                rk.as_ref(),
                ri.as_ref(),
                tk.as_ref(),
                ti.as_ref(),
            ),
            (
                ConnectionTrafficSecrets::Chacha20Poly1305 { key: rk, iv: ri },
                ConnectionTrafficSecrets::Chacha20Poly1305 { key: tk, iv: ti },
            ) => (
                Suite::ChaCha20Poly1305,
                rk.as_ref(),
                ri.as_ref(),
                tk.as_ref(),
                ti.as_ref(),
            ),
            _ => return Err(TlsError::Internal("unsupported suite")),
        };
        let rec = RecordLayer::new(suite, rx_secret, secrets.rx.0, tx_secret, secrets.tx.0)
            .ok_or(TlsError::Internal("key derivation"))?;
        // The captured secrets must reproduce rustls's keys exactly.
        // Constant time (H2): every operand is a secret.
        let iv_eq = |iv: Option<[u8; 12]>, want: &[u8]| iv.is_some_and(|v| ct_eq(&v, want));
        let same = ct_eq(rec.rx().key(suite).as_slice(), rx_key)
            & iv_eq(rec.rx().iv(), rx_iv)
            & ct_eq(rec.tx().key(suite).as_slice(), tx_key)
            & iv_eq(rec.tx().iv(), tx_iv);
        if !same {
            return Err(TlsError::Internal("captured secrets do not match"));
        }
        let inbuf = (!inbuf.is_empty()).then(|| Box::new(inbuf));
        let mut open = Open { rec, inbuf };
        let ev = drain_records(&mut open, tx, app)?;
        self.state = if ev == Event::PeerClosed {
            State::Closed
        } else {
            State::Open(open)
        };
        Ok(match client {
            Some((identity, role, serial_tag)) => Event::Established {
                identity,
                suite: suite.name(),
                resumed,
                role,
                serial_tag,
            },
            None => Event::EstablishedServerOnly {
                suite: suite.name(),
            },
        })
    }

    /// The client certificate's identity, role and serial tag, checked again
    /// for a resumed session.
    fn client_identity(
        conn: &UnbufferedServerConnection,
        resumed: bool,
        revoked: &RevocationList,
        roles: &RoleVerifiers,
        identity_field: IdentityField,
    ) -> Result<(String, CertRole, u64), TlsError> {
        // A ticket outlives a revocation (it is issued before, and the list
        // changes with a new image of possibly the same version): resumed
        // sessions are checked again (M16). A full handshake is checked
        // again too (ADR-361): the list was read when the client's
        // Certificate was verified, and a revocation applied between that
        // and its Finished (a client may hold its flight back for up to the
        // handshake timeout) would otherwise never reach this connection,
        // since the cores scan only connections that were live when the
        // control epoch changed.
        let peer = conn.peer_certificates().unwrap_or(&[]);
        let Some(ee) = peer.first() else {
            return Err(TlsError::NoIdentity);
        };
        if revoked.is_revoked(ee) {
            return Err(TlsError::Handshake(if resumed {
                "resumed session of a revoked certificate".into()
            } else {
                "certificate revoked during the handshake".into()
            }));
        }
        // A full handshake recorded the role during verification. A resumed
        // one verified nothing: the chain from the ticket is checked again
        // now, which also refuses a certificate that has expired since or
        // whose CA was removed from this image.
        let role = match take_role(ee) {
            Some(r) if !resumed => r,
            _ => {
                let now = KernelTime
                    .current_time()
                    .ok_or_else(|| TlsError::Handshake("no wall clock".into()))?;
                roles
                    .verify(ee, peer.get(1..).unwrap_or(&[]), now)
                    .map(|(_, r)| r)?
            }
        };
        let serial_tag = identity::serial(ee).map_or(0, |s| serial_tag(&s));
        let ident = identity::identity(ee, identity_field);
        Ok((ident.ok_or(TlsError::NoIdentity)?, role, serial_tag))
    }

    /// Encrypts application data for the peer.
    pub fn send(&mut self, data: &[u8], tx: &mut Vec<u8>) -> Result<(), TlsError> {
        match &mut self.state {
            State::Open(o) => Ok(o.rec.send(data, tx)?),
            _ => Err(TlsError::Internal("not established")),
        }
    }

    /// Sends close_notify (if established) and stops.
    pub fn close(&mut self, tx: &mut Vec<u8>) {
        if let State::Open(o) = &mut self.state {
            let _ = o.rec.close(tx);
        }
        self.state = State::Closed;
    }

    /// Per-connection record layer size (for memory accounting).
    pub fn record_state_size() -> usize {
        core::mem::size_of::<RecordLayer>()
    }
}

fn drain_records(o: &mut Open, tx: &mut Vec<u8>, app: &mut Vec<u8>) -> Result<Event, TlsError> {
    let Some(mut buf) = o.inbuf.take() else {
        return Ok(Event::None);
    };
    let mut off = 0usize;
    let mut ev = Event::None;
    let r = (|| {
        while let Some(rest) = buf.get(off..) {
            let Some(n) = record::record_len(rest) else {
                break;
            };
            if n > record::HEADER + record::MAX_CIPHERTEXT {
                return Err(TlsError::Record(RecordError::Overflow));
            }
            let Some(rec) = buf.get_mut(off..off + n) else {
                break;
            };
            match o.rec.open(rec, tx)? {
                Opened::Data(r) => app.extend_from_slice(rec.get(r).unwrap_or(&[])),
                Opened::Closed => {
                    ev = Event::PeerClosed;
                    off += n;
                    break;
                }
                Opened::KeyUpdated { .. } => {}
            }
            off += n;
        }
        Ok(())
    })();
    buf.drain(..off.min(buf.len()));
    // An idle connection keeps no buffer (M15).
    if !buf.is_empty() {
        o.inbuf = Some(buf);
    }
    r.map(|()| ev)
}

#[cfg(test)]
mod size_tests {
    /// An established session costs its inline size and nothing else
    /// while idle (M15, ADR-034; PROMPT §6 target ≤ 128 B).
    #[test]
    fn established_state_stays_small() {
        assert!(core::mem::size_of::<super::Open>() <= 96);
        assert!(
            core::mem::size_of::<super::TlsSession>() <= 104,
            "{}",
            core::mem::size_of::<super::TlsSession>()
        );
    }
}
