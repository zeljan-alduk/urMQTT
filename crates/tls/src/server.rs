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
use rustls::server::{ProducesTickets, UnbufferedServerConnection, WebPkiClientVerifier};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::{
    CertificateError, ConnectionTrafficSecrets, DigitallySignedStruct, DistinguishedName,
    HandshakeKind, KeyLog, RootCertStore, ServerConfig, SignatureScheme,
};
use urmqtt_sync::sync::SpinLock;

use crate::identity::{self, IdentityField};
use crate::record::{self, Opened, RecordError, RecordLayer, Suite};

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

/// (ClientHello random, client traffic secret, server traffic secret).
type CapturedSecrets = ([u8; 32], Option<[u8; 32]>, Option<[u8; 32]>);

/// Traffic secrets by ClientHello random, while handshakes are in flight.
#[derive(Default)]
struct Captured {
    entries: Vec<CapturedSecrets>,
}

/// Bound on concurrently captured handshakes (admission control keeps the
/// real number far lower).
const MAX_CAPTURED: usize = 4096;

static SECRETS: SpinLock<Captured> = SpinLock::new(Captured {
    entries: Vec::new(),
});

#[derive(Debug)]
struct SecretCapture;

impl KeyLog for SecretCapture {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let (Ok(cr), Ok(s)) = (
            <[u8; 32]>::try_from(client_random),
            <[u8; 32]>::try_from(secret),
        ) else {
            return;
        };
        let client = label == "CLIENT_TRAFFIC_SECRET_0";
        if !client && label != "SERVER_TRAFFIC_SECRET_0" {
            return;
        }
        let mut g = SECRETS.lock();
        let idx = match g.entries.iter().position(|e| e.0 == cr) {
            Some(i) => i,
            None => {
                if g.entries.len() >= MAX_CAPTURED {
                    g.entries.remove(0);
                }
                g.entries.push((cr, None, None));
                g.entries.len() - 1
            }
        };
        if let Some(e) = g.entries.get_mut(idx) {
            if client {
                e.1 = Some(s);
            } else {
                e.2 = Some(s);
            }
        }
    }

    fn will_log(&self, label: &str) -> bool {
        label == "CLIENT_TRAFFIC_SECRET_0" || label == "SERVER_TRAFFIC_SECRET_0"
    }
}

fn take_secrets(client_random: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let mut g = SECRETS.lock();
    let i = g.entries.iter().position(|e| &e.0 == client_random)?;
    let (_, c, s) = g.entries.swap_remove(i);
    Some((c?, s?))
}

fn drop_secrets(client_random: &[u8; 32]) {
    let _ = take_secrets(client_random);
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
/// DER, from verification until the handshake completes. Bounded like the
/// captured secrets.
static ROLES: SpinLock<Vec<([u8; 32], CertRole)>> = SpinLock::new(Vec::new());

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
    if g.len() >= MAX_CAPTURED {
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
        let (ok, role) = self.roles.verify(end_entity, intermediates, now)?;
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

// --- session tickets --------------------------------------------------------

/// Stateless TLS 1.3 tickets: ChaCha20-Poly1305 under a key derived from the
/// embedded server key and the image version (rotates with every image).
struct Ticketer {
    key: [u8; 32],
    lifetime: u32,
}

impl fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ticketer")
    }
}

impl ProducesTickets for Ticketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        let mut nonce = [0u8; 12];
        crate::rng::fill_global(&mut nonce).ok()?;
        let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key).ok()?;
        let mut body = plain.to_vec();
        c.encrypt_in_place((&nonce).into(), b"urmqtt ticket", &mut body)
            .ok()?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&body);
        Some(out)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit};
        let (nonce, body) = cipher.split_at_checked(12)?;
        let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key).ok()?;
        let mut body = body.to_vec();
        c.decrypt_in_place(nonce.into(), b"urmqtt ticket", &mut body)
            .ok()?;
        Some(body)
    }
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
    /// Mixed into the ticket key so a new image invalidates old tickets.
    pub version: &'a str,
}

pub struct TlsServer {
    config: Arc<ServerConfig>,
    identity_field: IdentityField,
    revoked: Arc<RevocationList>,
    roles: Arc<RoleVerifiers>,
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
    Ok(roots)
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
    pub fn new(setup: &ServerSetup<'_>) -> Result<Self, TlsError> {
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
        let ticket_key = ticket_key(&key, setup.version);
        let mut config = ServerConfig::builder_with_details(provider, Arc::new(KernelTime))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsError::Config("protocol versions"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|_| TlsError::Config("server certificate/key mismatch or unsupported key"))?;
        config.enable_secret_extraction = true;
        config.key_log = Arc::new(SecretCapture);
        config.max_early_data_size = 0;
        if setup.resumption {
            config.ticketer = Arc::new(Ticketer {
                key: ticket_key,
                lifetime: 24 * 3600,
            });
            config.send_tls13_tickets = 1;
        } else {
            config.send_tls13_tickets = 0;
        }
        Ok(Self {
            config: Arc::new(config),
            identity_field: setup.identity_field,
            revoked,
            roles,
        })
    }

    pub fn accept(&self) -> Result<TlsSession, TlsError> {
        let conn = UnbufferedServerConnection::new(self.config.clone())?;
        Ok(TlsSession {
            state: State::Handshake(Box::new(Hs {
                conn,
                inbuf: Vec::new(),
                random: None,
                revoked: self.revoked.clone(),
                roles: self.roles.clone(),
            })),
            identity_field: self.identity_field,
        })
    }
}

fn ticket_key(key: &PrivateKeyDer<'_>, version: &str) -> [u8; 32] {
    let ikm: &[u8] = match key {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der(),
        PrivateKeyDer::Sec1(k) => k.secret_sec1_der(),
        PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der(),
        _ => &[],
    };
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(version.as_bytes()), ikm);
    let mut out = [0u8; 32];
    let _ = hk.expand(b"urmqtt session ticket key v1", &mut out);
    out
}

struct Hs {
    conn: UnbufferedServerConnection,
    inbuf: Vec<u8>,
    random: Option<[u8; 32]>,
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
    /// The peer closed the TLS session (close_notify).
    PeerClosed,
}

pub struct TlsSession {
    state: State,
    identity_field: IdentityField,
}

/// ClientHello.random from the first record (RFC 8446 §4.1.2).
fn client_random(buf: &[u8]) -> Option<Result<[u8; 32], TlsError>> {
    if buf.len() < 43 {
        return None;
    }
    let ok = buf.first() == Some(&22) && buf.get(1) == Some(&3) && buf.get(5) == Some(&1);
    if !ok {
        return Some(Err(TlsError::NotTls));
    }
    let r: Option<[u8; 32]> = buf.get(11..43).and_then(|s| s.try_into().ok());
    Some(r.ok_or(TlsError::NotTls))
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
                if hs.random.is_none() {
                    match client_random(&hs.inbuf) {
                        Some(Ok(r)) => hs.random = Some(r),
                        Some(Err(e)) => return Err(e),
                        None => return Ok(Event::None),
                    }
                }
                self.drive_handshake(tx, app)
            }
            State::Open(o) => {
                o.inbuf
                    .get_or_insert_with(Default::default)
                    .extend_from_slice(data);
                let ev = drain_records(o, tx, app)?;
                if ev == Event::PeerClosed {
                    self.state = State::Closed;
                }
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
                    if let Some(r) = hs.random {
                        drop_secrets(&r);
                    }
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
        self.finish_handshake(tx, app)
    }

    fn finish_handshake(&mut self, tx: &mut Vec<u8>, app: &mut Vec<u8>) -> Result<Event, TlsError> {
        let State::Handshake(hs) = core::mem::replace(&mut self.state, State::Closed) else {
            return Err(TlsError::Internal("state"));
        };
        let Hs {
            conn,
            inbuf,
            random,
            revoked,
            roles,
        } = *hs;
        let random = random.ok_or(TlsError::NotTls)?;
        let resumed = conn.handshake_kind() == Some(HandshakeKind::Resumed);
        // A ticket outlives a revocation (it is issued before, and the list
        // changes with a new image of possibly the same version): resumed
        // sessions are checked again (M16).
        let peer = conn.peer_certificates().unwrap_or(&[]);
        let Some(ee) = peer.first() else {
            return Err(TlsError::NoIdentity);
        };
        if resumed && revoked.is_revoked(ee) {
            return Err(TlsError::Handshake(
                "resumed session of a revoked certificate".into(),
            ));
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
        let ident = identity::identity(ee, self.identity_field);
        let (secrets, kernel) = conn.dangerous_into_kernel_connection()?;
        drop(kernel);
        let (rx_secret, tx_secret) =
            take_secrets(&random).ok_or(TlsError::Internal("traffic secrets not captured"))?;
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
        if rec.rx().key(suite).as_slice() != rx_key
            || rec.rx().iv().as_ref().map(|v| v.as_slice()) != Some(rx_iv)
            || rec.tx().key(suite).as_slice() != tx_key
            || rec.tx().iv().as_ref().map(|v| v.as_slice()) != Some(tx_iv)
        {
            return Err(TlsError::Internal("captured secrets do not match"));
        }
        let identity = ident.ok_or(TlsError::NoIdentity)?;
        let inbuf = (!inbuf.is_empty()).then(|| Box::new(inbuf));
        let mut open = Open { rec, inbuf };
        let ev = drain_records(&mut open, tx, app)?;
        self.state = if ev == Event::PeerClosed {
            State::Closed
        } else {
            State::Open(open)
        };
        Ok(Event::Established {
            identity,
            suite: suite.name(),
            resumed,
            role,
            serial_tag,
        })
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
                return Err(TlsError::Record(RecordError::BadHeader));
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
