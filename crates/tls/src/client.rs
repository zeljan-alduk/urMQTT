//! A minimal TLS 1.3 client on rustls' unbuffered API and our crypto
//! provider.
//!
//! Two uses:
//! - the in-kernel self-tests and host tests ([`TlsClient::new`]: a client
//!   certificate, the server name `localhost`);
//! - the kernel's outbound connections (NEXT-7, ADR-317,
//!   [`TlsClient::verifying`]): no client certificate, the server's chain
//!   verified against the configured trust anchors only (never a system or
//!   built-in root store), its name against the configured one (a DNS name,
//!   or an IP address that must be in the certificate's IP SANs), and the
//!   validity against the kernel's wall clock: without one the handshake
//!   fails (fail closed). TLS 1.3 only, no resumption, no early data.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::client::UnbufferedClientConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{ClientConfig, RootCertStore};

use crate::server::{KernelTime, TlsError};

/// Most bytes of an unfinished record a session holds: a full TLS 1.3
/// record (16 KiB of plaintext, 256 bytes of expansion, the 5-byte header).
/// More means the peer is not speaking TLS.
pub const MAX_PENDING_IN: usize = 16 * 1024 + 256 + 5;

pub struct ClientSetup<'a> {
    pub ca_pem: &'a [u8],
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
}

pub struct TlsClient {
    config: Arc<ClientConfig>,
}

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
    if roots.is_empty() {
        return Err(TlsError::Config("no trust anchor"));
    }
    Ok(roots)
}

impl TlsClient {
    pub fn new(setup: &ClientSetup<'_>) -> Result<Self, TlsError> {
        let provider = Arc::new(crate::provider::provider());
        let roots = roots(&[setup.ca_pem])?;
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(setup.cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| TlsError::Config("client certificate PEM is invalid"))?;
        let key = PrivateKeyDer::from_pem_slice(setup.key_pem)
            .map_err(|_| TlsError::Config("client key PEM is invalid"))?;
        let mut config = ClientConfig::builder_with_details(provider, Arc::new(KernelTime))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsError::Config("protocol versions"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .map_err(|_| TlsError::Config("client certificate/key mismatch or unsupported key"))?;
        // Every connection is a full handshake.
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// A client for the kernel's outbound connections (ADR-317): the
    /// server is verified against `anchors` (PEM, one or more certificates
    /// each) and nothing else; no client certificate is offered.
    pub fn verifying(anchors: &[&[u8]]) -> Result<Self, TlsError> {
        let provider = Arc::new(crate::provider::provider());
        let mut config = ClientConfig::builder_with_details(provider, Arc::new(KernelTime))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsError::Config("protocol versions"))?
            .with_root_certificates(roots(anchors)?)
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// A new connection to `localhost` (the server certificate's name).
    pub fn connect(&self) -> Result<ClientSession, TlsError> {
        self.connect_to("localhost")
    }

    /// A new connection to the server called `name`: a DNS name, or an
    /// IPv4 or IPv6 literal that the certificate must name as an IP SAN.
    pub fn connect_to(&self, name: &str) -> Result<ClientSession, TlsError> {
        let name =
            ServerName::try_from(name.to_string()).map_err(|_| TlsError::Config("server name"))?;
        let conn = UnbufferedClientConnection::new(self.config.clone(), name)?;
        Ok(ClientSession {
            conn: Box::new(conn),
            inbuf: Vec::new(),
            outbox: Vec::new(),
            established: false,
            close_pending: false,
            closed: false,
        })
    }
}

pub struct ClientSession {
    conn: Box<UnbufferedClientConnection>,
    inbuf: Vec<u8>,
    /// Application data waiting for the handshake to finish.
    outbox: Vec<u8>,
    established: bool,
    /// [`ClientSession::close`] was called: a close_notify follows the data.
    close_pending: bool,
    /// The connection is closed (close_notify sent or received).
    closed: bool,
}

impl ClientSession {
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// The TLS connection is over: our close_notify went out or the peer's
    /// arrived. Nothing more can be sent.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Application bytes queued and not yet encrypted.
    pub fn pending(&self) -> usize {
        self.outbox.len()
    }

    /// Queues application data (sent as soon as the handshake allows).
    pub fn send(&mut self, data: &[u8]) {
        if !self.closed && !self.close_pending {
            self.outbox.extend_from_slice(data);
        }
    }

    /// Queues `data` and encrypts what can go now into `tx`.
    pub fn write(&mut self, data: &[u8], tx: &mut Vec<u8>) -> Result<(), TlsError> {
        self.send(data);
        self.flush(tx)
    }

    /// Encrypts what is queued into `tx`, if the handshake is done.
    pub fn flush(&mut self, tx: &mut Vec<u8>) -> Result<(), TlsError> {
        if !self.established || self.closed {
            return Ok(());
        }
        let mut ignored = Vec::new();
        self.input(&[], tx, &mut ignored)
    }

    /// Ends the connection after the queued data: a close_notify alert goes
    /// out with the next [`ClientSession::flush`] (at once if established).
    pub fn close(&mut self, tx: &mut Vec<u8>) -> Result<(), TlsError> {
        self.close_pending = true;
        self.flush(tx)
    }

    /// Feeds bytes from the server (none to start the handshake). Appends
    /// what to send to `tx` and decrypted application data to `app`.
    pub fn input(
        &mut self,
        data: &[u8],
        tx: &mut Vec<u8>,
        app: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        if self.closed {
            return Ok(());
        }
        self.inbuf.extend_from_slice(data);
        loop {
            let UnbufferedStatus { mut discard, state } =
                self.conn.process_tls_records(&mut self.inbuf);
            let mut stop = false;
            match state? {
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
                ConnectionState::BlockedHandshake => stop = true,
                ConnectionState::ReadTraffic(mut s) => {
                    while let Some(r) = s.next_record() {
                        let r = r?;
                        app.extend_from_slice(r.payload);
                        discard += r.discard;
                    }
                }
                ConnectionState::WriteTraffic(mut w) => {
                    self.established = true;
                    if !self.outbox.is_empty() {
                        let mut buf = vec![0u8; self.outbox.len() + 64];
                        loop {
                            match w.encrypt(&self.outbox, &mut buf) {
                                Ok(n) => {
                                    tx.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                                    break;
                                }
                                Err(EncryptError::InsufficientSize(need)) => {
                                    buf.resize(need.required_size, 0)
                                }
                                Err(_) => return Err(TlsError::Internal("encrypt")),
                            }
                        }
                        self.outbox.clear();
                    }
                    if self.close_pending {
                        let mut buf = vec![0u8; 64];
                        loop {
                            match w.queue_close_notify(&mut buf) {
                                Ok(n) => {
                                    tx.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                                    break;
                                }
                                Err(EncryptError::InsufficientSize(need)) => {
                                    buf.resize(need.required_size, 0)
                                }
                                Err(_) => return Err(TlsError::Internal("close_notify")),
                            }
                        }
                        self.closed = true;
                    }
                    stop = true;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    self.closed = true;
                    stop = true;
                }
                _ => stop = true,
            }
            if discard > 0 {
                self.inbuf.drain(..discard.min(self.inbuf.len()));
            }
            if stop {
                // What is left is an unfinished record; a peer that sends
                // more than one record's worth of it is not speaking TLS.
                if self.inbuf.len() > MAX_PENDING_IN {
                    self.closed = true;
                    return Err(TlsError::NotTls);
                }
                return Ok(());
            }
        }
    }
}
