//! A minimal TLS 1.3 client with a client certificate, on rustls'
//! unbuffered API and our crypto provider. Used by in-kernel self-tests
//! (`test=dp-bench` drives full handshakes against the server in memory)
//! and by host tests.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::client::UnbufferedClientConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::{ClientConfig, RootCertStore};

use crate::server::{KernelTime, TlsError};

pub struct ClientSetup<'a> {
    pub ca_pem: &'a [u8],
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
}

pub struct TlsClient {
    config: Arc<ClientConfig>,
}

impl TlsClient {
    pub fn new(setup: &ClientSetup<'_>) -> Result<Self, TlsError> {
        let provider = Arc::new(crate::provider::provider());
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(setup.ca_pem) {
            let c = c.map_err(|_| TlsError::Config("CA PEM is invalid"))?;
            roots
                .add(c)
                .map_err(|_| TlsError::Config("CA certificate rejected"))?;
        }
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

    /// A new connection to `localhost` (the server certificate's name).
    pub fn connect(&self) -> Result<ClientSession, TlsError> {
        let name =
            ServerName::try_from("localhost").map_err(|_| TlsError::Config("server name"))?;
        let conn = UnbufferedClientConnection::new(self.config.clone(), name)?;
        Ok(ClientSession {
            conn: Box::new(conn),
            inbuf: Vec::new(),
            outbox: Vec::new(),
            established: false,
        })
    }
}

pub struct ClientSession {
    conn: Box<UnbufferedClientConnection>,
    inbuf: Vec<u8>,
    /// Application data waiting for the handshake to finish.
    outbox: Vec<u8>,
    established: bool,
}

impl ClientSession {
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Queues application data (sent as soon as the handshake allows).
    pub fn send(&mut self, data: &[u8]) {
        self.outbox.extend_from_slice(data);
    }

    /// Feeds bytes from the server (none to start the handshake). Appends
    /// what to send to `tx` and decrypted application data to `app`.
    pub fn input(
        &mut self,
        data: &[u8],
        tx: &mut Vec<u8>,
        app: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
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
                    stop = true;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => return Ok(()),
                _ => stop = true,
            }
            if discard > 0 {
                self.inbuf.drain(..discard.min(self.inbuf.len()));
            }
            if stop {
                return Ok(());
            }
        }
    }
}
