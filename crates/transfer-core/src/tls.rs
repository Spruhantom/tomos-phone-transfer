use rcgen::generate_simple_self_signed;
use rustls::{pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName}, ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, Error)]
pub enum TlsSetupError {
    #[error("certificate generation failed: {0}")] Certificate(String),
    #[error("invalid trusted certificate: {0}")] Trust(String),
}

/// A device TLS identity. The certificate DER is shared through the QR invitation;
/// the private key must be stored securely and never exported.
pub struct DeviceTlsIdentity {
    pub certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    pub fingerprint: String,
}

impl DeviceTlsIdentity {
    pub fn generate() -> Result<Self, TlsSetupError> {
        let certified = generate_simple_self_signed(vec!["tomos-transfer.local".to_string()])
            .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        let certificate_der = certified.cert.der().to_vec();
        let private_key_der = certified.key_pair.serialize_der();
        let fingerprint = hex(&Sha256::digest(&certificate_der));
        Ok(Self { certificate_der, private_key_der, fingerprint })
    }
    pub fn server_acceptor(&self) -> Result<TlsAcceptor, TlsSetupError> {
        let cert = CertificateDer::from(self.certificate_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.clone()));
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
    /// Pins the server certificate obtained from the QR invitation. This authenticates
    /// the TLS endpoint; the Ed25519 challenge proof separately authenticates the peer.
    pub fn pinned_connector(trusted_certificate: Vec<u8>) -> Result<TlsConnector, TlsSetupError> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(trusted_certificate))
            .map_err(|e| TlsSetupError::Trust(e.to_string()))?;
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }
    pub fn connect_name() -> Result<ServerName<'static>, TlsSetupError> {
        ServerName::try_from("tomos-transfer.local".to_string())
            .map_err(|e| TlsSetupError::Trust(e.to_string()))
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
