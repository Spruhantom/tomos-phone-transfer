use rcgen::{CertificateParams, IsCa, KeyPair};
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

/// TLS certificate material. Keep private_key_der in platform secure storage.
/// The public certificate is distributed in the short-lived QR invitation.
pub struct DeviceTlsIdentity {
    pub certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    pub fingerprint: String,
}

fn ensure_crypto_provider() {
    // rcgen and tokio-rustls can enable different rustls providers transitively.
    // Select ring explicitly so rustls never has to guess at runtime.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl DeviceTlsIdentity {
    pub fn generate() -> Result<Self, TlsSetupError> {
        ensure_crypto_provider();
        let mut params = CertificateParams::new(vec!["tomos-transfer.local".to_string()])
            .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        // This certificate is the device's TLS leaf certificate, not a CA.
        // The QR invitation distributes it as the explicitly trusted certificate.
        params.is_ca = IsCa::NoCa;
        let key_pair = KeyPair::generate().map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        let certificate = params.self_signed(&key_pair).map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        let certificate_der = certificate.der().to_vec();
        let private_key_der = key_pair.serialize_der();
        let fingerprint = hex(&Sha256::digest(&certificate_der));
        Ok(Self { certificate_der, private_key_der, fingerprint })
    }

    pub fn from_der(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Self {
        let fingerprint = hex(&Sha256::digest(&certificate_der));
        Self { certificate_der, private_key_der, fingerprint }
    }

    pub fn private_key_der(&self) -> &[u8] { &self.private_key_der }

    pub fn server_acceptor(&self) -> Result<TlsAcceptor, TlsSetupError> {
        ensure_crypto_provider();
        let cert = CertificateDer::from(self.certificate_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.clone()));
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Pins the inviter's certificate from the scanned QR payload.
    pub fn pinned_connector(trusted_certificate: Vec<u8>) -> Result<TlsConnector, TlsSetupError> {
        ensure_crypto_provider();
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
