use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use qrcode::QrCode;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use crate::identity::PublicIdentity;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingInvitation {
    pub version: u16,
    pub identity: PublicIdentity,
    pub host: String,
    pub port: u16,
    /// SHA-256 fingerprint of the TLS certificate, encoded as lowercase hex.
    pub tls_fingerprint: String,
    /// DER certificate, included so the scanner can pin this TLS endpoint.
    pub tls_certificate: String,
    /// One-time random secret. Consume once and expire quickly.
    pub token: String,
    pub expires_at: u64,
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("invalid invitation lifetime")] InvalidLifetime,
    #[error("invitation has expired")] Expired,
    #[error("invitation token is invalid")] InvalidToken,
    #[error("invalid QR payload: {0}")] InvalidPayload(String),
}

impl PairingInvitation {
    pub fn create(identity: PublicIdentity, host: String, port: u16, tls_fingerprint: String, tls_certificate_der: Vec<u8>, lifetime_seconds: u64) -> Result<Self, PairingError> {
        if lifetime_seconds == 0 || lifetime_seconds > 600 { return Err(PairingError::InvalidLifetime); }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| PairingError::InvalidPayload(e.to_string()))?.as_secs();
        let mut token = [0_u8; 32];
        OsRng.fill_bytes(&mut token);
        Ok(Self { version: 1, identity, host, port, tls_fingerprint, tls_certificate: URL_SAFE_NO_PAD.encode(tls_certificate_der), token: URL_SAFE_NO_PAD.encode(token), expires_at: now + lifetime_seconds })
    }
    pub fn to_qr_payload(&self) -> Result<String, PairingError> {
        let json = serde_json::to_vec(self).map_err(|e| PairingError::InvalidPayload(e.to_string()))?;
        Ok(format!("tomos-transfer://pair/{}", URL_SAFE_NO_PAD.encode(json)))
    }
    pub fn qr_code(&self) -> Result<QrCode, PairingError> {
        QrCode::new(self.to_qr_payload()?.as_bytes()).map_err(|e| PairingError::InvalidPayload(e.to_string()))
    }
    pub fn parse_qr_payload(payload: &str) -> Result<Self, PairingError> {
        let encoded = payload.strip_prefix("tomos-transfer://pair/").ok_or_else(|| PairingError::InvalidPayload("unsupported scheme".into()))?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| PairingError::InvalidPayload(e.to_string()))?;
        let invitation: Self = serde_json::from_slice(&bytes).map_err(|e| PairingError::InvalidPayload(e.to_string()))?;
        invitation.ensure_valid()?;
        Ok(invitation)
    }
    pub fn trusted_certificate_der(&self) -> Result<Vec<u8>, PairingError> {
        use sha2::{Digest, Sha256};
        let der = URL_SAFE_NO_PAD.decode(&self.tls_certificate).map_err(|e| PairingError::InvalidPayload(e.to_string()))?;
        let fingerprint = Sha256::digest(&der).iter().map(|b| format!("{b:02x}")).collect::<String>();
        if !fingerprint.eq_ignore_ascii_case(&self.tls_fingerprint) {
            return Err(PairingError::InvalidPayload("TLS certificate fingerprint mismatch".into()));
        }
        Ok(der)
    }
    pub fn ensure_valid(&self) -> Result<(), PairingError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| PairingError::InvalidPayload(e.to_string()))?.as_secs();
        if self.version != 1 || self.expires_at < now { return Err(PairingError::Expired); }
        let token = URL_SAFE_NO_PAD.decode(&self.token).map_err(|_| PairingError::InvalidToken)?;
        if token.len() != 32 { return Err(PairingError::InvalidToken); }
        Ok(())
    }
}
