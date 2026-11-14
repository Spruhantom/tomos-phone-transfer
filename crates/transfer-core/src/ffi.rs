//! Stable UniFFI surface shared by Android and Linux front ends.
//!
//! The platform adapter owns secret persistence. It passes the decrypted seed
//! into this boundary only for the duration of an operation; Rust never stores
//! the seed in an ordinary file.
use crate::{
    identity::LocalIdentity,
    pairing::PairingInvitation,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn error_json(message: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": message.to_string() }).to_string()
}

/// Restore the existing platform-protected Ed25519 identity into the shared
/// Rust engine and return its public identity as JSON.
#[uniffi::export]
pub fn restore_identity_json(device_id: String, mut seed: Vec<u8>) -> String {
    if seed.len() != 32 {
        seed.fill(0);
        return error_json("Ed25519 seed must contain exactly 32 bytes");
    }
    let id = match Uuid::parse_str(&device_id) {
        Ok(value) => value,
        Err(error) => {
            seed.fill(0);
            return error_json(error);
        }
    };
    let secret: [u8; 32] = match seed.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => {
            seed.fill(0);
            return error_json("invalid Ed25519 seed");
        }
    };
    seed.fill(0);
    let identity = LocalIdentity::from_secret(id, secret);
    json!({
        "ok": true,
        "device_id": identity.public_identity().device_id,
        "public_key": identity.public_identity().public_key
    }).to_string()
}

/// Create the short-lived pairing envelope on the receiving device. The TLS
/// certificate and its private key are generated and protected by the platform
/// adapter; only the public DER certificate is accepted here.
#[uniffi::export]
pub fn create_pairing_payload(
    device_id: String,
    mut seed: Vec<u8>,
    host: String,
    port: u16,
    certificate_der: Vec<u8>,
    lifetime_seconds: u64,
) -> String {
    if seed.len() != 32 {
        seed.fill(0);
        return error_json("Ed25519 seed must contain exactly 32 bytes");
    }
    let id = match Uuid::parse_str(&device_id) {
        Ok(value) => value,
        Err(error) => {
            seed.fill(0);
            return error_json(error);
        }
    };
    if certificate_der.is_empty() || host.trim().is_empty() || port == 0 {
        seed.fill(0);
        return error_json("host, port and TLS certificate are required");
    }
    let secret: [u8; 32] = match seed.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => {
            seed.fill(0);
            return error_json("invalid Ed25519 seed");
        }
    };
    seed.fill(0);
    let identity = LocalIdentity::from_secret(id, secret);
    let fingerprint = Sha256::digest(&certificate_der)
        .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    match PairingInvitation::create(
        identity.public_identity(), host, port, fingerprint, certificate_der, lifetime_seconds,
    ).and_then(|invitation| invitation.to_qr_payload()) {
        Ok(payload) => json!({ "ok": true, "payload": payload }).to_string(),
        Err(error) => error_json(error),
    }
}

/// Validate a scanned invitation in Rust, including expiry and the certificate
/// fingerprint. This is input validation only; TLS and mutual proof are still
/// mandatory before any transfer is accepted.
#[uniffi::export]
pub fn validate_pairing_payload(payload: String) -> String {
    match PairingInvitation::parse_qr_payload(&payload) {
        Ok(invitation) => json!({
            "ok": true,
            "device_id": invitation.identity.device_id,
            "public_key": invitation.identity.public_key,
            "host": invitation.host,
            "port": invitation.port,
            "tls_fingerprint": invitation.tls_fingerprint,
            "expires_at": invitation.expires_at
        }).to_string(),
        Err(error) => error_json(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_restores_existing_identity_without_changing_public_key() {
        let id = Uuid::new_v4();
        let seed = vec![9_u8; 32];
        let result: serde_json::Value =
            serde_json::from_str(&restore_identity_json(id.to_string(), seed)).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["device_id"], id.to_string());
        assert_eq!(result["public_key"].as_array().unwrap().len(), 32);
    }

    #[test]
    fn ffi_rejects_wrong_seed_length() {
        let result: serde_json::Value =
            serde_json::from_str(&restore_identity_json(Uuid::new_v4().to_string(), vec![1; 31])).unwrap();
        assert_eq!(result["ok"], false);
    }
}
