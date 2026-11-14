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
use std::sync::{Arc, Mutex};

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


/// Opaque, long-lived native identity handle. Platform code keeps this handle
/// for the active session; the secret key is never returned through UniFFI.
#[derive(uniffi::Object)]
pub struct TransferIdentity {
    identity: Mutex<LocalIdentity>,
}

#[uniffi::export]
impl TransferIdentity {
    /// Restore an existing identity from a seed retrieved from secure storage.
    /// Invalid input returns None rather than generating a replacement identity.
    #[uniffi::constructor]
    pub fn restore(device_id: String, mut seed: Vec<u8>) -> Option<Arc<Self>> {
        if seed.len() != 32 {
            seed.fill(0);
            return None;
        }
        let id = match Uuid::parse_str(&device_id) {
            Ok(value) => value,
            Err(_) => {
                seed.fill(0);
                return None;
            }
        };
        let secret: [u8; 32] = match seed.as_slice().try_into() {
            Ok(value) => value,
            Err(_) => {
                seed.fill(0);
                return None;
            }
        };
        seed.fill(0);
        Some(Arc::new(Self {
            identity: Mutex::new(LocalIdentity::from_secret(id, secret)),
        }))
    }

    pub fn public_identity_json(&self) -> String {
        match self.identity.lock() {
            Ok(identity) => serde_json::to_string(&identity.public_identity())
                .unwrap_or_else(|error| error_json(error)),
            Err(_) => error_json("identity lock poisoned"),
        }
    }

    pub fn prove_challenge_json(&self, challenge: Vec<u8>) -> String {
        let challenge: [u8; 32] = match challenge.as_slice().try_into() {
            Ok(value) => value,
            Err(_) => return error_json("challenge must contain exactly 32 bytes"),
        };
        match self.identity.lock() {
            Ok(identity) => serde_json::to_string(&identity.prove(challenge))
                .unwrap_or_else(|error| error_json(error)),
            Err(_) => error_json("identity lock poisoned"),
        }
    }

    pub fn create_pairing_payload(
        &self,
        host: String,
        port: u16,
        certificate_der: Vec<u8>,
        lifetime_seconds: u64,
    ) -> String {
        if certificate_der.is_empty() || host.trim().is_empty() || port == 0 {
            return error_json("host, port and TLS certificate are required");
        }
        let identity = match self.identity.lock() {
            Ok(identity) => identity.public_identity(),
            Err(_) => return error_json("identity lock poisoned"),
        };
        let fingerprint = Sha256::digest(&certificate_der)
            .iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        match PairingInvitation::create(
            identity, host, port, fingerprint, certificate_der, lifetime_seconds,
        ).and_then(|invitation| invitation.to_qr_payload()) {
            Ok(payload) => json!({ "ok": true, "payload": payload }).to_string(),
            Err(error) => error_json(error),
        }
    }

    /// Send one file through the existing TLS 1.3 + QR pinning + mutual
    /// Ed25519 authentication pipeline. Run this blocking call on a worker
    /// thread in platform applications. Reuse transfer_id when retrying.
    pub fn send_file(
        &self,
        invitation_payload: String,
        source_path: String,
        remote_name: String,
        transfer_id: String,
    ) -> String {
        let invitation = match PairingInvitation::parse_qr_payload(&invitation_payload) {
            Ok(value) => value,
            Err(error) => return error_json(error),
        };
        let transfer_id = match Uuid::parse_str(&transfer_id) {
            Ok(value) => value,
            Err(error) => return error_json(error),
        };
        let source = std::path::PathBuf::from(source_path);
        if !source.is_file() {
            return error_json("source file does not exist or is not a regular file");
        }
        let identity = match self.identity.lock() {
            Ok(identity) => identity,
            Err(_) => return error_json("identity lock poisoned"),
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => return error_json(error),
        };
        match runtime.block_on(crate::tcp::connect_and_send_with_id(
            &invitation,
            &identity,
            &source,
            &remote_name,
            transfer_id,
            |_| {},
        )) {
            Ok(()) => json!({ "ok": true, "transfer_id": transfer_id }).to_string(),
            Err(error) => error_json(error),
        }
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

    #[test]
    fn opaque_identity_handle_keeps_device_identity_and_signs_challenges() {
        let id = Uuid::new_v4();
        let handle = TransferIdentity::restore(id.to_string(), vec![4; 32]).unwrap();
        let public: crate::identity::PublicIdentity =
            serde_json::from_str(&handle.public_identity_json()).unwrap();
        assert_eq!(public.device_id, id);
        let proof: crate::identity::IdentityProof =
            serde_json::from_str(&handle.prove_challenge_json(vec![6; 32])).unwrap();
        assert!(crate::identity::verify_proof(&public, &proof, &[6; 32]));
    }
}
