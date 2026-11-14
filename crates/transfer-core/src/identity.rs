use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Long-term identity key. Persist the 32-byte secret using the platform secure
/// storage (Android Keystore / Linux Secret Service); never advertise it.
pub struct LocalIdentity { pub device_id: Uuid, signing_key: SigningKey }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    pub device_id: Uuid,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityProof {
    pub device_id: Uuid,
    pub challenge: [u8; 32],
    pub signature: Vec<u8>,
}

impl LocalIdentity {
    pub fn generate() -> Self {
        Self { device_id: Uuid::new_v4(), signing_key: SigningKey::generate(&mut OsRng) }
    }
    /// Restore an identity from a secret retrieved from the platform keystore.
    pub fn from_secret(device_id: Uuid, secret: [u8; 32]) -> Self {
        Self { device_id, signing_key: SigningKey::from_bytes(&secret) }
    }
    /// Export only for storage in Android Keystore or the Linux Secret Service.
    /// Do not write this value to logs, QR codes, or ordinary shared files.
    pub fn secret_bytes(&self) -> [u8; 32] { self.signing_key.to_bytes() }

    pub fn public_identity(&self) -> PublicIdentity {
        PublicIdentity { device_id: self.device_id, public_key: self.signing_key.verifying_key().to_bytes() }
    }
    pub fn prove(&self, challenge: [u8; 32]) -> IdentityProof {
        let mut message = Vec::with_capacity(48);
        message.extend_from_slice(self.device_id.as_bytes());
        message.extend_from_slice(&challenge);
        IdentityProof { device_id: self.device_id, challenge, signature: self.signing_key.sign(&message).to_bytes().to_vec() }
    }
}

pub fn verify_proof(identity: &PublicIdentity, proof: &IdentityProof, expected_challenge: &[u8; 32]) -> bool {
    if identity.device_id != proof.device_id || &proof.challenge != expected_challenge { return false; }
    let Ok(key) = VerifyingKey::from_bytes(&identity.public_key) else { return false; };
    let Ok(signature) = Signature::from_slice(&proof.signature) else { return false; };
    let mut message = Vec::with_capacity(48);
    message.extend_from_slice(identity.device_id.as_bytes());
    message.extend_from_slice(expected_challenge);
    key.verify(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenge_proof_is_bound_to_device_and_nonce() {
        let identity = LocalIdentity::generate();
        let public = identity.public_identity();
        let nonce = [7_u8; 32];
        let proof = identity.prove(nonce);
        assert!(verify_proof(&public, &proof, &nonce));
        assert!(!verify_proof(&public, &proof, &[8_u8; 32]));
    }
}
