//! Stable UniFFI surface shared by Android and Linux front ends.
//!
//! The platform adapter owns secret persistence. It passes the decrypted seed
//! into this boundary only for the duration of an operation; Rust never stores
//! the seed in an ordinary file.
use crate::{
    identity::LocalIdentity,
    pairing::{OneTimePairingToken, PairingInvitation},
    tcp::{accept_one_resumable, connect_and_send_with_id},
    tls::DeviceTlsIdentity,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use std::{net::TcpListener as StdTcpListener, path::Path, sync::{Arc, Mutex}};
use tokio_rustls::TlsAcceptor;

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



/// TLS leaf identity used by the receiving device. The private key must be
/// persisted by the platform in secure storage and must never be logged or
/// placed in the pairing QR payload.
#[derive(uniffi::Object)]
pub struct TlsIdentityHandle {
    identity: Mutex<DeviceTlsIdentity>,
}

#[uniffi::export]
impl TlsIdentityHandle {
    #[uniffi::constructor]
    pub fn generate() -> Option<Arc<Self>> {
        let identity = DeviceTlsIdentity::generate().ok()?;
        Some(Arc::new(Self { identity: Mutex::new(identity) }))
    }

    /// Restore certificate material from platform secure storage and validate
    /// that the certificate and private key can form a TLS server identity.
    #[uniffi::constructor]
    pub fn restore(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Option<Arc<Self>> {
        if certificate_der.is_empty() || private_key_der.is_empty() {
            return None;
        }
        let identity = DeviceTlsIdentity::from_der(certificate_der, private_key_der);
        identity.server_acceptor().ok()?;
        Some(Arc::new(Self { identity: Mutex::new(identity) }))
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.identity.lock().map(|identity| identity.certificate_der.clone()).unwrap_or_default()
    }

    pub fn fingerprint(&self) -> String {
        self.identity.lock().map(|identity| identity.fingerprint.clone()).unwrap_or_default()
    }

    /// Export only so the platform can encrypt it with Android Keystore or
    /// store it in Linux Secret Service. Never persist this in ordinary files.
    pub fn private_key_der_for_secure_storage(&self) -> Vec<u8> {
        self.identity.lock().map(|identity| identity.private_key_der().to_vec()).unwrap_or_default()
    }
}


/// Progress notifications for an outgoing transfer.
#[uniffi::export(callback_interface)]
pub trait TransferProgressCallbacks: Send + Sync {
    fn on_progress(&self, bytes_sent: u64, total_bytes: u64, bytes_per_second: u64);
}

/// User approval and progress callbacks for a receiving session. Implementations
/// must present the peer/file details to the user and return explicit approval.
#[uniffi::export(callback_interface)]
pub trait TransferCallbacks: Send + Sync {
    fn approve_peer(&self, device_id: String, public_key: Vec<u8>) -> bool;
    fn approve_file(&self, file_name: String, size_bytes: u64, sha256: String) -> bool;
    fn on_progress(&self, bytes_received: u64, total_bytes: u64, bytes_per_second: u64);
}

/// A one-shot receiver created before its QR is shown. The bound socket and
/// one-time invitation token stay together so the QR cannot be detached from
/// the listener that will authenticate it.
#[derive(uniffi::Object)]
pub struct TransferReceiver {
    listener: Mutex<Option<StdTcpListener>>,
    identity: Mutex<LocalIdentity>,
    acceptor: TlsAcceptor,
    invitation: PairingInvitation,
}

#[uniffi::export]
impl TransferReceiver {
    pub fn pairing_payload(&self) -> String {
        self.invitation.to_qr_payload().unwrap_or_default()
    }

    pub fn port(&self) -> u16 {
        self.invitation.port
    }

    /// Wait for one sender. This is a blocking call and must run on a worker
    /// thread in Android/Linux. A disconnect leaves the checkpoint manifest in
    /// state_dir; create a fresh receiver/QR and retry with the same transfer ID.
    pub fn receive_once(
        &self,
        destination_dir: String,
        state_dir: String,
        callbacks: Box<dyn TransferCallbacks>,
    ) -> String {
        let listener = match self.listener.lock() {
            Ok(mut listener) => match listener.take() {
                Some(listener) => listener,
                None => return error_json("receiver has already been used"),
            },
            Err(_) => return error_json("receiver listener lock poisoned"),
        };
        let identity = match self.identity.lock() {
            Ok(identity) => identity,
            Err(_) => return error_json("receiver identity lock poisoned"),
        };
        let token_guard = OneTimePairingToken::from_invitation(&self.invitation);
        let callbacks: Arc<dyn TransferCallbacks> = Arc::from(callbacks);
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => return error_json(error),
        };
        let result = runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            accept_one_resumable(
                &listener,
                &self.acceptor,
                &identity,
                &token_guard,
                Path::new(&destination_dir),
                Path::new(&state_dir),
                |peer| {
                    let callbacks = Arc::clone(&callbacks);
                    let peer = peer.clone();
                    async move {
                        callbacks.approve_peer(
                            peer.device_id.to_string(),
                            peer.public_key.to_vec(),
                        )
                    }
                },
                |name, size, checksum| {
                    callbacks.approve_file(name.to_owned(), size, checksum.to_owned())
                },
                |progress| {
                    callbacks.on_progress(
                        progress.bytes_received,
                        progress.total_bytes,
                        progress.bytes_per_second,
                    );
                },
            ).await
        });
        match result {
            Ok((peer, transfer)) => json!({
                "ok": true,
                "peer_device_id": peer.device_id,
                "path": transfer.path,
                "bytes_received": transfer.bytes_received,
                "sha256": transfer.sha256
            }).to_string(),
            Err(error) => error_json(error),
        }
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


    /// Bind a one-shot receive socket and create its QR invitation before the
    /// UI displays the QR. bind_address should normally be "0.0.0.0:0".
    pub fn create_receiver(
        &self,
        advertised_host: String,
        bind_address: String,
        tls_identity: Arc<TlsIdentityHandle>,
        lifetime_seconds: u64,
    ) -> Option<Arc<TransferReceiver>> {
        if advertised_host.trim().is_empty() {
            return None;
        }
        let listener = StdTcpListener::bind(&bind_address).ok()?;
        listener.set_nonblocking(true).ok()?;
        let port = listener.local_addr().ok()?.port();
        let identity = self.identity.lock().ok()?;
        let identity_copy = LocalIdentity::from_secret(identity.device_id, identity.secret_bytes());
        let tls = tls_identity.identity.lock().ok()?;
        let acceptor = tls.server_acceptor().ok()?;
        let invitation = PairingInvitation::create(
            identity.public_identity(),
            advertised_host,
            port,
            tls.fingerprint.clone(),
            tls.certificate_der.clone(),
            lifetime_seconds,
        ).ok()?;
        Some(Arc::new(TransferReceiver {
            listener: Mutex::new(Some(listener)),
            identity: Mutex::new(identity_copy),
            acceptor,
            invitation,
        }))
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
        callbacks: Box<dyn TransferProgressCallbacks>,
    ) -> String {
        let callbacks: Arc<dyn TransferProgressCallbacks> = Arc::from(callbacks);
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
            |progress| callbacks.on_progress(
                progress.bytes_received,
                progress.total_bytes,
                progress.bytes_per_second,
            ),
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


    #[test]
    fn tls_handle_restores_certificate_and_private_key() {
        let generated = TlsIdentityHandle::generate().unwrap();
        let certificate = generated.certificate_der();
        let private_key = generated.private_key_der_for_secure_storage();
        assert!(!certificate.is_empty());
        assert!(!private_key.is_empty());
        let restored = TlsIdentityHandle::restore(certificate.clone(), private_key).unwrap();
        assert_eq!(restored.certificate_der(), certificate);
        assert_eq!(restored.fingerprint(), generated.fingerprint());
    }


    #[test]
    fn receiver_binds_socket_and_creates_matching_pairing_qr() {
        let id = Uuid::new_v4();
        let identity = TransferIdentity::restore(id.to_string(), vec![8; 32]).unwrap();
        let tls = TlsIdentityHandle::generate().unwrap();
        let receiver = identity.create_receiver(
            "127.0.0.1".to_string(),
            "127.0.0.1:0".to_string(),
            tls,
            120,
        ).unwrap();
        let invitation = PairingInvitation::parse_qr_payload(&receiver.pairing_payload()).unwrap();
        assert_eq!(invitation.identity.device_id, id);
        assert_eq!(invitation.port, receiver.port());
        assert!(invitation.trusted_certificate_der().is_ok());
    }
}
