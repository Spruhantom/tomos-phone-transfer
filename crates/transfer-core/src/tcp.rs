use crate::{
    auth::{authenticate_client, authenticate_server, AuthenticationError},
    identity::{LocalIdentity, PublicIdentity},
    network::{receive_one, receive_one_resumable, send_file, send_file_with_id, NetworkTransferError},
    pairing::{OneTimePairingToken, PairingError, PairingInvitation},
    tls::{DeviceTlsIdentity, TlsSetupError},
    transfer::{TransferProgress, TransferResult},
};
use std::{future::Future, net::SocketAddr, path::Path};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Error)]
pub enum TcpTransferError {
    #[error("pairing error: {0}")] Pairing(#[from] PairingError),
    #[error("TLS setup error: {0}")] Tls(#[from] TlsSetupError),
    #[error("authentication error: {0}")] Authentication(#[from] AuthenticationError),
    #[error("network transfer error: {0}")] Transfer(#[from] NetworkTransferError),
    #[error("socket error: {0}")] Io(#[from] std::io::Error),
    #[error("invalid invitation address")] InvalidAddress,
}

/// Accepts one paired sender on an already-bound listener. Callers should bind only
/// to the intended LAN interface, present the incoming identity for approval, and
/// store the invitation token as one-use state.
pub async fn accept_one<F, Fut, A, P>(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    local_identity: &LocalIdentity,
    token_guard: &OneTimePairingToken,
    destination: &Path,
    approve_device: F,
    approve_file: A,
    on_progress: P,
) -> Result<(PublicIdentity, TransferResult), TcpTransferError>
where
    F: FnOnce(&PublicIdentity) -> Fut,
    Fut: Future<Output = bool>,
    A: FnOnce(&str, u64, &str) -> bool,
    P: FnMut(TransferProgress),
{
    let (socket, _) = listener.accept().await?;
    let mut tls = acceptor.accept(socket).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
    let peer = authenticate_server(&mut tls, local_identity, token_guard, approve_device).await?;
    let result = receive_one(&mut tls, destination, approve_file, on_progress).await?;
    Ok((peer, result))
}

/// Connects to the host and port encoded in the scanned QR invitation, pins the
/// embedded TLS certificate, proves both device identities, then sends one file.
pub async fn connect_and_send<P>(
    invitation: &PairingInvitation,
    local_identity: &LocalIdentity,
    source: &Path,
    remote_name: &str,
    on_progress: P,
) -> Result<(), TcpTransferError>
where P: FnMut(TransferProgress) {
    invitation.ensure_valid()?;
    let certificate = invitation.trusted_certificate_der()?;
    let connector = DeviceTlsIdentity::pinned_connector(certificate)?;
    let address: SocketAddr = format!("{}:{}", invitation.host, invitation.port).parse()
        .map_err(|_| TcpTransferError::InvalidAddress)?;
    let socket = TcpStream::connect(address).await?;
    let server_name = DeviceTlsIdentity::connect_name()?;
    let mut tls = connector.connect(server_name, socket).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
    authenticate_client(&mut tls, local_identity, &invitation.identity, &invitation.token).await?;
    send_file(&mut tls, source, remote_name, on_progress).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pairing::OneTimePairingToken, tls::DeviceTlsIdentity};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn authenticated_tls_tcp_transfer() {
        let sender_identity = LocalIdentity::generate();
        let receiver_identity = LocalIdentity::generate();
        let tls_identity = DeviceTlsIdentity::generate().unwrap();
        let acceptor = tls_identity.server_acceptor().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let invitation = PairingInvitation::create(
            receiver_identity.public_identity(), address.ip().to_string(), address.port(),
            tls_identity.fingerprint.clone(), tls_identity.certificate_der.clone(), 120,
        ).unwrap();
        let token_guard = OneTimePairingToken::new(invitation.token.clone());
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let source = src_dir.path().join("payload.bin");
        let data = vec![91_u8; 128 * 1024];
        tokio::fs::write(&source, &data).await.unwrap();

        let server = async {
            accept_one(&listener, &acceptor, &receiver_identity, &token_guard, dst_dir.path(),
                |_| async { true },
                |name, size, _| name == "payload.bin" && size == data.len() as u64,
                |_| {}).await
        };
        let client = async {
            connect_and_send(&invitation, &sender_identity, &source, "payload.bin", |_| {}).await
        };
        let (received, sent) = tokio::join!(server, client);
        sent.unwrap();
        let (_, result) = received.unwrap();
        assert_eq!(tokio::fs::read(result.path).await.unwrap(), data);
    }
}


/// Resumable counterpart to accept_one. Keep state_dir on the same filesystem as
/// destination so the verified partial file can be atomically linked into place.
pub async fn accept_one_resumable<F, Fut, A, P>(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    local_identity: &LocalIdentity,
    token_guard: &OneTimePairingToken,
    destination: &Path,
    state_dir: &Path,
    approve_device: F,
    approve_file: A,
    on_progress: P,
) -> Result<(PublicIdentity, TransferResult), TcpTransferError>
where
    F: FnOnce(&PublicIdentity) -> Fut,
    Fut: Future<Output = bool>,
    A: FnOnce(&str, u64, &str) -> bool,
    P: FnMut(TransferProgress),
{
    let (socket, _) = listener.accept().await?;
    let mut tls = acceptor.accept(socket).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
    let peer = authenticate_server(&mut tls, local_identity, token_guard, approve_device).await?;
    let result = receive_one_resumable(&mut tls, destination, state_dir, approve_file, on_progress).await?;
    Ok((peer, result))
}

/// Stable transfer ID must be reused when retrying after a disconnect so the
/// receiver can locate and validate the matching resume manifest.
pub async fn connect_and_send_with_id<P>(
    invitation: &PairingInvitation,
    local_identity: &LocalIdentity,
    source: &Path,
    remote_name: &str,
    transfer_id: uuid::Uuid,
    on_progress: P,
) -> Result<(), TcpTransferError>
where P: FnMut(TransferProgress) {
    invitation.ensure_valid()?;
    let certificate = invitation.trusted_certificate_der()?;
    let connector = DeviceTlsIdentity::pinned_connector(certificate)?;
    let address: SocketAddr = format!("{}:{}", invitation.host, invitation.port).parse()
        .map_err(|_| TcpTransferError::InvalidAddress)?;
    let socket = TcpStream::connect(address).await?;
    let server_name = DeviceTlsIdentity::connect_name()?;
    let mut tls = connector.connect(server_name, socket).await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;
    authenticate_client(&mut tls, local_identity, &invitation.identity, &invitation.token).await?;
    send_file_with_id(&mut tls, source, remote_name, transfer_id, on_progress).await?;
    Ok(())
}
