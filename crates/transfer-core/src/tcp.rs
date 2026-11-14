use crate::{
    auth::{authenticate_client, authenticate_server, AuthenticationError},
    identity::{LocalIdentity, PublicIdentity},
    network::{receive_one, send_file, NetworkTransferError},
    pairing::{OneTimePairingToken, PairingError, PairingInvitation},
    tls::{DeviceTlsIdentity, TlsSetupError},
    transfer::{TransferProgress, TransferResult},
};
use std::{future::Future, net::SocketAddr, path::Path};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
