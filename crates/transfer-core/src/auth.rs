use crate::{identity::{verify_proof, IdentityProof, LocalIdentity, PublicIdentity}, pairing::OneTimePairingToken};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::future::Future;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_AUTH_FRAME: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("authentication frame is invalid or too large")] InvalidFrame,
    #[error("peer identity could not be verified")] InvalidIdentity,
    #[error("pairing invitation token is invalid")] InvalidToken,
    #[error("pairing was declined by the user")] Declined,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("serialization error: {0}")] Serialization(String),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AuthMessage {
    Challenge { identity: PublicIdentity, nonce: [u8; 32] },
    Response { identity: PublicIdentity, proof: IdentityProof, client_nonce: [u8; 32], invitation_token: String },
    ServerProof { proof: IdentityProof },
}

async fn send<W: AsyncWrite + Unpin, T: Serialize>(stream: &mut W, value: &T) -> Result<(), AuthenticationError> {
    let bytes = serde_json::to_vec(value).map_err(|e| AuthenticationError::Serialization(e.to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_AUTH_FRAME { return Err(AuthenticationError::InvalidFrame); }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn receive<R: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut R) -> Result<T, AuthenticationError> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > MAX_AUTH_FRAME { return Err(AuthenticationError::InvalidFrame); }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|e| AuthenticationError::Serialization(e.to_string()))
}

/// Server side of the QR-authorised handshake. expected_token must be the fresh,
/// single-use invitation token retained by the inviting device. approve_client must
/// prompt the user before trusting a previously unknown device identity.
pub async fn authenticate_server<S, F, Fut>(
    stream: &mut S, local: &LocalIdentity, token_guard: &OneTimePairingToken, approve_client: F,
) -> Result<PublicIdentity, AuthenticationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&PublicIdentity) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    send(stream, &AuthMessage::Challenge { identity: local.public_identity(), nonce }).await?;

    let response: AuthMessage = receive(stream).await?;
    let (client_identity, proof, client_nonce, token) = match response {
        AuthMessage::Response { identity, proof, client_nonce, invitation_token } => (identity, proof, client_nonce, invitation_token),
        _ => return Err(AuthenticationError::InvalidFrame),
    };
    if !token_guard.consume(&token) { return Err(AuthenticationError::InvalidToken); }
    if !verify_proof(&client_identity, &proof, &nonce) { return Err(AuthenticationError::InvalidIdentity); }
    if !approve_client(&client_identity).await { return Err(AuthenticationError::Declined); }
    send(stream, &AuthMessage::ServerProof { proof: local.prove(client_nonce) }).await?;
    Ok(client_identity)
}

/// Client side of the handshake. expected_server is obtained from the scanned QR
/// invitation; the TLS connector must separately pin the invitation certificate.
pub async fn authenticate_client<S>(
    stream: &mut S, local: &LocalIdentity, expected_server: &PublicIdentity, invitation_token: &str,
) -> Result<(), AuthenticationError>
where S: AsyncRead + AsyncWrite + Unpin {
    let challenge: AuthMessage = receive(stream).await?;
    let (server_identity, nonce) = match challenge {
        AuthMessage::Challenge { identity, nonce } => (identity, nonce),
        _ => return Err(AuthenticationError::InvalidFrame),
    };
    if &server_identity != expected_server { return Err(AuthenticationError::InvalidIdentity); }
    let mut client_nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut client_nonce);
    send(stream, &AuthMessage::Response {
        identity: local.public_identity(),
        proof: local.prove(nonce),
        client_nonce,
        invitation_token: invitation_token.to_string(),
    }).await?;

    let proof: AuthMessage = receive(stream).await?;
    match proof {
        AuthMessage::ServerProof { proof } if verify_proof(expected_server, &proof, &client_nonce) => Ok(()),
        _ => Err(AuthenticationError::InvalidIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn mutually_authenticates_devices_with_invitation_token() {
        let server = LocalIdentity::generate();
        let client = LocalIdentity::generate();
        let expected_server = server.public_identity();
        let (mut a, mut b) = duplex(4096);
        let token_guard = OneTimePairingToken::new("one-time-secret".into());
        let server_task = async {
            authenticate_server(&mut a, &server, &token_guard, |_| async { true }).await
        };
        let client_task = async {
            authenticate_client(&mut b, &client, &expected_server, "one-time-secret").await
        };
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        assert_eq!(server_result.unwrap(), client.public_identity());
        client_result.unwrap();
    }
}
