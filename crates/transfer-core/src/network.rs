use crate::{
    protocol::{validate_file_name, ControlMessage, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE},
    transfer::{receive_file, TransferError, TransferProgress, TransferResult},
    verification::{sha256_reader, to_hex},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{path::{Path, PathBuf}, time::Instant};
use thiserror::Error;
use tokio::{fs::File, io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt}};

const MAX_CONTROL_FRAME: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum NetworkTransferError {
    #[error("control frame is too large")] FrameTooLarge,
    #[error("invalid control message: {0}")] Protocol(String),
    #[error("peer rejected the transfer: {0}")] Rejected(String),
    #[error("peer did not confirm the completed file")] CompletionMismatch,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("file transfer failed: {0}")] Transfer(#[from] TransferError),
    #[error("verification failed: {0}")] Verification(#[from] crate::verification::VerificationError),
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) -> Result<(), NetworkTransferError> {
    let payload = serde_json::to_vec(value).map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
    if payload.len() > MAX_CONTROL_FRAME { return Err(NetworkTransferError::FrameTooLarge); }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T, NetworkTransferError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_CONTROL_FRAME { return Err(NetworkTransferError::FrameTooLarge); }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|e| NetworkTransferError::Protocol(e.to_string()))
}

/// Sends a file over an already authenticated TLS stream. The caller must perform
/// device identity verification and obtain user approval before invoking this.
pub async fn send_file<S, F>(stream: &mut S, source: &Path, remote_name: &str, on_progress: F) -> Result<(), NetworkTransferError>
where S: AsyncRead + AsyncWrite + Unpin, F: FnMut(TransferProgress) {
    send_file_with_id(stream, source, remote_name, uuid::Uuid::new_v4(), on_progress).await
}

pub async fn send_file_with_id<S, F>(stream: &mut S, source: &Path, remote_name: &str, transfer_id: uuid::Uuid, mut on_progress: F) -> Result<(), NetworkTransferError>
where S: AsyncRead + AsyncWrite + Unpin, F: FnMut(TransferProgress) {
    if !validate_file_name(remote_name) { return Err(NetworkTransferError::Protocol("unsafe destination filename".into())); }
    let mut source_file = File::open(source).await?;
    let size = source_file.metadata().await?.len();
    let mut hash_file = File::open(source).await?;
    let digest = to_hex(&sha256_reader(&mut hash_file).await?);
    write_frame(stream, &ControlMessage::TransferOffer {
        transfer_id, file_name: remote_name.to_string(), size_bytes: size, sha256: digest.clone(),
    }).await?;

    let (offset, expected_prefix) = match read_frame::<_, ControlMessage>(stream).await? {
        ControlMessage::TransferAccepted { transfer_id: accepted } if accepted == transfer_id => (0, String::new()),
        ControlMessage::TransferResumeAccepted { transfer_id: accepted, offset, prefix_sha256 } if accepted == transfer_id => (offset, prefix_sha256),
        ControlMessage::TransferRejected { transfer_id: rejected, reason } if rejected == transfer_id => return Err(NetworkTransferError::Rejected(reason)),
        _ => return Err(NetworkTransferError::Protocol("unexpected transfer response".into())),
    };
    if offset > size { return Err(NetworkTransferError::Protocol("resume offset exceeds source size".into())); }
    let prefix = hash_prefix(source, offset).await?;
    if offset > 0 && !prefix.eq_ignore_ascii_case(&expected_prefix) {
        return Err(NetworkTransferError::Protocol("resume prefix checksum mismatch".into()));
    }
    source_file.seek(std::io::SeekFrom::Start(offset)).await?;

    let started = Instant::now();
    let mut sent = offset;
    let mut buffer = vec![0_u8; DEFAULT_CHUNK_SIZE.min(MAX_CHUNK_SIZE)];
    loop {
        let count = source_file.read(&mut buffer).await?;
        if count == 0 { break; }
        stream.write_all(&buffer[..count]).await?;
        sent = sent.saturating_add(count as u64);
        let elapsed = started.elapsed().as_secs_f64().max(0.001);
        on_progress(TransferProgress { bytes_received: sent, total_bytes: size, bytes_per_second: (sent as f64 / elapsed) as u64 });
    }
    stream.flush().await?;

    match read_frame::<_, ControlMessage>(stream).await? {
        ControlMessage::TransferComplete { transfer_id: completed, sha256 }
            if completed == transfer_id && sha256.eq_ignore_ascii_case(&digest) => Ok(()),
        _ => Err(NetworkTransferError::CompletionMismatch),
    }
}

/// Receives one offered file. approve must represent an explicit user decision.
/// The supplied stream must be authenticated TLS and the peer identity verified.
pub async fn receive_one<S, F, A>(stream: &mut S, destination_dir: &Path, approve: A, on_progress: F) -> Result<TransferResult, NetworkTransferError>
where S: AsyncRead + AsyncWrite + Unpin, F: FnMut(TransferProgress), A: FnOnce(&str, u64, &str) -> bool {
    let (transfer_id, file_name, size_bytes, sha256) = match read_frame::<_, ControlMessage>(stream).await? {
        ControlMessage::TransferOffer { transfer_id, file_name, size_bytes, sha256 } => (transfer_id, file_name, size_bytes, sha256),
        _ => return Err(NetworkTransferError::Protocol("expected transfer offer".into())),
    };

    if !validate_file_name(&file_name) {
        write_frame(stream, &ControlMessage::TransferRejected { transfer_id, reason: "unsafe filename".into() }).await?;
        return Err(NetworkTransferError::Protocol("unsafe filename".into()));
    }
    if !approve(&file_name, size_bytes, &sha256) {
        write_frame(stream, &ControlMessage::TransferRejected { transfer_id, reason: "declined by recipient".into() }).await?;
        return Err(NetworkTransferError::Rejected("declined by recipient".into()));
    }
    write_frame(stream, &ControlMessage::TransferAccepted { transfer_id }).await?;

    // Limit reads to the exact offered size so payload bytes cannot consume the next control frame.
    let mut limited = (&mut *stream).take(size_bytes);
    let result = receive_file(&mut limited, destination_dir, &file_name, size_bytes, &sha256, DEFAULT_CHUNK_SIZE, on_progress).await?;
    drop(limited);
    write_frame(stream, &ControlMessage::TransferComplete { transfer_id, sha256: result.sha256.clone() }).await?;
    Ok(result)
}

pub fn result_path(result: &TransferResult) -> PathBuf { result.path.clone() }

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn transfers_file_between_two_stream_endpoints() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("photo.bin");
        let data = vec![42_u8; 900_000];
        tokio::fs::write(&source, &data).await.unwrap();

        let (mut sender, mut receiver) = duplex(128 * 1024);
        let send = async { send_file(&mut sender, &source, "photo.bin", |_| {}).await };
        let receive = async {
            receive_one(&mut receiver, destination_dir.path(), |name, size, _| name == "photo.bin" && size == data.len() as u64, |_| {}).await
        };
        let (sent, received) = tokio::join!(send, receive);
        sent.unwrap();
        let result = received.unwrap();
        assert_eq!(tokio::fs::read(result.path).await.unwrap(), data);
    }
}


async fn hash_prefix(path: &Path, length: u64) -> Result<String, NetworkTransferError> {
    let mut file = File::open(path).await?;
    let mut remaining = length;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..wanted]).await?;
        if count == 0 { return Err(NetworkTransferError::Protocol("source shorter than resume offset".into())); }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(format!("{:x}", hasher.finalize()))
}



/// Receives a file with durable checkpoints. If the socket drops, the manifest and
/// partial file remain; retry the same transfer ID to continue at the last committed
/// chunk. The final whole-file SHA-256 is always checked before publishing the file.
pub async fn receive_one_resumable<S, F, A>(
    stream: &mut S,
    destination_dir: &Path,
    state_dir: &Path,
    approve: A,
    mut on_progress: F,
) -> Result<TransferResult, NetworkTransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(TransferProgress),
    A: FnOnce(&str, u64, &str) -> bool,
{
    use crate::resume::ResumeManifest;
    use tokio::fs;

    let (transfer_id, file_name, size_bytes, sha256) = match read_frame::<_, ControlMessage>(stream).await? {
        ControlMessage::TransferOffer { transfer_id, file_name, size_bytes, sha256 } =>
            (transfer_id, file_name, size_bytes, sha256),
        _ => return Err(NetworkTransferError::Protocol("expected transfer offer".into())),
    };
    if !validate_file_name(&file_name) {
        write_frame(stream, &ControlMessage::TransferRejected { transfer_id, reason: "unsafe filename".into() }).await?;
        return Err(NetworkTransferError::Protocol("unsafe filename".into()));
    }
    if !approve(&file_name, size_bytes, &sha256) {
        write_frame(stream, &ControlMessage::TransferRejected { transfer_id, reason: "declined by recipient".into() }).await?;
        return Err(NetworkTransferError::Rejected("declined by recipient".into()));
    }

    fs::create_dir_all(destination_dir).await?;
    fs::create_dir_all(state_dir).await?;
    let manifest_path = state_dir.join(format!("{}.tomos-transfer.json", transfer_id));
    let partial_path = state_dir.join(format!("{}.tomos-transfer.part", transfer_id));
    let mut manifest = if fs::try_exists(&manifest_path).await? {
        let loaded = ResumeManifest::load(&manifest_path).await
            .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        if !loaded.matches_offer(transfer_id, &file_name, size_bytes, &sha256) {
            return Err(NetworkTransferError::Protocol("resume state does not match this transfer offer".into()));
        }
        loaded.recover_partial(&partial_path).await
            .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        loaded
    } else {
        let fresh = ResumeManifest::new(transfer_id, file_name.clone(), size_bytes, sha256.clone(), DEFAULT_CHUNK_SIZE as u32)
            .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        fresh.save_atomic(&manifest_path).await.map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        fresh
    };

    let offset = manifest.committed_bytes;
    let prefix_sha256 = if offset == 0 { String::new() } else { hash_prefix(&partial_path, offset).await? };
    write_frame(stream, &ControlMessage::TransferResumeAccepted { transfer_id, offset, prefix_sha256 }).await?;

    let started = Instant::now();
    let mut remaining = size_bytes.saturating_sub(offset);
    while remaining > 0 {
        let count = remaining.min(manifest.chunk_size as u64) as usize;
        let mut chunk = vec![0_u8; count];
        stream.read_exact(&mut chunk).await?;
        manifest.append_chunk(&partial_path, manifest.committed_bytes, &chunk).await
            .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        manifest.save_atomic(&manifest_path).await
            .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
        remaining -= count as u64;
        let elapsed = started.elapsed().as_secs_f64().max(0.001);
        on_progress(TransferProgress {
            bytes_received: manifest.committed_bytes,
            total_bytes: size_bytes,
            bytes_per_second: ((manifest.committed_bytes - offset) as f64 / elapsed) as u64,
        });
    }

    let destination = destination_dir.join(&file_name);
    let result_path = manifest.finalize(&partial_path, &destination).await
        .map_err(|e| NetworkTransferError::Protocol(e.to_string()))?;
    let _ = fs::remove_file(&manifest_path).await;
    let result = TransferResult { path: result_path, bytes_received: size_bytes, sha256: sha256.clone() };
    write_frame(stream, &ControlMessage::TransferComplete { transfer_id, sha256 }).await?;
    Ok(result)
}
