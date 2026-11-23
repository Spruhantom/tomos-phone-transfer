use crate::{
    chunks::validate_chunk,
    protocol::{validate_file_name, MAX_CHUNK_SIZE},
    verification::{sha256_reader, to_hex},
};
use std::{path::{Path, PathBuf}, time::Instant};
use thiserror::Error;
use tokio::{fs::{self, OpenOptions}, io::{AsyncRead, AsyncReadExt, AsyncWriteExt}};

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("invalid remote file name")] InvalidFileName,
    #[error("destination already exists")] DestinationExists,
    #[error("incoming file exceeded the offered size")] SizeExceeded,
    #[error("incoming file size did not match the offer")] SizeMismatch,
    #[error("SHA-256 checksum did not match the offer")] ChecksumMismatch,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("verification error: {0}")] Verification(#[from] crate::verification::VerificationError),
}

#[derive(Clone, Debug, Default)]
pub struct TransferProgress {
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub bytes_per_second: u64,
}

#[derive(Clone, Debug)]
pub struct TransferResult {
    pub path: PathBuf,
    pub bytes_received: u64,
    pub sha256: String,
}

/// Receives a file with bounded memory. Call only after peer authentication,
/// encrypted transport establishment, and explicit user acceptance.
/// Existing files are never overwritten; failed partial files are removed.
pub async fn receive_file<R, F>(
    reader: &mut R, destination_dir: &Path, remote_name: &str,
    expected_size: u64, expected_sha256: &str, chunk_size: usize,
    mut on_progress: F,
) -> Result<TransferResult, TransferError>
where R: AsyncRead + Unpin, F: FnMut(TransferProgress) {
    if !validate_file_name(remote_name) { return Err(TransferError::InvalidFileName); }
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(TransferError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid chunk size")));
    }

    fs::create_dir_all(destination_dir).await?;
    let destination = destination_dir.join(remote_name);
    let mut output = match OpenOptions::new().write(true).create_new(true).open(&destination).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(TransferError::DestinationExists),
        Err(error) => return Err(error.into()),
    };

    let started = Instant::now();
    let mut received = 0_u64;
    let mut buffer = vec![0_u8; chunk_size];
    let result = async {
        loop {
            let count = reader.read(&mut buffer).await?;
            if count == 0 { break; }
            validate_chunk(&buffer[..count], count)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            received = received.saturating_add(count as u64);
            if received > expected_size { return Err(TransferError::SizeExceeded); }
            output.write_all(&buffer[..count]).await?;
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            on_progress(TransferProgress {
                bytes_received: received,
                total_bytes: expected_size,
                bytes_per_second: (received as f64 / elapsed) as u64,
            });
        }
        output.flush().await?;
        output.sync_all().await?;
        if received != expected_size { return Err(TransferError::SizeMismatch); }
        drop(output);

        let mut file = fs::File::open(&destination).await?;
        let digest = to_hex(&sha256_reader(&mut file).await?);
        if !digest.eq_ignore_ascii_case(expected_sha256) { return Err(TransferError::ChecksumMismatch); }
        Ok(TransferResult { path: destination.clone(), bytes_received: received, sha256: digest })
    }.await;

    if result.is_err() { let _ = fs::remove_file(&destination).await; }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn receives_and_verifies_file() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"TomOS Transfer test";
        let digest = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(data))
        };
        let mut source = BufReader::new(&data[..]);
        let result = receive_file(&mut source, dir.path(), "sample.txt", data.len() as u64, &digest, 4, |_| {}).await.unwrap();
        assert_eq!(tokio::fs::read(result.path).await.unwrap(), data);
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = BufReader::new(&b"x"[..]);
        let result = receive_file(&mut source, dir.path(), "../escape", 1, "", 1024, |_| {}).await;
        assert!(matches!(result, Err(TransferError::InvalidFileName)));
    }

    #[tokio::test]
    async fn never_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("same.txt"), b"keep").await.unwrap();
        let mut source = BufReader::new(&b"new"[..]);
        let result = receive_file(&mut source, dir.path(), "same.txt", 3, "", 1024, |_| {}).await;
        assert!(matches!(result, Err(TransferError::DestinationExists)));
        assert_eq!(tokio::fs::read(dir.path().join("same.txt")).await.unwrap(), b"keep");
    }
}
