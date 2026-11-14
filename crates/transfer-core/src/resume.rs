use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
use thiserror::Error;
use tokio::{fs::{self, OpenOptions}, io::AsyncWriteExt};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeManifest {
    pub transfer_id: uuid::Uuid,
    pub file_name: String,
    pub total_bytes: u64,
    pub expected_sha256: String,
    pub chunk_size: u32,
    pub committed_bytes: u64,
    pub chunk_sha256: Vec<String>,
    pub updated_at_unix: u64,
}

#[derive(Debug, Error)]
pub enum ResumeError {
    #[error("resume metadata does not match the offered transfer")] MetadataMismatch,
    #[error("resume offset is not the next expected byte")] InvalidOffset,
    #[error("chunk is too large or has an invalid digest")] InvalidChunk,
    #[error("partial file size does not match its checkpoint")] PartialFileMismatch,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("manifest error: {0}")] Manifest(String),
}

impl ResumeManifest {
    pub fn new(transfer_id: uuid::Uuid, file_name: String, total_bytes: u64, expected_sha256: String, chunk_size: u32) -> Result<Self, ResumeError> {
        if chunk_size == 0 || chunk_size > 1024 * 1024 { return Err(ResumeError::InvalidChunk); }
        Ok(Self { transfer_id, file_name, total_bytes, expected_sha256, chunk_size, committed_bytes: 0, chunk_sha256: Vec::new(), updated_at_unix: now()? })
    }

    pub async fn save_atomic(&mut self, path: &Path) -> Result<(), ResumeError> {
        self.updated_at_unix = now()?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| ResumeError::Manifest(e.to_string()))?;
        let temp = path.with_extension("tmp");
        let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&temp).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(temp, path).await?;
        Ok(())
    }

    pub async fn load(path: &Path) -> Result<Self, ResumeError> {
        let bytes = fs::read(path).await?;
        serde_json::from_slice(&bytes).map_err(|e| ResumeError::Manifest(e.to_string()))
    }

    pub fn matches_offer(&self, transfer_id: uuid::Uuid, file_name: &str, total_bytes: u64, sha256: &str) -> bool {
        self.transfer_id == transfer_id && self.file_name == file_name
            && self.total_bytes == total_bytes && self.expected_sha256.eq_ignore_ascii_case(sha256)
    }

    pub async fn verify_partial(&self, partial_path: &Path) -> Result<(), ResumeError> {
        let metadata = fs::metadata(partial_path).await?;
        if metadata.len() != self.committed_bytes { return Err(ResumeError::PartialFileMismatch); }
        Ok(())
    }

    /// Append one sequential chunk and persist its digest checkpoint. A chunk is
    /// committed only after the partial file has been flushed and synced.
    pub async fn append_chunk(&mut self, partial_path: &Path, offset: u64, bytes: &[u8]) -> Result<(), ResumeError> {
        if offset != self.committed_bytes { return Err(ResumeError::InvalidOffset); }
        if bytes.is_empty() || bytes.len() > self.chunk_size as usize
            || self.committed_bytes.saturating_add(bytes.len() as u64) > self.total_bytes {
            return Err(ResumeError::InvalidChunk);
        }
        let digest = format!("{:x}", Sha256::digest(bytes));
        let mut file = OpenOptions::new().create(true).append(true).open(partial_path).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        self.committed_bytes += bytes.len() as u64;
        self.chunk_sha256.push(digest);
        Ok(())
    }

    pub async fn finalize(self, partial_path: &Path, destination: &Path) -> Result<PathBuf, ResumeError> {
        self.verify_partial(partial_path).await?;
        if self.committed_bytes != self.total_bytes { return Err(ResumeError::PartialFileMismatch); }
        let data = fs::read(partial_path).await?;
        let actual = format!("{:x}", Sha256::digest(&data));
        if !actual.eq_ignore_ascii_case(&self.expected_sha256) { return Err(ResumeError::InvalidChunk); }
        if fs::try_exists(destination).await? { return Err(ResumeError::MetadataMismatch); }
        fs::rename(partial_path, destination).await?;
        Ok(destination.to_path_buf())
    }
}

fn now() -> Result<u64, ResumeError> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).map_err(|e| ResumeError::Manifest(e.to_string()))
}
