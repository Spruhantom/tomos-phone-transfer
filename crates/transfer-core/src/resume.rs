use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
use thiserror::Error;
use tokio::{fs::{self, OpenOptions, File}, io::{AsyncReadExt, AsyncWriteExt}};

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
    #[error("partial file size or checkpoint does not match")] PartialFileMismatch,
    #[error("destination already exists")] DestinationExists,
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

    /// Reconcile a crash that occurred after writing file bytes but before saving
    /// the manifest: truncate uncommitted tail bytes, then verify every checkpoint.
    pub async fn recover_partial(&self, partial_path: &Path) -> Result<(), ResumeError> {
        if !fs::try_exists(partial_path).await? && self.committed_bytes == 0 {
            OpenOptions::new().create_new(true).write(true).open(partial_path).await?;
        }
        let file = OpenOptions::new().write(true).open(partial_path).await?;
        let actual_len = file.metadata().await?.len();
        if actual_len < self.committed_bytes { return Err(ResumeError::PartialFileMismatch); }
        if actual_len > self.committed_bytes { file.set_len(self.committed_bytes).await?; }
        drop(file);

        let mut input = File::open(partial_path).await?;
        let mut remaining = self.committed_bytes;
        for expected in &self.chunk_sha256 {
            if remaining == 0 { return Err(ResumeError::PartialFileMismatch); }
            let length = remaining.min(self.chunk_size as u64) as usize;
            let mut bytes = vec![0; length];
            input.read_exact(&mut bytes).await?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if !actual.eq_ignore_ascii_case(expected) { return Err(ResumeError::PartialFileMismatch); }
            remaining -= length as u64;
        }
        if remaining != 0 { return Err(ResumeError::PartialFileMismatch); }
        Ok(())
    }

    pub async fn append_chunk(&mut self, partial_path: &Path, offset: u64, bytes: &[u8]) -> Result<(), ResumeError> {
        if offset != self.committed_bytes { return Err(ResumeError::InvalidOffset); }
        if bytes.is_empty() || bytes.len() > self.chunk_size as usize
            || self.committed_bytes.saturating_add(bytes.len() as u64) > self.total_bytes {
            return Err(ResumeError::InvalidChunk);
        }
        if fs::try_exists(partial_path).await? {
            let metadata = fs::metadata(partial_path).await?;
            if metadata.len() != self.committed_bytes { return Err(ResumeError::PartialFileMismatch); }
        } else if self.committed_bytes != 0 {
            return Err(ResumeError::PartialFileMismatch);
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
        self.recover_partial(partial_path).await?;
        if self.committed_bytes != self.total_bytes { return Err(ResumeError::PartialFileMismatch); }
        let mut file = File::open(partial_path).await?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).await?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        let actual = format!("{:x}", hasher.finalize());
        if !actual.eq_ignore_ascii_case(&self.expected_sha256) { return Err(ResumeError::InvalidChunk); }
        match fs::hard_link(partial_path, destination).await {
            Ok(()) => fs::remove_file(partial_path).await?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(ResumeError::DestinationExists),
            Err(error) => return Err(error.into()),
        }
        Ok(destination.to_path_buf())
    }
}

fn now() -> Result<u64, ResumeError> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).map_err(|e| ResumeError::Manifest(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn checkpoints_and_recovers_after_uncommitted_tail() {
        let dir = tempfile::tempdir().unwrap();
        let partial = dir.path().join("partial");
        let manifest_path = dir.path().join("transfer.json");
        let destination = dir.path().join("final.bin");
        let data = b"abcdefgh";
        let digest = format!("{:x}", Sha256::digest(data));
        let mut manifest = ResumeManifest::new(uuid::Uuid::new_v4(), "final.bin".into(), 8, digest, 4).unwrap();
        manifest.append_chunk(&partial, 0, b"abcd").await.unwrap();
        manifest.save_atomic(&manifest_path).await.unwrap();
        // Simulate a process dying after writing bytes but before committing metadata.
        let mut tail = OpenOptions::new().append(true).open(&partial).await.unwrap();
        tail.write_all(b"junk").await.unwrap();
        tail.sync_all().await.unwrap();
        let mut restored = ResumeManifest::load(&manifest_path).await.unwrap();
        restored.recover_partial(&partial).await.unwrap();
        assert_eq!(fs::metadata(&partial).await.unwrap().len(), 4);
        restored.append_chunk(&partial, 4, b"efgh").await.unwrap();
        let final_path = restored.finalize(&partial, &destination).await.unwrap();
        assert_eq!(fs::read(final_path).await.unwrap(), data);
    }
}
