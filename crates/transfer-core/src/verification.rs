use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("I/O error while hashing file: {0}")] Io(#[from] std::io::Error),
}

pub async fn sha256_reader<R>(reader: &mut R) -> Result<[u8; 32], VerificationError>
where R: AsyncRead + Unpin {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

pub fn to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
