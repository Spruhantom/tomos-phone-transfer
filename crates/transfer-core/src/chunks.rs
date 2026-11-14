use crate::protocol::MAX_CHUNK_SIZE;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChunkError {
    #[error("chunk exceeds the maximum permitted size")] TooLarge,
    #[error("chunk length does not match the expected length")] InvalidLength,
}

pub fn validate_chunk(data: &[u8], expected_len: usize) -> Result<(), ChunkError> {
    if data.len() > MAX_CHUNK_SIZE { return Err(ChunkError::TooLarge); }
    if data.len() != expected_len { return Err(ChunkError::InvalidLength); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_valid_chunk() { assert_eq!(validate_chunk(&[1, 2, 3], 3), Ok(())); }
    #[test]
    fn rejects_oversized_chunk() {
        assert_eq!(validate_chunk(&vec![0; MAX_CHUNK_SIZE + 1], MAX_CHUNK_SIZE + 1), Err(ChunkError::TooLarge));
    }
}
