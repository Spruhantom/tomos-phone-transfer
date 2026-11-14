use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Versioned control messages. File payloads use bounded binary chunks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    PairingRequest { device_id: Uuid, protocol_version: u16, nonce: String },
    PairingAccepted { device_id: Uuid, protocol_version: u16 },
    TransferOffer { transfer_id: Uuid, file_name: String, size_bytes: u64, sha256: String },
    TransferAccepted { transfer_id: Uuid },
    TransferResumeAccepted { transfer_id: Uuid, offset: u64 },
    TransferRejected { transfer_id: Uuid, reason: String },
    TransferComplete { transfer_id: Uuid, sha256: String },
    CancelTransfer { transfer_id: Uuid },
}

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;
pub const MAX_FILE_NAME_BYTES: usize = 255;

pub fn validate_file_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_FILE_NAME_BYTES && name != "." && name != ".."
        && !name.contains('/') && !name.contains('\\') && !name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_name_validation_blocks_paths() {
        assert!(validate_file_name("holiday.jpg"));
        assert!(!validate_file_name("../secret"));
        assert!(!validate_file_name("folder/file.txt"));
        assert!(!validate_file_name(".."));
    }
    #[test]
    fn protocol_message_round_trips() {
        let msg = ControlMessage::TransferAccepted { transfer_id: Uuid::nil() };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, decoded);
    }
}
