use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable identifier generated locally for this installation.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DeviceIdentity { pub id: Uuid }

impl DeviceIdentity {
    pub fn generate() -> Self { Self { id: Uuid::new_v4() } }
}

/// Public discovery metadata only. Never put private keys or pairing secrets here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub identity: DeviceIdentity,
    pub display_name: String,
    pub platform: DevicePlatform,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform { Android, Linux, Unknown }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_identities_are_distinct() {
        assert_ne!(DeviceIdentity::generate(), DeviceIdentity::generate());
    }
}
