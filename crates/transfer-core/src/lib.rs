//! Shared, platform-independent primitives for TomOS Transfer.
//! Network transports must authenticate peers and encrypt sessions before accepting data.
pub mod chunks;
pub mod device;
pub mod protocol;
pub mod transfer;
pub mod verification;

pub use device::{DeviceIdentity, DeviceInfo};
pub use transfer::{receive_file, TransferError, TransferProgress, TransferResult};
