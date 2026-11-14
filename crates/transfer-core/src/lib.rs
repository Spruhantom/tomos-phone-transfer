//! Shared, platform-independent primitives for TomOS Transfer.
//! All network payloads must run over TLS 1.3 and complete identity authentication
//! before the application invokes the file transfer functions.
pub mod auth;
pub mod chunks;
pub mod device;
pub mod discovery;
pub mod identity;
pub mod network;
pub mod pairing;
pub mod protocol;
pub mod resume;
pub mod tls;
pub mod tcp;
pub mod transfer;
pub mod verification;
pub mod ffi;

uniffi::setup_scaffolding!();

pub use device::{DeviceIdentity, DeviceInfo};
pub use transfer::{receive_file, TransferError, TransferProgress, TransferResult};
