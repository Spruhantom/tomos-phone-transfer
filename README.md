# TomOS Transfer

A free, open-source, offline-first device migration application for Android and Linux.

The project uses a shared Rust transfer engine with native Android (Kotlin/Jetpack Compose) and Linux (GTK4/Libadwaita) front ends.

## Core engine status

Phase 1 implementation is in progress on the `phase1/core-transfer-engine` branch.

Implemented in the core crate:
- Ed25519 device identities and signed challenge-response authentication.
- Expiring QR pairing invitations containing the device identity, endpoint, TLS certificate and SHA-256 certificate fingerprint.
- One-time invitation token guard.
- TLS 1.3 server/client configurations with certificate pinning from the QR invitation.
- mDNS service advertisement and browsing for local network discovery.
- TCP device connection helpers.
- File offer/accept/reject/completion control messages.
- Bounded streaming file transfer, progress callbacks, size and SHA-256 verification.
- Resume manifests, durable chunk checkpoints, prefix verification and recovery after a process interruption.
- Tests for identity proof, stream transfer, checkpoint recovery and a local TLS/TCP device transfer.

## Security model

1. mDNS advertisements are discovery hints only; they do not establish trust.
2. The QR invitation carries the inviter's public identity, TLS certificate and certificate fingerprint.
3. The scanner validates the certificate fingerprint and pins the certificate for TLS 1.3.
4. Both devices prove possession of their Ed25519 identity keys using fresh challenges.
5. The inviter checks a short-lived, single-use QR token and asks the user to approve the new device.
6. Incoming file offers require a separate user approval.
7. File names are validated, existing files are not overwritten, and completed files are SHA-256 verified.

Private Ed25519 and TLS keys must be persisted using Android Keystore or Linux Secret Service. The core exposes key material import/export for platform adapters but does not write secrets to ordinary shared storage.

## Resumable transfers

The sender must reuse the same transfer ID when retrying. The receiver stores a manifest and partial file in an application-private state directory. Each chunk is synced and checkpointed; recovery truncates bytes written after the last committed checkpoint, verifies committed chunk hashes, and resumes from the saved offset. Final publication checks the complete file hash and does not overwrite an existing destination.

For reliable atomic finalisation, keep the resume state directory and destination directory on the same filesystem.

## Build and test

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
```

GitHub Actions runs these checks for pushes to the main and Phase 1 branches and for pull requests.

## Current limitations

- The native Android and Linux user interfaces are not yet implemented.
- Platform secure-key storage adapters are not yet implemented.
- The mDNS service is a LAN discovery mechanism; it does not provide internet-wide discovery or NAT traversal.
- USB transport is planned separately.
- Android SMS, call history and application data migration depend on Android permissions and OS restrictions.

## License

License to be selected before the first public release.
