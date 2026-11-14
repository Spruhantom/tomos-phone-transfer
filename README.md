# TomOS Transfer

A free, open-source, offline-first device migration application for Android and Linux.

The project uses a shared Rust transfer engine with native Android (Kotlin/Jetpack Compose) and Linux (GTK4/Libadwaita) front ends.

## Development status

### Phase 1 — Shared Rust transfer core

Implemented on `phase1/core-transfer-engine`:
- Ed25519 device identities and signed challenge-response authentication.
- Expiring QR pairing invitations with TLS certificate pinning.
- Single-use invitation tokens and explicit peer/file approval callbacks.
- TLS 1.3 transport and mDNS local-network discovery.
- TCP file transfer, bounded chunk streaming, progress callbacks and SHA-256 verification.
- Resumable transfers with durable chunk checkpoints and crash recovery.
- Rust formatting, compilation and workspace tests pass in GitHub Actions.

### Phase 2 — Android foundation

In progress on `phase2/android-foundation`:
- Native Kotlin/Jetpack Compose application module.
- Android Keystore AES-256-GCM wrapping key for the Ed25519 identity seed.
- Encrypted identity record in app-private, no-backup storage.
- Fail-closed handling when an existing identity cannot be decrypted.
- Android Gradle build workflow.

The Android UI is currently a foundation screen. The Rust JNI/UniFFI bridge, QR scanning, file selection, mDNS browsing, listener lifecycle and real transfer controls are not connected yet.

## Security model

1. mDNS advertisements are discovery hints only; they do not establish trust.
2. QR pairing pins the inviter's TLS certificate and identifies its Ed25519 public key.
3. Both devices prove possession of their identity keys using fresh challenges.
4. The inviter checks a short-lived, single-use QR token and asks the user to approve the new device.
5. Incoming file offers require separate user approval.
6. File names are validated, existing files are not overwritten, and completed files are SHA-256 verified.
7. Android private identity seeds are encrypted with an Android Keystore-held AES key. Linux key storage will use Secret Service.

## Resumable transfers

The sender reuses the same transfer ID when retrying. The receiver stores a manifest and partial file in an application-private state directory. Each chunk is synced and checkpointed; recovery truncates bytes written after the last committed checkpoint and verifies committed chunk hashes. Final publication verifies the complete file and does not overwrite an existing destination.

For reliable atomic finalisation, keep the resume state directory and destination directory on the same filesystem.

## Build and test

Rust core:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
```

Android application (JDK 17, Android SDK 35, Gradle 8.9):

```sh
gradle :android:assembleDebug
```

GitHub Actions validates the Rust workspace and builds the Android debug application.

## Current limitations

- The Android app foundation is not yet connected to the Rust engine.
- Linux UI and Secret Service adapter are not yet implemented.
- mDNS is LAN-only; there is no internet discovery, NAT traversal or relay.
- USB transport is planned separately.
- Android SMS, call history and application-data migration depend on Android permissions and OS restrictions.

## License

License to be selected before the first public release.
