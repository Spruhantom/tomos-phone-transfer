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
- Native Kotlin/Jetpack Compose application.
- Android Keystore AES-256-GCM protection for the Ed25519 identity seed.
- Encrypted identity record in app-private, no-backup storage.
- QR scanning and local validation of pairing invitation envelopes, including certificate fingerprint.
- Android NSD browsing for nearby `_tomos-transfer._tcp` devices.
- System document picker for selecting files.
- Android Gradle build workflow.

The Android UI now supports selecting a file, scanning a pairing QR, and discovering LAN advertisements. These are interaction-layer features only: the native Rust bridge, authenticated socket connection, actual send/receive operations, and progress/resume controls are not connected yet.

## Security model

1. mDNS advertisements are discovery hints only; they do not establish trust.
2. QR pairing pins the inviter's TLS certificate and identifies its Ed25519 public key.
3. Both devices prove possession of their identity keys using fresh challenges.
4. The inviter checks a short-lived, single-use QR token and asks the user to approve the new device.
5. Incoming file offers require separate user approval.
6. File names are validated, existing files are not overwritten, and completed files are SHA-256 verified.
7. Android private identity seeds are encrypted with an Android Keystore-held AES key. Linux key storage will use Secret Service.

QR parsing in Android is not peer authentication. The Rust core remains responsible for TLS 1.3 certificate pinning, mutual identity proof, token consumption and transfer approval.

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

- JNI/UniFFI bridge to the Rust engine is not yet implemented.
- QR scanning, discovery and file selection do not yet initiate transfers.
- Android listener lifecycle, incoming approvals, progress and resume UI remain to do.
- Linux UI and Secret Service adapter are not yet implemented.
- mDNS is LAN-only; there is no internet discovery, NAT traversal or relay.
- USB transport is planned separately.
- Android SMS, call history and application-data migration depend on Android permissions and OS restrictions.

## License

License to be selected before the first public release.


## Native engine bridge (Phase 3)

Android and Linux are being connected to the same Rust transfer engine through UniFFI. The Rust crate is built as both an `rlib` and `cdylib`; the platform application owns secure persistence and passes the Ed25519 seed to an opaque Rust identity handle only when restoring the session.

The first exported operations cover identity restoration, public identity retrieval, challenge proofs, pairing QR payload generation, and scanned invitation validation. The QR certificate fingerprint is checked in Rust. A valid invitation is not by itself an authenticated session: the TLS 1.3 certificate pin and mutual Ed25519 challenge-response handshake must still complete before a transfer.

### Build Android native libraries and Kotlin bindings

Install Rust, Android SDK/NDK, `cargo-ndk`, and `uniffi-bindgen-cli` 0.29.4, then run:

```bash
bash scripts/build-android-native.sh
gradle :android:assembleDebug
```

The script builds Android ABI libraries for arm64-v8a, armeabi-v7a, and x86_64 under `android/src/main/jniLibs`, then generates Kotlin bindings into the Android source tree.

**Integration status:** the exported native identity and pairing surface is under development. The Android UI is not yet wired to the native listener, authenticated TLS transfer session, receive approval, progress callbacks, or resume controls. Linux secure-storage and UI adapters are also outstanding. Do not treat the current Android UI as a working file-transfer client yet.


## Linux client

The `tomos-transfer` Linux command-line client is part of the workspace and uses the same Rust transfer core as Android. Device identity seeds and the TLS private key are stored in the desktop Secret Service through `secret-tool`; neither is written to ordinary files.

Install the Secret Service command-line utility (Debian/Ubuntu: `sudo apt install libsecret-tools`) and build:

```bash
cargo build --release -p tomos-transfer-linux
```

Start a receiver, advertising an IP address reachable by the sender:

```bash
cargo run --release -p tomos-transfer-linux -- receive 192.168.1.20 ~/Downloads/Received
```

Scan the displayed pairing QR code from the sending device. To send from Linux, pass the scanned QR payload and file:

```bash
cargo run --release -p tomos-transfer-linux -- send 'tomos-transfer://pair/…' ./photo.jpg
```

The Linux receiver prompts separately to trust the peer and accept the offered file. Receiving uses the core's resumable checkpoint pipeline. The listener binds to all interfaces on an ephemeral TCP port; the host/IP printed into the QR is supplied by the operator and must be reachable from the peer.


The UniFFI surface now also includes opaque long-lived Ed25519 and TLS identity handles, TLS certificate/private-key export specifically for platform secure storage, a receiver factory that binds its socket before returning the matching QR payload, and an approved one-shot resumable receive operation with peer/file approval and progress callbacks. The Android TLS store encrypts the certificate/private-key record with the same non-exportable Android Keystore wrapping key as the device identity.

The sender bridge accepts a stable transfer UUID so a retry can resume against a receiver's checkpoint. The receiving side consumes each QR token once; after an interrupted session, the receiver must issue a fresh QR while retaining the resume state directory.
