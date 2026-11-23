# Android application

The Android application lives in :android and uses Kotlin, Jetpack Compose,
Android Keystore, Android NSD, and ZXing QR scanning. It shares the Rust transfer
engine with the Linux client through UniFFI.

## Device identity storage

AndroidIdentityStore generates a random 32-byte Ed25519 seed and a stable UUID
on first launch. The seed is encrypted with an AES-256-GCM wrapping key held by
Android Keystore. The encrypted record is stored under noBackupFilesDir,
excluded from Android backup, and authenticated with a versioned record header.

The store deliberately fails closed if an existing identity record cannot be
decrypted. It does not silently replace a lost or invalid identity.

The UniFFI TransferIdentity object restores this identity into a long-lived
Rust handle. The seed is passed only in process memory and the Kotlin caller
must clear its temporary byte array after construction.

## TLS identity storage

TlsIdentityHandle generates or restores the TLS leaf certificate and key.
AndroidTlsIdentityStore encrypts the certificate and private-key DER with
AES-256-GCM under the same non-exportable Android Keystore wrapping key. The
private key is returned to Rust only when restoring the TLS handle and must
never be logged or written to ordinary files.

## Native engine API

The current UniFFI surface provides:

- Long-lived Ed25519 identity handles and challenge-proof generation.
- TLS identity generation/restoration and secure-storage export.
- Pairing QR payload generation and Rust-side invitation validation.
- Receiver creation that binds the socket before returning the corresponding QR.
- A one-shot resumable receive operation with explicit peer/file approval and
  progress callbacks.
- Authenticated file sending with a caller-supplied stable transfer UUID.

The receiving API consumes each QR token once. After an interrupted session,
the receiver creates a fresh invitation while retaining its resume-state
directory; the sender retries using the same transfer UUID.

## Android interaction layer

- QR scanner reads TomOS Transfer pairing invitations.
- Android NSD browses for _tomos-transfer._tcp devices on the local network.
- The system document picker selects files without broad storage permissions.
- Nearby discovery entries remain untrusted hints until the Rust handshake
  authenticates the peer.

QR parsing is not authentication. A transfer requires the QR-pinned TLS 1.3
connection, mutual Ed25519 challenge-response, one-time token validation, and
explicit peer/file approval.

## Build

Requirements: JDK 17, Android SDK platform 35, Android NDK 27.2.12479018,
Rust stable, cargo-ndk, and Gradle 8.9.

```sh
cargo install cargo-ndk --locked
bash scripts/build-android-native.sh
gradle :android:assembleDebug
```

The script builds native libraries for arm64-v8a, armeabi-v7a, and x86_64 and
generates Kotlin bindings using the workspace-local UniFFI bindgen executable.

## Current boundaries

- The Rust bridge and receive/send APIs are implemented, but the Compose UI has
  not yet been wired to those APIs.
- Android listener lifecycle, QR rendering for the local receiver, content-URI
  staging, approval prompts, progress UI, and resume controls remain to be
  connected.
- Android-to-Android and Android-to-Linux physical-device tests remain
  outstanding.
