# Android application foundation

The Android application lives in `:android` and uses Kotlin, Jetpack Compose,
Android Keystore, Android NSD, and ZXing QR scanning. It is intended to share the
Rust transfer engine with the Linux client; the native Rust bridge is a separate
integration step and is not yet wired into the UI.

## Device identity storage

`AndroidIdentityStore` generates a random 32-byte Ed25519 seed and a stable UUID
on first launch. The seed is encrypted with an AES-256-GCM wrapping key held by
Android Keystore. The encrypted record is stored under `noBackupFilesDir`,
excluded from Android backup, and authenticated with a versioned record header.

The store deliberately fails closed if an existing identity record cannot be
decrypted. It does not silently replace a lost or invalid identity, because doing
so would create a different device identity and invalidate existing trust.

The Rust core can restore its `LocalIdentity` from the UUID and seed using
`LocalIdentity::from_secret`. The bridge must pass the seed only in process
memory, never log it, and clear temporary byte arrays after importing it.

## Android interaction layer

- QR scanner reads TomOS Transfer pairing invitations.
- The invitation parser validates protocol version, device UUID, key length,
  endpoint, expiry, one-time token shape, and SHA-256 certificate fingerprint.
- Android NSD browses for `_tomos-transfer._tcp` devices on the local network.
- The system document picker selects files without broad storage permissions.
- Nearby discovery entries are displayed as untrusted hints only.

QR parsing is not authentication. The Rust engine must still validate the pinned
certificate, perform TLS 1.3, complete mutual Ed25519 challenge-response, consume
the one-time invitation token, and request user approval before transferring.

## Build

Requirements: JDK 17, Android SDK platform 35, and Gradle 8.9.

```sh
gradle :android:assembleDebug
```

## Current boundaries

- The Compose UI is an initial interaction layer, not a completed transfer client.
- JNI/UniFFI bridge to `tomos-transfer-core` is not implemented yet.
- QR invitation validation is local only; it does not open a network connection.
- mDNS discovery does not automatically trust or connect to devices.
- File selection does not start a transfer until the Rust bridge is available.
- Listener lifecycle, incoming transfer approval, transfer progress and resume UI
  remain to be implemented.
- Physical-device tests across Android and Linux remain outstanding.
