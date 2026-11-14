# Android application foundation

The Android application lives in `:android` and uses Kotlin, Jetpack Compose, and
Android Keystore. It is intended to share the Rust transfer engine with the Linux
client; the native Rust bridge is a separate integration step and is not yet wired
into the UI.

## Device identity storage

`AndroidIdentityStore` generates a random 32-byte Ed25519 seed and a stable UUID
on first launch. The seed is encrypted with AES-256-GCM using a non-exportable
wrapping key held by Android Keystore. The encrypted record is stored under
`noBackupFilesDir`, excluded from Android backup, and authenticated with a
versioned record header.

The store deliberately fails closed if an existing identity record cannot be
decrypted. It does not silently replace a lost or invalid identity, because doing
so would create a different device identity and invalidate existing trust.

The Rust core can restore its `LocalIdentity` from the UUID and seed using
`LocalIdentity::from_secret`. The bridge must pass the seed only in process
memory, never log it, and clear temporary byte arrays after importing it.

## Build

Requirements: JDK 17, Android SDK platform 35, and Gradle 8.9.

```sh
gradle :android:assembleDebug
```

## Current boundaries

- The Compose screen is an initial app shell, not a completed transfer UI.
- QR scanning, file selection, mDNS browsing, TCP listener lifecycle, and transfer
  progress UI are not connected yet.
- The JNI/UniFFI bridge to `tomos-transfer-core` is the next integration task.
- No private identity material is included in QR invitations or discovery records.
