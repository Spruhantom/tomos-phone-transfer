# TomOS Transfer protocol (v1 draft)

## Trust boundary

A peer discovered on the local network is untrusted. mDNS advertisements are hints only. No transfer is accepted until the devices complete the QR-authorised identity handshake and TLS 1.3 session setup.

## Pairing sequence

1. The receiving device creates a short-lived invitation (maximum ten minutes).
2. The QR payload contains the receiver's public Ed25519 identity, TCP endpoint, TLS certificate DER, certificate SHA-256 fingerprint, protocol version and random one-time token.
3. The scanning device checks the certificate fingerprint and trusts that exact certificate for the TLS 1.3 connection.
4. The devices exchange fresh random challenges and Ed25519 signatures over the TLS channel.
5. The receiver validates the single-use token and asks the user to approve the previously unknown sender identity.
6. A successful pairing should be persisted by the platform adapter; private keys belong in Android Keystore or Linux Secret Service.

TLS certificate pinning authenticates the TLS endpoint. The signed challenge exchange binds the application-level device identity to the session. Discovery metadata alone is never trusted.

## Transfer sequence

1. Sender transmits a bounded, length-prefixed JSON offer (transfer UUID, filename, byte count and SHA-256).
2. Receiver validates the filename and asks the user to approve the transfer.
3. Receiver returns accepted, rejected, or a resume offset with the SHA-256 of the committed prefix.
4. File bytes are streamed in chunks of up to 256 KiB (hard maximum 1 MiB).
5. Receiver checkpoints each chunk to a partial file and durable manifest.
6. Receiver verifies the complete byte count and SHA-256 before publishing the destination file.
7. Receiver sends a completion message containing the verified digest.

## Interrupted transfer recovery

The sender must reuse the original transfer UUID when retrying. The receiver loads the matching manifest, checks that the new offer has the same name, size and expected digest, truncates uncommitted tail bytes, verifies all committed chunk hashes, and returns its current offset and prefix digest. The sender verifies that prefix against its source before seeking to the offset and continuing.

The receiver only publishes the final file after verifying the complete SHA-256. Existing destinations are never overwritten. Keep the resume state and destination directories on the same filesystem so final publication can use a no-overwrite hard link.

## File safety

- Remote names must be a single filename, not a path.
- Control frames are limited to 64 KiB.
- Chunks are limited to 1 MiB; default transfer chunk size is 256 KiB.
- Incoming files are created without overwriting existing paths.
- Partial files remain in an application-private state directory.
- Failed or incomplete transfers are not exposed as completed files.

## Implementation boundaries

The Rust crate contains QR payload creation, identity challenge verification, TLS 1.3 configuration, mDNS service advertisement/browsing, TCP send/receive helpers and resumable file primitives. Platform adapters still need to persist keys securely, display QR codes, present device/file approval prompts, bind listeners to the intended LAN interface and manage transfer lifecycle.

mDNS is local-network discovery only. It does not provide internet-wide reachability, NAT traversal or a relay.
