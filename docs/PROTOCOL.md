# TomOS Transfer protocol (v1 draft)

## Trust boundary
A peer discovered on the local network is untrusted. Discovery metadata is a hint only; it does not authenticate a device. No file offer or payload may be accepted until the peer completes authenticated pairing and the transport is encrypted.

## Initial control messages
The Rust core defines versioned messages for pairing, transfer offers, acceptance/rejection, completion and cancellation. Binary file data is streamed separately in bounded chunks.

## File safety
- Remote names must be a single filename, not a path.
- Chunks are limited to 1 MiB; the default target is 256 KiB.
- The receiver creates files exclusively and never overwrites an existing path.
- The receiver checks the offered byte count and SHA-256 digest.
- A failed receive removes its partial output.

## Planned next protocol work
1. Define mutual device authentication using a reviewed cryptographic handshake.
2. Add TLS 1.3 with device identity binding.
3. Add mDNS discovery, treating advertisements as untrusted.
4. Require explicit user approval for incoming transfers.
5. Add resumable manifests with per-chunk integrity and atomic finalisation.

This crate currently provides transfer primitives only. It is not yet a network-ready transfer application.
