# TomOS Transfer

A free, open-source, offline-first device migration application for Android and Linux.

The project uses a shared Rust transfer engine with native Android (Kotlin/Jetpack Compose) and Linux (GTK4/Libadwaita) front ends.

## Development status

Phase 1 — Core transfer engine is under development.

The first milestone establishes the shared Rust workspace, safe transfer primitives, device identity model, chunked streaming, integrity verification, and protocol documentation. Network discovery and authenticated encrypted sessions will be added on top of these primitives.

## Security principles

- Device-to-device transfers; no cloud storage or central file relay.
- Explicit pairing and authenticated peers before accepting data.
- Encrypted transport for all network transfers.
- File paths are treated as untrusted input and constrained to a chosen destination.
- SHA-256 integrity verification for completed files.
- No silent overwrite of existing destination files.

## License

License to be selected before the first public release.
