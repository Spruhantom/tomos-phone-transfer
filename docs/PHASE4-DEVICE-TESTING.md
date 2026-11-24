# Phase 4 physical-device validation

This checklist is for testing the Android application against a second Android
device and the Linux CLI. Emulator CI validates Android code and storage APIs,
but it does not replace testing on real Wi-Fi hardware.

## Prepare

1. Download the `tomos-transfer-debug-apk` artifact from the latest successful
   Android CI run and install it on the Android test device(s).
2. Use devices on the same trusted Wi-Fi network. Disable guest/client isolation
   and VPNs for the initial LAN test.
3. Record the app version, Android version, device model, Wi-Fi network, and
   CI run URL. Do not record private keys or pairing tokens.
4. Choose a test file and calculate its SHA-256 checksum before sending.

## Android to Android

1. On device A, open TomOS Transfer and start a receive session.
2. Confirm that the app displays a QR invitation and listening state.
3. On device B, scan A's QR invitation and select the test file.
4. Confirm the peer identity on the receiving device, then separately approve
   the incoming file.
5. Wait for both sides to report completion.
6. Compare the received file's SHA-256 checksum with the source checksum.
7. Repeat with a different file name and a larger file.

Record: both device models/Android versions, file size, elapsed time, result,
and whether progress/completion matched on both sides.

## Android to Linux

On a Linux machine with a logged-in Secret Service and `secret-tool` installed:

```sh
cargo build --release -p tomos-transfer-linux
cargo run --release -p tomos-transfer-linux -- receive <LAN-IP> ~/Downloads/TomosReceived
```

1. Scan the QR payload shown by the Linux receiver using Android.
2. Select a test file on Android.
3. Approve the Android peer and file offer in the Linux terminal.
4. Verify the resulting file checksum on Linux:

```sh
sha256sum ~/Downloads/TomosReceived/<received-file>
```

Compare the checksum with the source file's checksum.

## Interrupted transfer and resume

1. Start with a file large enough to transfer for several minutes.
2. Start a transfer and wait until measurable progress is displayed.
3. Interrupt the network (toggle Wi-Fi off on the sender or receiver) or
   terminate the sender process. Record the bytes transferred and transfer ID.
4. Restore the network and start a fresh receiver invitation. The QR token is
   single-use and must not be reused.
5. Retry the same transfer using the same transfer UUID where the client
   interface exposes it. The receiver must retain its resume-state directory.
6. Verify that the final file is complete, has the original checksum, and was
   not published as a partial file.

The current Android UI may not yet expose a resume/retry control. If it does
not, record the interruption as a blocked manual test rather than claiming
resume has passed.

## Receiver cancellation

1. Start a receiver and leave it waiting for a connection.
2. Close/cancel the receiver from the app.
3. Confirm the UI returns promptly and the listening socket is released.
4. Repeat while a sender is attempting to connect and during an active transfer.
5. Confirm a subsequent receiver can bind and display a fresh QR invitation.

## Result template

For each run record:

- Test case and date/time
- Sender and receiver platform/version
- Network type and topology
- File size and source SHA-256
- Transfer ID (if applicable)
- Result: pass / fail / blocked
- Observed error or unexpected behaviour
- Received file SHA-256 and final file size
- CI run and APK artifact used

Do not mark a physical-device case as passed based only on emulator CI.
