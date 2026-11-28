# Android testing strategy

The default Android CI deliberately does **not** boot an Android emulator. GitHub-hosted
emulators have repeatedly crashed before starting the instrumentation process, even
though native compilation, JVM tests, APK assembly and artifact upload succeed.

## Automated checks on every Android CI run

1. Build the shared Rust libraries and generate UniFFI Kotlin bindings for Android ABIs.
2. Run `gradle :android:testDebugUnitTest`, including Robolectric tests. These run on
   the hosted JVM and cover Android framework-dependent logic such as QR invitation
   parsing without starting an emulator.
3. Compile the device instrumentation APK with `gradle :android:assembleDebugAndroidTest`.
   This catches instrumentation test source and packaging errors without launching a device.
4. Run Android Lint.
5. Assemble and publish the debug APK and native bridge artifacts.

The existing `androidTest` suite remains available for a real device or a developer's
working emulator. It is not treated as a required hosted-CI gate.

## Physical Android device test

Use a real Android phone connected by USB with Developer options and USB debugging enabled.
Install Android Platform Tools on the computer, then:

```bash
adb devices
adb install -r app-debug.apk
adb logcat -c
```

Open TomOS Transfer and verify the following, recording the phone model and Android version:

- App launches and reports that its secure device identity is ready.
- Close and reopen the app; the same device identity is restored.
- Create a receive QR code and scan it from a second device.
- Reject an unexpected peer and confirm no transfer starts.
- Approve a known peer and a test file; confirm the received bytes and SHA-256 match.
- Reject a file and confirm it is not saved.
- Stop a receiver and confirm it closes.
- Interrupt a transfer, retry it, and verify the final file is complete and uncorrupted.
- Repeat over Wi-Fi and, where available, a mobile hotspot.

Collect logs after reproducing an issue:

```bash
adb logcat -d -v threadtime > tomos-transfer-device-logcat.txt
```

Do not use real personal files for test transfers. Use disposable test files and remove
them after verification.

## What CI does not prove

Robolectric does not reproduce hardware-backed Android Keystore, camera scanning,
Wi-Fi multicast discovery, or real socket behaviour across two phones. Those checks
must be completed on physical Android devices. A green JVM build is not a substitute
for the two-device transfer acceptance test.
