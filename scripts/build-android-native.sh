#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

: "${ANDROID_NDK_HOME:=${ANDROID_NDK_ROOT:-}}"
if [[ -z "$ANDROID_NDK_HOME" ]]; then
  echo "ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must point to an installed Android NDK." >&2
  exit 2
fi
export ANDROID_NDK_HOME

rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o android/src/main/jniLibs \
  build --release -p tomos-transfer-core

BINDGEN_LIB="android/src/main/jniLibs/arm64-v8a/libtomos_transfer_core.so"
test -f "$BINDGEN_LIB"
mkdir -p android/src/main/java
cargo run --release -p uniffi-bindgen -- generate \
  --library "$BINDGEN_LIB" \
  --language kotlin \
  --out-dir android/src/main/java

# Guard the Android API 26 minimum: UniFFI must generate the JNA cleaner,
# not java.lang.ref.Cleaner (which requires API 33 on Android).
if grep -R -n -F "java.lang.ref.Cleaner.create()" android/src/main/java; then
  echo "Generated UniFFI bindings reference API 33 Cleaner; check crates/transfer-core/uniffi.toml." >&2
  exit 1
fi

echo "Android Rust libraries and API 26-compatible Kotlin UniFFI bindings generated."
