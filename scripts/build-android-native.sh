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

echo "Android Rust libraries and Kotlin UniFFI bindings generated."
