#!/usr/bin/env bash
# Manual Android build for environments where Gradle cannot
# run (this VM's network policy intercepts the Gradle
# daemon's loopback TCP, so `gradlew assembleDebug` fails
# there; on a normal machine or Android Studio, prefer the
# Gradle build — this script is the fallback that produces
# the same debug APK from the same sources).
#
# Pipeline: kotlinc -> jar -> d8 -> aapt2 -> zipalign ->
# apksigner (debug key). Requires: JDK 21, kotlinc, the
# Android SDK (platform 34 + build-tools 34) and the Rust
# core built for aarch64-linux-android.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # mobile/
REPO="$(cd "$ROOT/.." && pwd)"                     # repo root
APP="$ROOT/android/app/src/main"
BUILD="$ROOT/android-build"
BT="${ANDROID_BUILD_TOOLS:-$HOME/tools/android-sdk/build-tools/34.0.0}"
AJ="${ANDROID_JAR:-$HOME/tools/android-sdk/platforms/android-34/android.jar}"
KOTLINC="${KOTLINC:-$HOME/tools/mobile/kotlinc/bin/kotlinc}"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/mobile/jdk}"
export PATH="$JAVA_HOME/bin:$PATH"

mkdir -p "$BUILD/classes" "$BUILD/dex" "$BUILD/stage/lib/arm64-v8a"

# 1. The Rust core for Android (arm64).
(cd "$REPO" && \
  NDK_BIN="$HOME/tools/android-sdk/ndk/26.3.11579264/toolchains/llvm/prebuilt/linux-x86_64/bin" \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android28-clang" \
  CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang" \
  cargo build -p poe-mobile --target aarch64-linux-android --release)
cp "$REPO/target/aarch64-linux-android/release/libpoe_mobile.so" \
   "$APP/jniLibs/arm64-v8a/libpoe_mobile.so"

# 2. Regenerate the UniFFI Kotlin bindings from the library.
(cd "$REPO" && cargo run -q -p poe-mobile --bin uniffi-bindgen -- generate \
  --library target/aarch64-linux-android/release/libpoe_mobile.so \
  --language kotlin --out-dir "$APP/java")

# 3. JNA (the bindings' runtime) — AAR from Maven Central.
if [ ! -f "$BUILD/jna-aar/classes.jar" ]; then
  curl -sSL -o /tmp/jna.aar \
    https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.14.0/jna-5.14.0.aar
  unzip -q -o /tmp/jna.aar -d "$BUILD/jna-aar"
fi

# 4. Compile the app + bindings.
"$KOTLINC" "$APP/java/app/poe/suite/MainActivity.kt" \
           "$APP/java/app/poe/suite/KeystoreCustody.kt" \
           "$APP/java/uniffi/poe_mobile/poe_mobile.kt" \
           -cp "$AJ:$BUILD/jna-aar/classes.jar" -d "$BUILD/classes"
(cd "$BUILD/classes" && jar cf "$BUILD/app-classes.jar" .)

# 5. Dex.
"$BT/d8" --lib "$AJ" --min-api 28 --output "$BUILD/dex" \
  "$BUILD/app-classes.jar" "$BUILD/jna-aar/classes.jar" \
  "$HOME/tools/mobile/kotlinc/lib/kotlin-stdlib.jar"

# 6. Package, align, sign (debug key).
"$BT/aapt2" link -o "$BUILD/app-unsigned.apk" -I "$AJ" \
  --manifest "$APP/AndroidManifest.xml" \
  --min-sdk-version 28 --target-sdk-version 34 \
  --version-code 2 --version-name 0.2.0
cp "$BUILD/dex/classes.dex" "$BUILD/stage/"
cp "$APP/jniLibs/arm64-v8a/libpoe_mobile.so" "$BUILD/stage/lib/arm64-v8a/"
cp "$BUILD/jna-aar/jni/arm64-v8a/libjnidispatch.so" "$BUILD/stage/lib/arm64-v8a/"
(cd "$BUILD/stage" && zip -q -r "$BUILD/app-unsigned.apk" classes.dex lib)
"$BT/zipalign" -f -p 4 "$BUILD/app-unsigned.apk" "$BUILD/app-aligned.apk"
[ -f "$BUILD/debug.keystore" ] || keytool -genkeypair \
  -keystore "$BUILD/debug.keystore" -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=PoE Debug,O=PoE,C=BD"
"$BT/apksigner" sign --ks "$BUILD/debug.keystore" \
  --ks-pass pass:android --key-pass pass:android \
  --out "$ROOT/android/poe-suite-android-0.2.0.apk" "$BUILD/app-aligned.apk"
"$BT/apksigner" verify "$ROOT/android/poe-suite-android-0.2.0.apk"
echo "APK: $ROOT/android/poe-suite-android-0.2.0.apk"
