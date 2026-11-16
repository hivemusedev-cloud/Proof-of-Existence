# PoE Suite mobile (Phase 2 — light-duty apps)

The phone is a **light-duty** device in the adopted model:
a wallet identity that verifies and shows, never a machine
registration (Manual lines 199/467/667; the light-duty
design note in `~/workspace/poe-build-2026-11-11/`). Both
apps are v1 identity cores over the Rust `poe-mobile`
crate (ML-DSA device key, machine id, signing) through
UniFFI — the foundation the rest of the light-duty design
builds on.

## Android — built here

`android/poe-suite-android-0.1.0.apk` (1.2 MB, arm64,
minSdk 28) is built and signature-verified. It creates or
restores the device identity, shows the machine id, and
runs a sign/verify self-test through the Rust core.

Two build routes, same sources:

- **Gradle** (normal machines / Android Studio): open
  `android/` and build, or `./gradlew assembleDebug`. The
  Gradle files are all here; the UniFFI bindings and the
  `.so` are checked in under `app/src/main/`.
- **Manual pipeline** (`android/build-manual.sh`):
  kotlinc → d8 → aapt2 → zipalign → apksigner. This is
  how the APK above was produced on the build VM, where
  the sandbox network policy (`other_tcp` = Deny)
  intercepts the Gradle daemon's loopback TCP and Gradle
  cannot run. Flipping that permission (Muse settings →
  Permissions → Direct network protocols) makes the
  Gradle route work there too.

## iOS — bindings ready, assembly is on a Mac

`ios/Bindings/` holds the generated Swift bindings
(`poe_mobile.swift`, `poe_mobileFFI.h`, modulemap) and
`ios/App/` the SwiftUI sources mirroring the Android v1.
What remains needs Xcode on HiveDevs' Mac:

1. Build the XCFramework from the Rust core:
   `cargo build -p poe-mobile --target aarch64-apple-ios`
   (and `aarch64-apple-ios-sim` for the simulator), then
   `xcodebuild -create-xcframework`.
2. New Xcode App project (bundle id `app.poe.suite`),
   add the XCFramework + the bindings + `ios/App/*.swift`.
3. Run on a device / TestFlight with HiveDevs' Apple
   Developer account. The Swift bindings have never been
   compiled by a Swift toolchain (none exists on the
   build VM) — expect the first Xcode build to be the
   real check, as the JVM run was for Kotlin in Step 7.

## Honest limits (both platforms)

- The v1 stores raw key bytes in app-private storage.
  The design note's home for the secret is the secure
  element (Android StrongBox/Keystore, Apple Secure
  Enclave/Keychain) with its monotonic counter — that
  move is Phase 2 hardening, before anything of value.
- Wallet containers, detection tags, finality
  certificates and Merkle paths are the design note's
  protocol additions: specified, unbuilt, and awaiting
  the owners' review (AdminMuse has the revised note).
