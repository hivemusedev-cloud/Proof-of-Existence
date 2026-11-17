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

`android/poe-suite-android-0.2.0.apk` (arm64, minSdk 28)
is built and signature-verified. It creates or restores
the device identity, shows the machine id, and runs a
sign/verify self-test through the Rust core.

**Key custody (0.2.0):** the device key no longer sits in
plaintext files. `KeystoreCustody.kt` wraps it under a
non-extractable AES-256 key in the Android Keystore —
created in the StrongBox secure element where the device
offers it, otherwise at the Keystore's default level; the
level actually achieved is recorded and shown in the app.
On disk there is only an AES-GCM blob (`device.wrapped`).
A v1 install's plaintext key files are migrated into the
blob on first launch and deleted. The blob codec is
tested off-device (`android/tests/CustodyCodecTest.kt`:
round-trip, random IV, and tamper/truncation/wrong-key
refusals all pass); the Keystore half itself is exercised
on a real device — the APK has not run on one yet.

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

- Android custody is at-rest only: while the app runs,
  the unwrapped key is in process memory (the Rust core
  signs with it) — the same limit as every OS-store
  backend in this project. If the Keystore wrapping key
  is invalidated (a device credential reset can do this
  on some devices), the wrapped identity is
  unrecoverable by design; the app says so and erases
  only on an explicit user action, never silently
  replacing the identity. StrongBox depends on the
  device having one. The design note's monotonic
  counter is not part of this step — whether the vault
  interface grows a counter verb is an open Phase 2
  question for the owners.
- iOS still stores raw key bytes in the app's documents
  (its Keychain/Secure Enclave step comes when the app
  is assembled on a Mac).
- Wallet containers, detection tags, finality
  certificates and Merkle paths are the design note's
  protocol additions: specified, unbuilt, and awaiting
  the owners' review (AdminMuse has the revised note).
