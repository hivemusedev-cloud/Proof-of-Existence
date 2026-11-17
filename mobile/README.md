# PoE Suite mobile (Phase 2 — light-duty apps)

The phone is a **light-duty** device in the adopted model:
a wallet identity that verifies and shows, never a machine
registration (Manual lines 199/467/667; the light-duty
design note in `~/workspace/poe-build-2026-11-11/`). The
apps are shells over the Rust `poe-mobile` crate through
UniFFI — the identity core (ML-DSA device key, machine id,
signing) plus, since 2026-11-17, the light core: Existence
Containers and finality-certificate verification over
poe-wallet and poe-finality.

## Android — built here

`android/poe-suite-android-0.3.0.apk` (arm64, minSdk 28)
is built and signature-verified (same debug certificate as
0.1.0/0.2.0, so it installs as an upgrade). The 0.2.0 build
was verified on the owner's device (identity created under
Keystore custody, self-test passed). 0.3.0 was verified on
the owner's device on 2026-11-17: installed over 0.2.0,
the same machine (1604234391729841426) was restored —
proving the Keystore unwrap/restore path end-to-end — and
a sample container's show at challenge 777 answered the
precomputed response 86469, recorded as the container's
first show. The certificate import check on-device is
still the owner's to run.

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
refusals all pass).

**Light core (0.3.0):** wallet containers and certificate
verification, the design note's §11 build-order item 4.
The app imports a coin's 1 KiB Existence Container (the
`.poec` form the node's control surface exports) and holds
it wrapped under the same Keystore key (POEK v2 blobs,
same codec battery); a show at a terminal's challenge is
computed and recorded by the Rust core — a repeat
challenge is refused by the container's log — and the
updated container is re-wrapped after each show. The app
also imports an epoch's finality certificate (public
evidence, stored plainly) and verifies it from its
evidence alone through the Rust core against the pinned
testnet root; verified certificates chain (each next one
must name the last verified state root), and for the
first certificate the predecessor is taken from the
certificate itself — the §3 bootstrap, labelled as such
in the UI. The Rust surface is unit-tested: container
shows extract the line secret from two challenges exactly
as the wallet's rule requires, and a simnet epoch's
certificate verifies through the byte surface while a
wrong predecessor is refused by name.

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
The bindings were regenerated for the light core
(2026-11-17), so the Swift surface includes containers
and certificate verification; the iOS app sources still
wire the identity core only — the light-core UI wiring
happens at the Mac assembly, with the Keychain custody
step. What remains needs Xcode on HiveDevs' Mac:

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
  on some devices), the wrapped identity and any held
  containers are unrecoverable by design; the app says
  so and erases only on an explicit user action, never
  silently replacing the identity. StrongBox depends on the
  device having one. The design note's monotonic
  counter is not part of this step — whether the vault
  interface grows a counter verb is an open Phase 2
  question for the owners.
- iOS still stores raw key bytes in the app's documents
  (its Keychain/Secure Enclave step comes when the app
  is assembled on a Mac).
- Detection tags (the design note's §5) are not built
  yet — they are the next item in §11's order. Finality
  certificates and Merkle paths, once specified-only,
  were built 2026-11-17 on the owners' approval (the
  node's corrections 27–28) and are what the light core
  above verifies against. Note proofs against a
  certificate's companion root are served by the node's
  control surface today; verifying them in the app is a
  later step, as is the terminal prover's NFC/BLE
  transport for offline shows.
