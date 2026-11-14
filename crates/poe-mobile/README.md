# poe-mobile — Step 7 mobile shell core

The device-identity surface a PoE phone app needs, exposed from
the same Rust crypto the node runs (ML-DSA device keys via
`poe-crypto`, machine ids via `poe-identity`) through UniFFI.
Shells are thin UI over this core — never a reimplementation of
the crypto.

## Verified state (2026-11-14)

- **Rust core**: builds, unit-tested (generate → sign/verify →
  export/restore roundtrip, garbage-key refusal).
- **Kotlin bindings**: generated (`bindings/kotlin/`, UniFFI
  0.28) and **compile-checked** with kotlinc 2.0.21 against JNA
  5.14 on a JVM. Also **run-checked**: a Kotlin smoke program
  drove the native library end-to-end — key generation, machine
  id consistency, sign/verify through the FFI boundary, identity
  restore, refusal of invalid key bytes.
- **Swift bindings**: generated (`bindings/swift/`, including the
  FFI header and modulemap). **Not compiled** — no Swift
  toolchain exists in the build environment; treat the Swift side
  as generated-but-unverified until built in Xcode.

## Still owed (the rest of Step 7)

- The Android and iOS **app projects** themselves (UI, secure
  key storage via the platform keystore/ Secure Enclave patterns,
  packaging of the native library per ABI) — to be built in
  Android Studio / Xcode, which this environment does not have.
- On-device runs of either shell.

## Regenerating the bindings

```
cargo build --release -p poe-mobile
cargo run --release -p poe-mobile --bin uniffi-bindgen -- \
  generate --library target/release/libpoe_mobile.so \
  --language kotlin --out-dir crates/poe-mobile/bindings/kotlin
cargo run --release -p poe-mobile --bin uniffi-bindgen -- \
  generate --library target/release/libpoe_mobile.so \
  --language swift --out-dir crates/poe-mobile/bindings/swift
```

The API surface is intentionally tiny (see `src/lib.rs`):
`DeviceKey` (generate / fromBytes / publicKey / secretKey /
machineId / sign), `verifySignature`, `machineIdForPublicKey`.
Grow it only with operations the shells genuinely need.
