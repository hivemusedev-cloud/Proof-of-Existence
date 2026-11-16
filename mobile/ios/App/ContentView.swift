import SwiftUI

/// The identity core screen: on first launch the app
/// generates its ML-DSA device key through the Rust core;
/// the key bytes are kept in the app's private documents
/// directory so the same machine id returns on later
/// launches, and a self-test signs a message and verifies
/// it through the same core.
///
/// Honest v1 limits, same as Android: raw key bytes in app
/// storage must move behind the Secure Enclave / Keychain
/// (the design note's secure-element home) before this
/// holds anything of value, and the light-duty protocol
/// additions (finality certificates, Merkle paths,
/// detection) are specified but unbuilt, awaiting the
/// owners' review. Testnet experiments only.
struct ContentView: View {
    @State private var key: DeviceKey? = nil
    @State private var status: String = ""

    var body: some View {
        VStack(spacing: 16) {
            if let key {
                Text("Machine")
                    .font(.headline)
                Text(String(key.machineId()))
                    .font(.title3)
                    .textSelection(.enabled)
                Text("Light-duty wallet identity (testnet).\nThis device verifies; it does not register.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                Button("Run sign / verify self-test") {
                    runSelfTest(key)
                }
                if !status.isEmpty {
                    Text(status)
                        .multilineTextAlignment(.center)
                }
            } else {
                ProgressView("Creating identity…")
            }
        }
        .padding()
        .onAppear {
            if key == nil {
                key = loadOrCreateKey()
            }
        }
    }

    private func keyDir() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private func loadOrCreateKey() -> DeviceKey? {
        let pkURL = keyDir().appendingPathComponent("device.pk")
        let skURL = keyDir().appendingPathComponent("device.sk")
        if let pk = try? Data(contentsOf: pkURL),
           let sk = try? Data(contentsOf: skURL),
           let restored = try? DeviceKey.fromBytes(publicKey: pk, secretKey: sk) {
            return restored
        }
        let fresh = DeviceKey.generate()
        try? fresh.publicKey().write(to: pkURL)
        try? fresh.secretKey().write(to: skURL)
        return fresh
    }

    private func runSelfTest(_ key: DeviceKey) {
        let message = Data("poe-suite-ios-self-test".utf8)
        let signature = key.sign(message: message)
        let ok = verifySignature(publicKey: key.publicKey(), message: message, signature: signature)
        let tampered = verifySignature(publicKey: key.publicKey(), message: Data("tampered".utf8), signature: signature)
        status = (ok && !tampered)
            ? "Self-test passed: signature verifies,\nand a tampered message is refused."
            : "Self-test FAILED (verify=\(ok), tampered=\(tampered))."
    }
}
