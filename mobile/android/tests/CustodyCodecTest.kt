import app.poe.suite.KeystoreCustody
import javax.crypto.spec.SecretKeySpec

/**
 * Off-device test of the KeystoreCustody blob codec — the
 * pure-JVM half of the custody layer (wrap/unwrap, tamper
 * and truncation refusal, wrong-key refusal). The Keystore
 * half itself (key generation, StrongBox) only exists on a
 * device and is exercised there.
 *
 * Run on this build host (from the repo root):
 *
 *   export JAVA_HOME=~/tools/mobile/jdk PATH=$JAVA_HOME/bin:$PATH
 *   AJ=~/tools/android-sdk/platforms/android-34/android.jar
 *   ~/tools/mobile/kotlinc/bin/kotlinc \
 *     mobile/android/app/src/main/java/app/poe/suite/KeystoreCustody.kt \
 *     mobile/android/tests/CustodyCodecTest.kt \
 *     -cp "$AJ" -include-runtime -d /tmp/custody-test.jar
 *   java -cp "/tmp/custody-test.jar:$AJ" CustodyCodecTestKt
 *
 * (android.jar is on the classpath so the class's Android
 * references resolve; the codec paths never call them —
 * the stubs would throw if they did.)
 */
fun main() {
    val key = SecretKeySpec(ByteArray(32) { (it * 7 + 1).toByte() }, "AES")
    val wrongKey = SecretKeySpec(ByteArray(32) { (it * 13 + 5).toByte() }, "AES")
    // Realistic ML-DSA sizes (public 2592, secret 4896 bytes).
    val pk = ByteArray(2592) { (it % 251).toByte() }
    val sk = ByteArray(4896) { (255 - it % 239).toByte() }

    val blob = KeystoreCustody.wrapBlob(key, pk, sk)
    check(blob.size > sk.size) { "blob should exceed the plaintext" }

    val (pk2, sk2) = KeystoreCustody.unwrapBlob(key, blob)
    check(pk.contentEquals(pk2)) { "public key round-trip mismatch" }
    check(sk.contentEquals(sk2)) { "secret key round-trip mismatch" }
    println("round-trip OK (blob ${blob.size} bytes)")

    // A fresh wrap of the same input differs (random IV) yet unwraps.
    val blob2 = KeystoreCustody.wrapBlob(key, pk, sk)
    check(!blob.contentEquals(blob2)) { "two wraps must differ (random IV)" }
    check(KeystoreCustody.unwrapBlob(key, blob2).second.contentEquals(sk)) {
        "second wrap must unwrap to the same key"
    }
    println("random-IV OK")

    expectRefusal("tampered ciphertext") {
        val bad = blob.copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1] + 1).toByte()
        KeystoreCustody.unwrapBlob(key, bad)
    }
    expectRefusal("tampered header") {
        val bad = blob.copyOf()
        bad[6] = (bad[6] + 1).toByte() // inside the IV
        KeystoreCustody.unwrapBlob(key, bad)
    }
    expectRefusal("truncated blob") {
        KeystoreCustody.unwrapBlob(key, blob.copyOf(blob.size - 10))
    }
    expectRefusal("wrong magic") {
        val bad = blob.copyOf()
        bad[0] = 0x51
        KeystoreCustody.unwrapBlob(key, bad)
    }
    expectRefusal("wrong key") {
        KeystoreCustody.unwrapBlob(wrongKey, blob)
    }

    // Generic data codec (v2, the light core's containers):
    // round-trip at container size, version separation both
    // ways, and the same tamper refusals.
    val data = ByteArray(1024) { (it % 253).toByte() }
    val dblob = KeystoreCustody.wrapData(key, data)
    check(KeystoreCustody.unwrapData(key, dblob).contentEquals(data)) {
        "data round-trip mismatch"
    }
    println("data round-trip OK (blob ${dblob.size} bytes)")
    expectRefusal("v1 blob through the data codec") {
        KeystoreCustody.unwrapData(key, blob)
    }
    expectRefusal("v2 blob through the identity codec") {
        KeystoreCustody.unwrapBlob(key, dblob)
    }
    expectRefusal("tampered data ciphertext") {
        val bad = dblob.copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1] + 1).toByte()
        KeystoreCustody.unwrapData(key, bad)
    }
    expectRefusal("data blob under the wrong key") {
        KeystoreCustody.unwrapData(wrongKey, dblob)
    }
    println("data codec OK")

    println("ALL CUSTODY CODEC TESTS PASSED")
}

private fun expectRefusal(name: String, block: () -> Unit) {
    try {
        block()
    } catch (e: Exception) {
        println("$name refused (${e.javaClass.simpleName})")
        return
    }
    throw AssertionError("$name was NOT refused")
}
