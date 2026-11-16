package app.poe.suite

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import uniffi.poe_mobile.DeviceKey
import uniffi.poe_mobile.verifySignature
import java.io.File

/**
 * PoE Suite — Android light-duty app, v1 (Phase 2 start).
 *
 * Scope of this build, honestly: the phone's identity core.
 * On first launch the app generates its ML-DSA device key
 * through the Rust core (poe-mobile, via UniFFI); the key
 * bytes are kept in the app's private storage so the same
 * machine id returns on later launches, and a self-test
 * signs a message and verifies it through the same core.
 * That is the foundation the light-duty design note builds
 * on (wallet identity; it verifies, it does not register).
 *
 * Not yet here: wallet containers, detection, finality
 * certificates — the protocol additions in the design note
 * are specified, unbuilt, and awaiting the owners' review;
 * and the raw key bytes in private storage must move
 * behind the Android Keystore / StrongBox (the design
 * note's secure-element home) before this holds anything
 * of value. Testnet experiments only.
 */
class MainActivity : Activity() {

    private lateinit var key: DeviceKey
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        key = loadOrCreateKey()

        val machine = TextView(this).apply {
            text = "Machine\n${key.machineId()}"
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(32, 48, 32, 16)
        }
        val duty = TextView(this).apply {
            text = "Light-duty wallet identity (testnet).\n" +
                "This device verifies; it does not register."
            gravity = Gravity.CENTER
            setPadding(32, 0, 32, 32)
        }
        val testButton = Button(this).apply {
            text = "Run sign / verify self-test"
            setOnClickListener { runSelfTest() }
        }
        status = TextView(this).apply {
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 0)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            addView(machine)
            addView(duty)
            addView(testButton)
            addView(status)
        }
        setContentView(root)
    }

    /** First launch: generate and persist. Later: restore. */
    private fun loadOrCreateKey(): DeviceKey {
        val pkFile = File(filesDir, "device.pk")
        val skFile = File(filesDir, "device.sk")
        if (pkFile.exists() && skFile.exists()) {
            return DeviceKey.fromBytes(pkFile.readBytes(), skFile.readBytes())
        }
        val fresh = DeviceKey.generate()
        pkFile.writeBytes(fresh.publicKey())
        skFile.writeBytes(fresh.secretKey())
        return fresh
    }

    private fun runSelfTest() {
        val message = "poe-suite-android-self-test".toByteArray()
        val signature = key.sign(message)
        val ok = verifySignature(key.publicKey(), message, signature)
        val tampered = verifySignature(
            key.publicKey(),
            "tampered".toByteArray(),
            signature,
        )
        status.text = if (ok && !tampered) {
            "Self-test passed: signature verifies,\nand a tampered message is refused."
        } else {
            "Self-test FAILED (verify=$ok, tampered=$tampered)."
        }
    }
}
