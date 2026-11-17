package app.poe.suite

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import uniffi.poe_mobile.DeviceKey
import uniffi.poe_mobile.verifySignature

/**
 * PoE Suite — Android light-duty app (Phase 2).
 *
 * Scope of this build, honestly: the phone's identity core
 * with real key custody. On first launch the app generates
 * its ML-DSA device key through the Rust core (poe-mobile,
 * via UniFFI) and stores it wrapped by the Android Keystore
 * (see KeystoreCustody: AES-GCM blob, StrongBox where the
 * device offers it); later launches unwrap the same key, so
 * the same machine id returns. A self-test signs a message
 * and verifies it through the same core. That is the
 * foundation the light-duty design note builds on (wallet
 * identity; it verifies, it does not register).
 *
 * If the Keystore wrapping key is ever invalidated, the
 * stored identity is unrecoverable by design: the app shows
 * that plainly and offers erasure as an explicit action —
 * it never silently replaces the identity.
 *
 * Not yet here: wallet containers, detection, finality
 * certificates — the protocol additions in the design note
 * are specified, unbuilt, and awaiting the owners' review.
 * Testnet experiments only.
 */
class MainActivity : Activity() {

    private var key: DeviceKey? = null
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (val outcome = KeystoreCustody.loadIdentity(filesDir)) {
            is KeystoreCustody.LoadOutcome.Loaded -> {
                key = DeviceKey.fromBytes(outcome.pk, outcome.sk)
                showIdentity(
                    key!!,
                    outcome.level,
                    if (outcome.migrated) "Migrated from the v1 plaintext store." else null,
                )
            }
            KeystoreCustody.LoadOutcome.Absent -> {
                val fresh = DeviceKey.generate()
                val level = KeystoreCustody.storeIdentity(
                    filesDir,
                    fresh.publicKey(),
                    fresh.secretKey(),
                )
                key = fresh
                showIdentity(fresh, level, null)
            }
            is KeystoreCustody.LoadOutcome.Locked -> showLocked(outcome.reason)
        }
    }

    private fun showIdentity(key: DeviceKey, level: KeystoreCustody.Level, note: String?) {
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
            setPadding(32, 0, 32, 16)
        }
        val custody = TextView(this).apply {
            text = buildString {
                append("Key custody: ${level.label} — the secret key is\n")
                append("stored encrypted; its unlock key never leaves\n")
                append("the Android Keystore.")
                if (note != null) append("\n").append(note)
            }
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
            addView(custody)
            addView(testButton)
            addView(status)
        }
        setContentView(root)
    }

    private fun showLocked(reason: String) {
        val title = TextView(this).apply {
            text = "Stored identity cannot be unlocked"
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(32, 48, 32, 16)
        }
        val body = TextView(this).apply {
            text = reason + "\n\nThe app will not replace it silently. " +
                "Erasing removes the wrapped identity and its unlock key; " +
                "a new identity is then created."
            gravity = Gravity.CENTER
            setPadding(32, 0, 32, 32)
        }
        val eraseButton = Button(this).apply {
            text = "Erase and create a new identity"
            setOnClickListener {
                KeystoreCustody.eraseIdentity(filesDir)
                recreate()
            }
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            addView(title)
            addView(body)
            addView(eraseButton)
        }
        setContentView(root)
    }

    private fun runSelfTest() {
        val k = key ?: return
        val message = "poe-suite-android-self-test".toByteArray()
        val signature = k.sign(message)
        val ok = verifySignature(k.publicKey(), message, signature)
        val tampered = verifySignature(
            k.publicKey(),
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
