package app.poe.suite

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import uniffi.poe_mobile.CertSummary
import uniffi.poe_mobile.DeviceKey
import uniffi.poe_mobile.LightCoreException
import uniffi.poe_mobile.WalletContainer
import uniffi.poe_mobile.certificateSummary
import uniffi.poe_mobile.verifySignature
import uniffi.poe_mobile.verifyTestnetCertificate

/**
 * PoE Suite — Android light-duty app (Phase 2).
 *
 * 0.3.0 adds the light core (the design note's §11 build
 * order, item 4) on top of the 0.2.0 identity + Keystore
 * custody foundation:
 *
 * - Wallet containers: the app imports a coin's 1 KiB
 *   Existence Container (the .poec form the node's control
 *   surface exports), holds it wrapped under the same
 *   Keystore custody as the identity, and shows the coin
 *   offline at a terminal's challenge. Every show is
 *   recorded in the container's own log by the Rust core —
 *   a repeat challenge is refused — and the updated
 *   container is re-wrapped and stored after each show.
 * - Finality certificates: the app imports an epoch's
 *   certificate (public evidence, stored plainly) and
 *   verifies it from its evidence alone through the Rust
 *   core, against the pinned testnet root. Verified
 *   certificates chain: the next one must name the last
 *   verified state root as its predecessor. For the FIRST
 *   certificate there is no chain yet, so its predecessor
 *   is taken from the certificate itself — the bootstrap
 *   the design note's §3 describes (a light client anchors
 *   its first root from its sync source); the UI says so
 *   rather than glossing it.
 *
 * Honest limits, as before: custody is at-rest (key and
 * container material are in process memory while the app
 * runs); if the Keystore wrapping key is invalidated the
 * wrapped identity AND containers are unrecoverable by
 * design, and the app says so instead of silently
 * replacing anything. Detection tags and the terminal
 * prover's NFC/BLE transport are not in this build.
 * Testnet experiments only.
 */
class MainActivity : Activity() {

    private var key: DeviceKey? = null
    private lateinit var status: TextView
    private lateinit var containerList: LinearLayout
    private lateinit var containerStatus: TextView
    private lateinit var challengeInput: EditText
    private lateinit var certStatus: TextView

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

    private fun centered(text: String, size: Float? = null) = TextView(this).apply {
        this.text = text
        gravity = Gravity.CENTER
        setPadding(32, 16, 32, 8)
        if (size != null) textSize = size
    }

    private fun showIdentity(key: DeviceKey, level: KeystoreCustody.Level, note: String?) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }
        root.addView(centered("Machine\n${key.machineId()}", 20f))
        root.addView(
            centered(
                "Light-duty wallet (testnet).\n" +
                    "This device verifies; it does not register.",
            ),
        )
        root.addView(
            centered(
                buildString {
                    append("Key custody: ${level.label} — the secret key is\n")
                    append("stored encrypted; its unlock key never leaves\n")
                    append("the Android Keystore.")
                    if (note != null) append("\n").append(note)
                },
            ),
        )
        val testButton = Button(this).apply {
            text = "Run sign / verify self-test"
            setOnClickListener { runSelfTest() }
        }
        root.addView(testButton)
        status = centered("")
        root.addView(status)

        // ---- Wallet containers ----
        root.addView(centered("Wallet containers", 18f))
        root.addView(
            centered(
                "Held coins, wrapped under the same Keystore\n" +
                    "custody. A show is recorded in the container's\n" +
                    "log; a repeat challenge is refused.",
            ),
        )
        challengeInput = EditText(this).apply {
            hint = "Terminal challenge (number)"
            inputType = InputType.TYPE_CLASS_NUMBER
            gravity = Gravity.CENTER
        }
        root.addView(challengeInput)
        containerList = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }
        root.addView(containerList)
        val importButton = Button(this).apply {
            text = "Import container (.poec)"
            setOnClickListener { pickFile(REQ_CONTAINER) }
        }
        root.addView(importButton)
        containerStatus = centered("")
        root.addView(containerStatus)

        // ---- Finality certificates ----
        root.addView(centered("Finality certificates", 18f))
        certStatus = centered(chainStatusText())
        root.addView(certStatus)
        val certButton = Button(this).apply {
            text = "Import & verify certificate"
            setOnClickListener { pickFile(REQ_CERT) }
        }
        root.addView(certButton)

        setContentView(ScrollView(this).apply { addView(root) })
        refreshContainers()
    }

    private fun showLocked(reason: String) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            addView(centered("Stored identity cannot be unlocked", 20f))
            addView(
                centered(
                    reason + "\n\nThe app will not replace it silently. " +
                        "Erasing removes the wrapped identity, its containers, " +
                        "and its unlock key; a new identity is then created.",
                ),
            )
            addView(
                Button(this@MainActivity).apply {
                    text = "Erase and create a new identity"
                    setOnClickListener {
                        KeystoreCustody.eraseIdentity(filesDir)
                        recreate()
                    }
                },
            )
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

    // ---- Containers ----

    private fun refreshContainers() {
        containerList.removeAllViews()
        val names = KeystoreCustody.listData(filesDir).filter { it.startsWith("container-") }
        if (names.isEmpty()) {
            containerList.addView(centered("No containers held."))
            return
        }
        for (name in names) {
            when (val outcome = KeystoreCustody.loadData(filesDir, name)) {
                is KeystoreCustody.DataOutcome.Loaded -> {
                    try {
                        val container = WalletContainer.fromBytes(outcome.data)
                        val info = container.info()
                        containerList.addView(
                            centered(
                                "Coin ${info.coin} · value ${info.value} · " +
                                    "born epoch ${info.born} · ${info.showsRecorded} show(s)",
                            ),
                        )
                        val row = LinearLayout(this).apply {
                            orientation = LinearLayout.HORIZONTAL
                            gravity = Gravity.CENTER
                            addView(
                                Button(this@MainActivity).apply {
                                    text = "Show coin ${info.coin}"
                                    setOnClickListener { showContainer(name, container) }
                                },
                            )
                            addView(
                                Button(this@MainActivity).apply {
                                    text = "Remove"
                                    setOnClickListener {
                                        KeystoreCustody.deleteData(filesDir, name)
                                        containerStatus.text = "Container for coin ${info.coin} removed."
                                        refreshContainers()
                                    }
                                },
                            )
                        }
                        containerList.addView(row)
                    } catch (e: LightCoreException) {
                        containerList.addView(centered("Stored container is unreadable: ${e.message}"))
                    }
                }
                is KeystoreCustody.DataOutcome.Locked ->
                    containerList.addView(centered("Container locked: ${outcome.reason}"))
                KeystoreCustody.DataOutcome.Absent -> Unit
            }
        }
    }

    private fun showContainer(name: String, container: WalletContainer) {
        val challenge = challengeInput.text.toString().toULongOrNull()
        if (challenge == null) {
            containerStatus.text = "Enter the terminal's challenge number first."
            return
        }
        try {
            val show = container.show(challenge, 0uL)
            // Persist the updated container (the show is in its
            // log now) under the same custody before reporting.
            KeystoreCustody.storeData(filesDir, name, container.toBytes())
            containerStatus.text =
                "Show for coin ${show.coin}: challenge ${show.challenge},\n" +
                    "response ${show.response}. Give the terminal these\n" +
                    "three numbers (coin, challenge, response)."
            refreshContainers()
        } catch (e: LightCoreException) {
            containerStatus.text = "Show refused: ${e.message}"
        }
    }

    // ---- Certificates ----

    private val chainFile get() = File(filesDir, CHAIN_FILE)

    /** (epoch, state root hex) of the last verified certificate. */
    private fun chainTip(): Pair<ULong, String>? {
        if (!chainFile.exists()) return null
        val parts = chainFile.readText().trim().split(" ")
        if (parts.size != 2) return null
        return parts[0].toULongOrNull()?.let { it to parts[1] }
    }

    private fun chainStatusText(): String {
        val tip = chainTip()
        return if (tip == null) {
            "No certificate verified yet. The first certificate's\n" +
                "predecessor is taken from the certificate itself\n" +
                "(bootstrap); later ones must chain to it."
        } else {
            "Verified through epoch ${tip.first}.\n" +
                "Next certificate must chain to root ${tip.second.take(16)}…"
        }
    }

    private fun verifyImportedCertificate(bytes: ByteArray) {
        val summary = try {
            certificateSummary(bytes)
        } catch (e: LightCoreException) {
            certStatus.text = "Not a certificate: ${e.message}"
            return
        }
        val tip = chainTip()
        val expectedPrevHex = tip?.second ?: summary.prevStateRoot
        val expectedPrev = hexToBytes(expectedPrevHex)
        if (expectedPrev == null) {
            certStatus.text = "Stored chain root is not valid hex; cannot verify."
            return
        }
        try {
            val verified = verifyTestnetCertificate(bytes, expectedPrev)
            File(filesDir, "cert-${verified.epoch}.bin").writeBytes(bytes)
            chainFile.writeText("${verified.epoch} ${verified.stateRoot}")
            certStatus.text = verifiedText(verified, bootstrapped = tip == null)
        } catch (e: LightCoreException) {
            certStatus.text = "Certificate REFUSED: ${e.message}"
        }
    }

    private fun verifiedText(s: CertSummary, bootstrapped: Boolean): String =
        "VERIFIED — epoch ${s.epoch}, close round ${s.closeRound},\n" +
            "minted ${s.minted}; ${s.votes} votes over ${s.reveals} reveals,\n" +
            "${s.announcements} announcements. Companion root\n" +
            "${s.companionRoot.take(32)}…" +
            if (bootstrapped) "\n(First certificate: predecessor taken from the\ncertificate itself — bootstrap.)" else ""

    // ---- File picking ----

    private fun pickFile(request: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, request)
    }

    @Deprecated("framework picker")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return
        when (requestCode) {
            REQ_CONTAINER -> importContainer(bytes)
            REQ_CERT -> verifyImportedCertificate(bytes)
        }
    }

    private fun importContainer(bytes: ByteArray) {
        try {
            val container = WalletContainer.fromBytes(bytes)
            val info = container.info()
            val name = "container-${info.coin}"
            if (KeystoreCustody.loadData(filesDir, name) !is KeystoreCustody.DataOutcome.Absent) {
                containerStatus.text = "A container for coin ${info.coin} is already held."
                return
            }
            KeystoreCustody.storeData(filesDir, name, container.toBytes())
            containerStatus.text =
                "Container imported: coin ${info.coin}, value ${info.value}, " +
                    "born epoch ${info.born}."
            refreshContainers()
        } catch (e: LightCoreException) {
            containerStatus.text = "Import refused: ${e.message}"
        }
    }

    private fun hexToBytes(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        return try {
            ByteArray(hex.length / 2) { i ->
                hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
            }
        } catch (e: NumberFormatException) {
            null
        }
    }

    companion object {
        private const val REQ_CONTAINER = 41
        private const val REQ_CERT = 42
        private const val CHAIN_FILE = "cert-chain.txt"
    }
}
