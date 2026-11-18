package app.poe.suite

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.Context
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import uniffi.poe_mobile.CertSummary
import uniffi.poe_mobile.DetectionBook
import uniffi.poe_mobile.DeviceKey
import uniffi.poe_mobile.LightCoreException
import uniffi.poe_mobile.WalletContainer
import uniffi.poe_mobile.certificateSummary
import uniffi.poe_mobile.verifySignature
import uniffi.poe_mobile.verifyTestnetCertificate

/**
 * PoE Suite — Android light-duty app (Phase 2).
 *
 * 0.5.0 is a UI/UX pass only (owner instruction, 2026-11-18):
 * the face is rebuilt to a professional, plain-words
 * standard — a home screen that says what this device can
 * do (hold, show, verify, detect) with the main actions
 * obvious, and every technical string (machine id, custody
 * internals, raw roots and counts) moved behind a
 * Details & advanced view, still fully visible there.
 * Branding per the owners' locked rules: the name NEBIS
 * appears only in the wordmark at the top of the home
 * screen, the ring is the icon, navy + teal throughout.
 *
 * NO protocol or security behaviour changes in 0.5.0.
 * Every behaviour below is the 0.4.0 behaviour verbatim:
 * Keystore custody (wrapped identity, locked-state
 * honesty, no silent replacement), container import
 * refusing a held coin, a show recorded in the container's
 * log and persisted before it is reported (a repeat
 * challenge is refused), certificate verification against
 * the pinned testnet root with chain enforcement (the
 * first certificate bootstraps from itself, stated in
 * plain words on the main screen), and the detection
 * book's counters advancing on a match so a settled tag
 * never matches again. Storage names and formats are
 * unchanged, so 0.5.0 installs over 0.4.0 and every
 * existing on-device check still applies.
 *
 * The light core this UI drives (0.3.0/0.4.0): wallet
 * containers held wrapped under Keystore custody and shown
 * offline at a terminal's challenge; finality certificates
 * imported as files and verified from their evidence
 * alone; a detection book of per-contact pairwise secrets
 * that scans a relayed tag stream for arrivals. In this
 * test build contacts are added by pasting the secret as
 * hex (testnet tooling); the product flow establishes the
 * secret at first contact, inside the app. Honest limits
 * unchanged: custody is at-rest; if the Keystore wrapping
 * key is invalidated the wrapped identity AND containers
 * are unrecoverable by design, and the app says so instead
 * of silently replacing anything. The terminal prover's
 * NFC/BLE transport is not in this build. Testnet
 * experiments only.
 */
class MainActivity : Activity() {

    private var key: DeviceKey? = null
    private var custodyLevel: KeystoreCustody.Level? = null
    private var lastCert: CertSummary? = null

    private lateinit var scroll: ScrollView
    private lateinit var selfTestStatus: TextView
    private lateinit var containerList: LinearLayout
    private lateinit var containerStatus: TextView
    private lateinit var challengeInput: EditText
    private lateinit var certStatus: TextView
    private var book: DetectionBook? = null
    private lateinit var detectionStatus: TextView
    private lateinit var contactNameInput: EditText
    private lateinit var contactSecretInput: EditText
    private lateinit var epochFromInput: EditText
    private lateinit var epochToInput: EditText
    private var coinsSection: View? = null
    private var verifySection: View? = null
    private var detectSection: View? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (val outcome = KeystoreCustody.loadIdentity(filesDir)) {
            is KeystoreCustody.LoadOutcome.Loaded -> {
                key = DeviceKey.fromBytes(outcome.pk, outcome.sk)
                custodyLevel = outcome.level
                showHome(
                    if (outcome.migrated) "Your saved identity was moved into secure storage." else null,
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
                custodyLevel = level
                showHome(null)
            }
            is KeystoreCustody.LoadOutcome.Locked -> showLocked(outcome.reason)
        }
    }

    // ---- Styling helpers (navy + teal) ----

    private fun roundedBg(fill: Int, stroke: Int, radiusDp: Float) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = radiusDp * resources.displayMetrics.density
        setColor(fill)
        if (stroke != Color.TRANSPARENT) setStroke(2, stroke)
    }

    private fun text(
        s: String,
        size: Float,
        color: Int,
        bold: Boolean = false,
        alignCenter: Boolean = false,
    ) = TextView(this).apply {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        if (alignCenter) gravity = Gravity.CENTER
        setPadding(0, dp(2), 0, dp(2))
    }

    private fun title(s: String) = text(s, 20f, NAVY, bold = true)
    private fun body(s: String) = text(s, 15f, INK)
    private fun muted(s: String) = text(s, 13.5f, MUTED)

    private fun card(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = roundedBg(Color.WHITE, BORDER, 14f)
        setPadding(dp(16), dp(14), dp(16), dp(14))
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(dp(16), dp(6), dp(16), dp(6)) }
    }

    private fun primaryButton(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setTextColor(Color.WHITE)
        background = roundedBg(TEAL, Color.TRANSPARENT, 10f)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(0, dp(6), 0, dp(2)) }
    }

    private fun quietButton(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setTextColor(NAVY)
        background = roundedBg(Color.WHITE, BORDER, 10f)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(0, dp(6), 0, dp(2)) }
    }

    private fun input(hintText: String, numeric: Boolean = false) = EditText(this).apply {
        hint = hintText
        if (numeric) inputType = InputType.TYPE_CLASS_NUMBER
        setTextColor(INK)
        setHintTextColor(MUTED)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { setMargins(0, dp(4), 0, dp(4)) }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun scrollToSection(section: View?) {
        val s = section ?: return
        scroll.post { scroll.smoothScrollTo(0, s.top) }
    }

    // ---- Home screen ----

    private fun showHome(note: String?) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
        }

        // Header: ring icon + the wordmark (the only place
        // the name appears, per the locked branding rules).
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(6))
            // The owners' ring artwork (assets/ring-mark.png,
            // generated from the Concept 2 source by
            // tools/make_icons.py). If the asset cannot be
            // read, the header falls back to the drawn ring.
            val markBitmap = try {
                assets.open("ring-mark.png").use { BitmapFactory.decodeStream(it) }
            } catch (e: Exception) {
                null
            }
            val markView: View = if (markBitmap != null) {
                ImageView(this@MainActivity).apply {
                    background = roundedBg(NAVY, Color.TRANSPARENT, 14f)
                    setPadding(dp(8), dp(8), dp(8), dp(8))
                    layoutParams = LinearLayout.LayoutParams(dp(54), dp(54))
                    setImageBitmap(markBitmap)
                }
            } else {
                RingView(this@MainActivity).apply {
                    background = roundedBg(NAVY, Color.TRANSPARENT, 14f)
                    layoutParams = LinearLayout.LayoutParams(dp(54), dp(54))
                }
            }
            addView(markView)
            val words = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), 0, 0, 0)
                addView(
                    TextView(this@MainActivity).apply {
                        text = "NEBIS"
                        textSize = 27f
                        setTextColor(NAVY)
                        setTypeface(typeface, android.graphics.Typeface.BOLD)
                        letterSpacing = 0.32f
                    },
                )
                addView(muted("Your light wallet · test network"))
            }
            addView(words)
        }
        root.addView(header)
        if (note != null) {
            root.addView(
                LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(20), dp(2), dp(20), 0)
                    addView(muted(note))
                },
            )
        }

        // What this device can do — the four main actions.
        val actions = card()
        actions.addView(title("What this device can do"))
        actions.addView(actionRow("Hold", "Keep coins safe on this device.") { scrollToSection(coinsSection) })
        actions.addView(actionRow("Show", "Prove a coin at a terminal, offline.") { scrollToSection(coinsSection) })
        actions.addView(actionRow("Verify", "Check the network's signed records yourself.") { scrollToSection(verifySection) })
        actions.addView(actionRow("Detect", "Find what has arrived for you.") { scrollToSection(detectSection) })
        root.addView(actions)

        // This device, in plain words.
        val device = card()
        device.addView(title("This device"))
        device.addView(
            body(
                "This device has its own identity, created here and never " +
                    "sent anywhere. Its secret is locked in this phone's " +
                    "secure storage and never leaves the device.",
            ),
        )
        device.addView(muted("Protected by ${custodyLevel?.label ?: "the Android Keystore"}. Technical details are under Details & advanced, below."))
        root.addView(device)

        // ---- Your coins (hold + show) ----
        val coins = card()
        coinsSection = coins
        coins.addView(title("Your coins"))
        coins.addView(
            body(
                "Coins you hold live here, locked the same way as your " +
                    "identity. To show a coin at a terminal, type the " +
                    "number the terminal gives you, then tap Show on the " +
                    "coin. Every show is written into the coin's own " +
                    "record, and the same challenge can never be answered " +
                    "twice.",
            ),
        )
        challengeInput = input("Number shown by the terminal", numeric = true)
        coins.addView(challengeInput)
        containerList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        coins.addView(containerList)
        coins.addView(primaryButton("Add a coin from a file") { pickFile(REQ_CONTAINER) })
        containerStatus = muted("")
        coins.addView(containerStatus)
        root.addView(coins)

        // ---- Verify (finality certificates) ----
        val verify = card()
        verifySection = verify
        verify.addView(title("Check the network"))
        verify.addView(
            body(
                "For each epoch, the network publishes a signed record " +
                    "of what happened. This device checks the signature " +
                    "itself — it trusts no server. The first record you " +
                    "check is your starting point: its starting link is " +
                    "taken from the record itself. After that, every " +
                    "record must link to the last one you checked, or it " +
                    "is refused.",
            ),
        )
        certStatus = body(chainStatusText())
        verify.addView(certStatus)
        verify.addView(primaryButton("Check a record file") { pickFile(REQ_CERT) })
        root.addView(verify)

        // ---- Detect (detection tags) ----
        val detect = card()
        detectSection = detect
        detect.addView(title("Find arrivals"))
        detect.addView(
            body(
                "When something is sent to you, it carries a tag that " +
                    "only your device can recognize. Add a contact's " +
                    "shared secret, then scan a tag file to find what " +
                    "has arrived. Once an arrival is found it is marked " +
                    "as settled, so it never shows up twice.",
            ),
        )
        detectionStatus = body("")
        detect.addView(detectionStatus)
        contactNameInput = input("Contact name")
        detect.addView(contactNameInput)
        contactSecretInput = input("Shared secret (64 hex characters — test tooling)")
        detect.addView(contactSecretInput)
        detect.addView(primaryButton("Add contact") { addContact() })
        epochFromInput = input("From epoch", numeric = true).apply { setText("0") }
        detect.addView(epochFromInput)
        epochToInput = input("To epoch", numeric = true).apply { setText("999") }
        detect.addView(epochToInput)
        detect.addView(primaryButton("Look for arrivals in a file") { pickFile(REQ_TAGS) })
        root.addView(detect)

        // Details & advanced.
        val details = card()
        details.addView(quietButton("Details & advanced") { showDetails() })
        root.addView(details)
        root.addView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(20), dp(4), dp(20), dp(20))
                addView(muted("Test build — testnet experiments only."))
            },
        )

        scroll = ScrollView(this).apply {
            setBackgroundColor(BG)
            addView(root)
        }
        setContentView(scroll)
        refreshContainers()
        loadBook()
    }

    private fun actionRow(label: String, line: String, onClick: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(7), 0, dp(7))
            isClickable = true
            setOnClickListener { onClick() }
            addView(
                TextView(this@MainActivity).apply {
                    text = label
                    textSize = 16.5f
                    setTextColor(TEAL)
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                    layoutParams = LinearLayout.LayoutParams(dp(74), LinearLayout.LayoutParams.WRAP_CONTENT)
                },
            )
            addView(
                TextView(this@MainActivity).apply {
                    text = line
                    textSize = 14.5f
                    setTextColor(INK)
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                },
            )
            addView(
                TextView(this@MainActivity).apply {
                    text = "›"
                    textSize = 20f
                    setTextColor(MUTED)
                },
            )
        }
        return row
    }

    // ---- Details & advanced ----

    private fun showDetails() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            setPadding(0, dp(8), 0, dp(16))
        }
        val head = card()
        head.addView(title("Details & advanced"))
        head.addView(muted("Everything technical, in one place. Nothing here is hidden — it is simply kept off the main screens."))
        head.addView(quietButton("Back") { showHome(null) })
        root.addView(head)

        val identity = card()
        identity.addView(title("Device identity"))
        identity.addView(body("Machine ${key?.machineId()}"))
        identity.addView(body("Key custody: ${custodyLevel?.label}"))
        identity.addView(
            muted(
                "The secret key is stored encrypted (wrapped blob, " +
                    "AES-GCM); its unlock key never leaves the Android " +
                    "Keystore. Custody is at-rest: while the app runs, " +
                    "the unwrapped key exists in process memory.",
            ),
        )
        selfTestStatus = body("")
        identity.addView(primaryButton("Run sign / verify self-test") { runSelfTest() })
        identity.addView(selfTestStatus)
        root.addView(identity)

        val chain = card()
        chain.addView(title("Certificate chain"))
        val tip = chainTip()
        chain.addView(
            body(
                if (tip == null) "No certificate verified yet."
                else "Verified through epoch ${tip.first}.\nState root ${tip.second}",
            ),
        )
        val lc = lastCert
        if (lc != null) {
            chain.addView(
                muted(
                    "Last verified this session — epoch ${lc.epoch}, close round " +
                        "${lc.closeRound}, minted ${lc.minted}; ${lc.votes} votes over " +
                        "${lc.reveals} reveals, ${lc.announcements} announcements.\n" +
                        "Companion root ${lc.companionRoot}",
                ),
            )
        }
        root.addView(chain)

        val det = card()
        det.addView(title("Detection book"))
        val b = book
        det.addView(
            body(
                if (b == null || b.contacts().isEmpty()) {
                    "No contacts."
                } else {
                    b.contacts().joinToString("\n") { name -> "$name — next counter ${b.nextCounter(name)}" }
                },
            ),
        )
        det.addView(muted("The book is held wrapped under the same Keystore custody (data item \"detection-book\"). Containers are items \"container-<coin>\"; verified certificates are stored plainly as \"cert-<epoch>.bin\" with the chain tip in \"cert-chain.txt\"."))
        root.addView(det)

        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun showLocked(reason: String) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(BG)
            setPadding(0, dp(8), 0, dp(16))
        }
        val card = card()
        card.addView(title("Your saved identity can't be opened"))
        card.addView(
            body(
                "The identity stored on this device is locked and cannot " +
                    "be unlocked — this can happen if the phone's secure " +
                    "storage was reset. The app will not replace it " +
                    "silently. Erasing removes the locked identity, its " +
                    "coins, and its unlock key; a new identity is then " +
                    "created.",
            ),
        )
        card.addView(muted("Technical reason: $reason"))
        card.addView(
            primaryButton("Erase and create a new identity") {
                AlertDialog.Builder(this)
                    .setMessage("Erase the locked identity, its coins, and its unlock key, and create a new identity?")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Erase") { _, _ ->
                        KeystoreCustody.eraseIdentity(filesDir)
                        recreate()
                    }
                    .show()
            },
        )
        root.addView(card)
        setContentView(ScrollView(this).apply { addView(root) })
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
        selfTestStatus.text = if (ok && !tampered) {
            "Self-test passed: signature verifies, and a tampered message is refused."
        } else {
            "Self-test FAILED (verify=$ok, tampered=$tampered)."
        }
    }

    // ---- Containers (behaviour unchanged from 0.4.0) ----

    private fun refreshContainers() {
        containerList.removeAllViews()
        val names = KeystoreCustody.listData(filesDir).filter { it.startsWith("container-") }
        if (names.isEmpty()) {
            containerList.addView(muted("No coins held yet."))
            return
        }
        for (name in names) {
            when (val outcome = KeystoreCustody.loadData(filesDir, name)) {
                is KeystoreCustody.DataOutcome.Loaded -> {
                    try {
                        val container = WalletContainer.fromBytes(outcome.data)
                        val info = container.info()
                        val coinCard = LinearLayout(this).apply {
                            orientation = LinearLayout.VERTICAL
                            background = roundedBg(BG, BORDER, 10f)
                            setPadding(dp(12), dp(10), dp(12), dp(10))
                            layoutParams = LinearLayout.LayoutParams(
                                LinearLayout.LayoutParams.MATCH_PARENT,
                                LinearLayout.LayoutParams.WRAP_CONTENT,
                            ).apply { setMargins(0, dp(4), 0, dp(4)) }
                            addView(
                                body(
                                    "Coin ${info.coin} · value ${info.value}\n" +
                                        "Arrived in epoch ${info.born} · shown ${info.showsRecorded} time(s)",
                                ),
                            )
                            val row = LinearLayout(this@MainActivity).apply {
                                orientation = LinearLayout.HORIZONTAL
                                addView(
                                    Button(this@MainActivity).apply {
                                        text = "Show this coin"
                                        setTextColor(Color.WHITE)
                                        background = roundedBg(TEAL, Color.TRANSPARENT, 10f)
                                        setOnClickListener { showContainer(name, container) }
                                        layoutParams = LinearLayout.LayoutParams(
                                            0,
                                            LinearLayout.LayoutParams.WRAP_CONTENT,
                                            1f,
                                        ).apply { setMargins(0, dp(6), dp(4), 0) }
                                    },
                                )
                                addView(
                                    Button(this@MainActivity).apply {
                                        text = "Remove"
                                        setTextColor(NAVY)
                                        background = roundedBg(Color.WHITE, BORDER, 10f)
                                        setOnClickListener {
                                            AlertDialog.Builder(this@MainActivity)
                                                .setMessage("Remove coin ${info.coin} from this device?")
                                                .setNegativeButton("Cancel", null)
                                                .setPositiveButton("Remove") { _, _ ->
                                                    KeystoreCustody.deleteData(filesDir, name)
                                                    containerStatus.text = "Coin ${info.coin} removed."
                                                    refreshContainers()
                                                }
                                                .show()
                                        }
                                        layoutParams = LinearLayout.LayoutParams(
                                            0,
                                            LinearLayout.LayoutParams.WRAP_CONTENT,
                                            1f,
                                        ).apply { setMargins(dp(4), dp(6), 0, 0) }
                                    },
                                )
                            }
                            addView(row)
                        }
                        containerList.addView(coinCard)
                    } catch (e: LightCoreException) {
                        containerList.addView(muted("A stored coin is unreadable: ${e.message}"))
                    }
                }
                is KeystoreCustody.DataOutcome.Locked ->
                    containerList.addView(muted("A stored coin is locked: ${outcome.reason}"))
                KeystoreCustody.DataOutcome.Absent -> Unit
            }
        }
    }

    private fun showContainer(name: String, container: WalletContainer) {
        val challenge = challengeInput.text.toString().toULongOrNull()
        if (challenge == null) {
            containerStatus.text = "Type the number the terminal shows you, above, first."
            return
        }
        try {
            val show = container.show(challenge, 0uL)
            // Persist the updated container (the show is in its
            // log now) under the same custody before reporting.
            KeystoreCustody.storeData(filesDir, name, container.toBytes())
            containerStatus.text =
                "Shown. Tell the terminal: coin ${show.coin}, " +
                    "challenge ${show.challenge}, answer ${show.response}."
            refreshContainers()
        } catch (e: LightCoreException) {
            containerStatus.text = "Show refused: ${e.message}"
        }
    }

    // ---- Certificates (behaviour unchanged from 0.4.0) ----

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
            "No record checked yet."
        } else {
            "Checked up to epoch ${tip.first}. The next record must link to this one."
        }
    }

    private fun verifyImportedCertificate(bytes: ByteArray) {
        val summary = try {
            certificateSummary(bytes)
        } catch (e: LightCoreException) {
            certStatus.text = "That file is not a network record: ${e.message}"
            return
        }
        val tip = chainTip()
        val expectedPrevHex = tip?.second ?: summary.prevStateRoot
        val expectedPrev = hexToBytes(expectedPrevHex)
        if (expectedPrev == null) {
            certStatus.text = "The stored chain link is not valid hex; cannot verify."
            return
        }
        try {
            val verified = verifyTestnetCertificate(bytes, expectedPrev)
            File(filesDir, "cert-${verified.epoch}.bin").writeBytes(bytes)
            chainFile.writeText("${verified.epoch} ${verified.stateRoot}")
            lastCert = verified
            certStatus.text = verifiedText(verified, bootstrapped = tip == null)
        } catch (e: LightCoreException) {
            certStatus.text = "Record REFUSED: ${e.message}"
        }
    }

    private fun verifiedText(s: CertSummary, bootstrapped: Boolean): String =
        "Record accepted — epoch ${s.epoch} is checked and chained." +
            if (bootstrapped) {
                "\n(This was your first record: its starting link came " +
                    "from the record itself.)"
            } else {
                ""
            }

    // ---- Detection (behaviour unchanged from 0.4.0) ----

    private fun loadBook() {
        book = when (val outcome = KeystoreCustody.loadData(filesDir, BOOK_NAME)) {
            is KeystoreCustody.DataOutcome.Loaded ->
                try {
                    DetectionBook.fromState(outcome.data)
                } catch (e: LightCoreException) {
                    DetectionBook()
                }
            else -> DetectionBook()
        }
        refreshDetectionStatus("Your address book for arrivals is ready.")
    }

    private fun persistBook() {
        val b = book ?: return
        try {
            KeystoreCustody.storeData(filesDir, BOOK_NAME, b.exportState())
        } catch (e: Exception) {
            detectionStatus.text = "Could not store the address book: ${e.message}"
        }
    }

    private fun refreshDetectionStatus(message: String) {
        val b = book
        val lines = StringBuilder(message)
        if (b == null || b.contacts().isEmpty()) {
            lines.append("\nNo contacts yet.")
        } else {
            for (name in b.contacts()) {
                lines.append("\n$name — watching for arrivals")
            }
        }
        detectionStatus.text = lines.toString()
    }

    private fun addContact() {
        val b = book ?: return
        val name = contactNameInput.text.toString().trim()
        val secret = hexToBytes(contactSecretInput.text.toString().trim())
        if (name.isEmpty() || secret == null || secret.size != 32) {
            detectionStatus.text =
                "A contact needs a name and a shared secret (64 hex characters)."
            return
        }
        try {
            b.addContact(name, secret)
            persistBook()
            contactSecretInput.text.clear()
            refreshDetectionStatus("Contact added.")
        } catch (e: LightCoreException) {
            detectionStatus.text = "Add refused: ${e.message}"
        }
    }

    private fun scanTagStream(bytes: ByteArray) {
        val b = book ?: return
        val from = epochFromInput.text.toString().toULongOrNull() ?: 0uL
        val to = epochToInput.text.toString().toULongOrNull() ?: 0uL
        if (to < from) {
            detectionStatus.text = "The epoch window is empty (to before from)."
            return
        }
        try {
            val hits = b.scan(bytes, from, to, 64uL)
            persistBook()
            val summary = if (hits.isEmpty()) {
                "No arrivals found in this file."
            } else {
                hits.joinToString("\n") { "Arrived for ${it.contact}: #${it.counter} in epoch ${it.epoch}" }
            }
            refreshDetectionStatus(summary)
        } catch (e: LightCoreException) {
            detectionStatus.text = "Scan refused: ${e.message}"
        }
    }

    // ---- File picking (unchanged) ----

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
            REQ_TAGS -> scanTagStream(bytes)
        }
    }

    private fun importContainer(bytes: ByteArray) {
        try {
            val container = WalletContainer.fromBytes(bytes)
            val info = container.info()
            val name = "container-${info.coin}"
            if (KeystoreCustody.loadData(filesDir, name) !is KeystoreCustody.DataOutcome.Absent) {
                containerStatus.text = "Coin ${info.coin} is already held."
                return
            }
            KeystoreCustody.storeData(filesDir, name, container.toBytes())
            containerStatus.text =
                "Coin added: coin ${info.coin}, value ${info.value}, " +
                    "arrived in epoch ${info.born}."
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
        private const val REQ_TAGS = 43
        private const val BOOK_NAME = "detection-book"
        private const val CHAIN_FILE = "cert-chain.txt"

        // Locked palette: navy + teal.
        private val NAVY = Color.rgb(10, 37, 64)
        private val TEAL = Color.rgb(13, 148, 136)
        private val INK = Color.rgb(38, 54, 72)
        private val MUTED = Color.rgb(107, 124, 147)
        private val BORDER = Color.rgb(216, 227, 240)
        private val BG = Color.rgb(244, 247, 251)
    }
}

/**
 * The ring mark, drawn: a teal ring with a centre dot, on
 * whatever background the caller gives it (navy in the
 * header; the launcher's adaptive icon carries the same
 * drawing as a vector resource).
 */
private class RingView(context: Context) : View(context) {
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = Color.rgb(20, 184, 166)
    }
    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = Color.rgb(20, 184, 166)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = minOf(width, height).toFloat()
        val cx = width / 2f
        val cy = height / 2f
        ringPaint.strokeWidth = size * 0.115f
        canvas.drawCircle(cx, cy, size * 0.295f, ringPaint)
        canvas.drawCircle(cx, cy, size * 0.075f, dotPaint)
    }
}
