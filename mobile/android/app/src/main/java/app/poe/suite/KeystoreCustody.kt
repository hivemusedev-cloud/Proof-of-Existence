package app.poe.suite

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.nio.ByteBuffer
import java.security.Key
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore custody for the phone's device key
 * (Phase 2, 2026-11-17 — the design note's secure-element
 * home for the wallet secret, Manual line 467).
 *
 * Design: the ML-DSA keypair itself cannot live inside the
 * Keystore — Android's key store has no ML-DSA, and the Rust
 * core needs the key bytes to sign. So custody is by
 * wrapping, the same shape as the desktop OS stores: a
 * non-extractable AES-256 key in the Android Keystore (in
 * the StrongBox secure element where the device has one and
 * key creation succeeds there, otherwise the Keystore's
 * default TEE/software level — which one was achieved is
 * recorded and shown in the UI, never glossed) encrypts the
 * keypair at rest with AES-GCM. On disk there is only the
 * blob: magic "POEK", a version byte, the IV, and the
 * authenticated ciphertext of (pk length | pk | sk).
 *
 * Honest limits, stated the same way as every other backend
 * in this project: while the app runs, the unwrapped key
 * exists in process memory (the core signs with it); the
 * wrapping removes plaintext-at-rest, not memory exposure.
 * And if the Keystore wrapping key is invalidated — a
 * device credential reset can do that on some devices — the
 * blob is unrecoverable BY DESIGN. The load path reports
 * that as [LoadOutcome.Locked]; the app never silently
 * mints a replacement identity over a locked one. Erasing
 * is an explicit user action only.
 *
 * A v1 install stored the raw key bytes as device.pk /
 * device.sk in app-private storage. The load path migrates
 * that pair into the wrapped blob on first run and deletes
 * the plaintext files.
 */
object KeystoreCustody {

    /** Which Keystore level actually holds the wrapping key. */
    enum class Level(val label: String) {
        STRONGBOX("StrongBox"),
        KEYSTORE("Android Keystore"),
    }

    sealed interface LoadOutcome {
        data class Loaded(
            val pk: ByteArray,
            val sk: ByteArray,
            val level: Level,
            val migrated: Boolean,
        ) : LoadOutcome

        /** Nothing stored yet — the caller generates a key. */
        object Absent : LoadOutcome

        /** Stored, but cannot be unlocked. Never auto-replaced. */
        data class Locked(val reason: String) : LoadOutcome
    }

    private const val ALIAS = "app.poe.suite.device-wrap-v1"
    private const val PROVIDER = "AndroidKeyStore"
    private const val BLOB_FILE = "device.wrapped"
    private const val LEVEL_FILE = "custody.level"
    private const val LEGACY_PK = "device.pk"
    private const val LEGACY_SK = "device.sk"

    // ---- Blob codec (pure JVM: exercised off-device by
    // ---- mobile/android/tests/CustodyCodecTest.kt) ----

    private val MAGIC = byteArrayOf(0x50, 0x4F, 0x45, 0x4B) // "POEK"
    private const val VERSION: Byte = 1
    private const val GCM_TAG_BITS = 128

    /** Encrypt (pk, sk) under [key]; output is the blob format above. */
    fun wrapBlob(key: Key, pk: ByteArray, sk: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.size in 1..255) { "unexpected GCM IV size ${iv.size}" }
        val plain = ByteBuffer.allocate(4 + pk.size + sk.size)
        plain.putInt(pk.size)
        plain.put(pk)
        plain.put(sk)
        val ct = cipher.doFinal(plain.array())
        val out = ByteBuffer.allocate(MAGIC.size + 2 + iv.size + ct.size)
        out.put(MAGIC)
        out.put(VERSION)
        out.put(iv.size.toByte())
        out.put(iv)
        out.put(ct)
        return out.array()
    }

    /**
     * Decrypt a blob from [wrapBlob]. Throws on any defect —
     * bad magic or version, truncation, a wrong key, or a
     * tampered ciphertext (the GCM tag refuses it). Callers
     * turn those refusals into [LoadOutcome.Locked].
     */
    fun unwrapBlob(key: Key, blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.size > MAGIC.size + 2) { "blob too short: ${blob.size} bytes" }
        require(MAGIC.indices.all { blob[it] == MAGIC[it] }) { "not a POEK blob" }
        require(blob[MAGIC.size] == VERSION) { "unsupported blob version ${blob[MAGIC.size]}" }
        val ivLen = blob[MAGIC.size + 1].toInt() and 0xFF
        val header = MAGIC.size + 2 + ivLen
        require(ivLen > 0 && blob.size > header) { "blob truncated in header" }
        val iv = blob.copyOfRange(MAGIC.size + 2, header)
        val ct = blob.copyOfRange(header, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val plain = cipher.doFinal(ct)
        require(plain.size >= 4) { "plaintext too short" }
        val pkLen = ByteBuffer.wrap(plain).int
        require(pkLen > 0 && 4 + pkLen <= plain.size) { "corrupt key length $pkLen" }
        val pk = plain.copyOfRange(4, 4 + pkLen)
        val sk = plain.copyOfRange(4 + pkLen, plain.size)
        require(sk.isNotEmpty()) { "empty secret key" }
        return pk to sk
    }

    // ---- Keystore wrapping key ----

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun generateWrappingKey(strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    /**
     * The existing wrapping key, or a newly created one
     * (StrongBox first, Keystore level as the recorded
     * fallback). When [forExistingBlob] is true and the alias
     * is gone, returns null instead of creating — a fresh key
     * could never decrypt the stored blob, and pretending
     * otherwise would hide a lost identity.
     */
    private fun wrappingKey(levelFile: File, forExistingBlob: Boolean): Pair<SecretKey, Level>? {
        val ks = keyStore()
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { existing ->
            val level = runCatching {
                Level.valueOf(levelFile.readText().trim())
            }.getOrDefault(Level.KEYSTORE)
            return existing to level
        }
        if (forExistingBlob) return null
        val created = try {
            generateWrappingKey(strongBox = true) to Level.STRONGBOX
        } catch (e: Exception) {
            // StrongBox absent or refused on this device: clean
            // any half-created entry and fall back a level.
            runCatching { if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS) }
            generateWrappingKey(strongBox = false) to Level.KEYSTORE
        }
        levelFile.writeText(created.second.name)
        return created
    }

    // ---- Identity storage orchestration ----

    fun loadIdentity(filesDir: File): LoadOutcome {
        val blobFile = File(filesDir, BLOB_FILE)
        val levelFile = File(filesDir, LEVEL_FILE)
        if (blobFile.exists()) {
            val (wrapKey, level) = wrappingKey(levelFile, forExistingBlob = true)
                ?: return LoadOutcome.Locked(
                    "The Keystore unlock key for the stored identity is gone. " +
                        "The wrapped identity on this device cannot be recovered.",
                )
            return try {
                val (pk, sk) = unwrapBlob(wrapKey, blobFile.readBytes())
                LoadOutcome.Loaded(pk, sk, level, migrated = false)
            } catch (e: KeyPermanentlyInvalidatedException) {
                LoadOutcome.Locked(
                    "The Keystore unlock key was invalidated (a device " +
                        "credential change can do this). The wrapped identity " +
                        "on this device cannot be recovered.",
                )
            } catch (e: AEADBadTagException) {
                LoadOutcome.Locked(
                    "The stored identity cannot be decrypted with this " +
                        "device's Keystore key. It cannot be recovered.",
                )
            } catch (e: Exception) {
                LoadOutcome.Locked("The stored identity cannot be read: ${e.message}")
            }
        }
        val legacyPk = File(filesDir, LEGACY_PK)
        val legacySk = File(filesDir, LEGACY_SK)
        if (legacyPk.exists() && legacySk.exists()) {
            val pk = legacyPk.readBytes()
            val sk = legacySk.readBytes()
            val level = storeIdentity(filesDir, pk, sk)
            legacyPk.delete()
            legacySk.delete()
            return LoadOutcome.Loaded(pk, sk, level, migrated = true)
        }
        return LoadOutcome.Absent
    }

    /** Wrap and store a (new or migrated) identity; returns its custody level. */
    fun storeIdentity(filesDir: File, pk: ByteArray, sk: ByteArray): Level {
        val levelFile = File(filesDir, LEVEL_FILE)
        val (wrapKey, level) = checkNotNull(wrappingKey(levelFile, forExistingBlob = false)) {
            "wrapping key creation returned nothing"
        }
        File(filesDir, BLOB_FILE).writeBytes(wrapBlob(wrapKey, pk, sk))
        return level
    }

    /**
     * Delete the wrapped identity, any legacy plaintext, and
     * the Keystore wrapping key. Only ever called from the
     * locked screen's explicit user action.
     */
    fun eraseIdentity(filesDir: File) {
        File(filesDir, BLOB_FILE).delete()
        File(filesDir, LEVEL_FILE).delete()
        File(filesDir, LEGACY_PK).delete()
        File(filesDir, LEGACY_SK).delete()
        runCatching {
            val ks = keyStore()
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        }
    }
}
