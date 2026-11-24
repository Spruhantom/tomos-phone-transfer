package org.tomos.transfer.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted persistence for the Rust core's 32-byte Ed25519 seed.
 *
 * The AES-GCM wrapping key is non-exportable and held by Android Keystore.
 * The encrypted record is kept in noBackupFilesDir, never shared storage.
 * A missing Keystore key for an existing record is treated as an error rather
 * than silently generating a new identity and breaking the device's trust ID.
 */
class AndroidIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val recordFile = File(appContext.noBackupFilesDir, RECORD_NAME)

    @Synchronized
    fun loadOrCreate(): StoredDeviceIdentity {
        if (recordFile.exists()) return readRecord()
        val seed = ByteArray(SEED_SIZE).also(SecureRandom()::nextBytes)
        val identity = StoredDeviceIdentity(UUID.randomUUID(), seed)
        try {
            writeRecord(identity)
            return identity
        } catch (failure: Exception) {
            seed.fill(0)
            throw failure
        }
    }

    @Synchronized
    fun save(identity: StoredDeviceIdentity) {
        require(identity.ed25519Seed.size == SEED_SIZE) { "Ed25519 seed must be 32 bytes" }
        writeRecord(identity)
    }

    private fun readRecord(): StoredDeviceIdentity {
        val bytes = recordFile.readBytes()
        require(bytes.size >= HEADER.size + NONCE_SIZE + GCM_TAG_BYTES) {
            "Stored device identity is truncated"
        }
        require(bytes.copyOfRange(0, HEADER.size).contentEquals(HEADER)) {
            "Unsupported device identity record"
        }

        val nonce = bytes.copyOfRange(HEADER.size, HEADER.size + NONCE_SIZE)
        val encrypted = bytes.copyOfRange(HEADER.size + NONCE_SIZE, bytes.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(create = false), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(HEADER)
        val plain = cipher.doFinal(encrypted)
        try {
            require(plain.size == UUID_BYTES + SEED_SIZE) { "Invalid device identity payload" }
            val buffer = ByteBuffer.wrap(plain)
            val id = UUID(buffer.long, buffer.long)
            val seed = ByteArray(SEED_SIZE)
            buffer.get(seed)
            return StoredDeviceIdentity(id, seed)
        } finally {
            plain.fill(0)
        }
    }

    private fun writeRecord(identity: StoredDeviceIdentity) {
        val plain = ByteBuffer.allocate(UUID_BYTES + SEED_SIZE)
            .putLong(identity.deviceId.mostSignificantBits)
            .putLong(identity.deviceId.leastSignificantBits)
            .put(identity.ed25519Seed)
            .array()

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(create = true))
        cipher.updateAAD(HEADER)
        val encrypted = cipher.doFinal(plain)
        plain.fill(0)

        val nonce = cipher.iv
        check(nonce.size == NONCE_SIZE) { "Unexpected AES-GCM nonce size" }
        val record = HEADER + nonce + encrypted
        val temp = File(appContext.noBackupFilesDir, "$RECORD_NAME.tmp")
        try {
            FileOutputStream(temp).use { output ->
                output.write(record)
                output.fd.sync()
            }
            try {
                Files.move(
                    temp.toPath(),
                    recordFile.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temp.toPath(), recordFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temp.delete()
            encrypted.fill(0)
            record.fill(0)
        }
    }

    private fun wrappingKey(create: Boolean): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { "Android Keystore wrapping key is missing for an existing device identity" }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "tomos.transfer.identity.wrap.v1"
        private const val RECORD_NAME = "device-identity.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val SEED_SIZE = 32
        private const val UUID_BYTES = 16
        private const val NONCE_SIZE = 12
        private const val GCM_TAG_BYTES = 16
        private const val TAG_BITS = 128
        private val HEADER = byteArrayOf(0x54, 0x4d, 0x49, 0x01) // TMI + format version
    }
}

data class StoredDeviceIdentity(
    val deviceId: UUID,
    val ed25519Seed: ByteArray
)
