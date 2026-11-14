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
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM encrypted persistence for the Rust TLS leaf certificate and private
 * key. The wrapping key is non-exportable in Android Keystore. The private key
 * is only returned to the native engine after decryption for an active session.
 */
class AndroidTlsIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val recordFile = File(appContext.noBackupFilesDir, RECORD_NAME)

    @Synchronized
    fun loadOrNull(): StoredTlsIdentity? {
        if (!recordFile.exists()) return null
        val record = recordFile.readBytes()
        require(record.size >= HEADER.size + NONCE_SIZE + GCM_TAG_BYTES) {
            "Stored TLS identity is truncated"
        }
        require(record.copyOfRange(0, HEADER.size).contentEquals(HEADER)) {
            "Unsupported TLS identity record"
        }

        val nonce = record.copyOfRange(HEADER.size, HEADER.size + NONCE_SIZE)
        val encrypted = record.copyOfRange(HEADER.size + NONCE_SIZE, record.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(create = false), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(HEADER)
        val plain = cipher.doFinal(encrypted)
        try {
            require(plain.size >= LENGTHS_SIZE) { "Invalid TLS identity payload" }
            val buffer = ByteBuffer.wrap(plain)
            val certificateSize = buffer.int
            val privateKeySize = buffer.int
            require(certificateSize in 1..MAX_CERTIFICATE_SIZE) { "Invalid TLS certificate size" }
            require(privateKeySize in 1..MAX_PRIVATE_KEY_SIZE) { "Invalid TLS private key size" }
            require(buffer.remaining() == certificateSize + privateKeySize) {
                "TLS identity payload length mismatch"
            }
            val certificate = ByteArray(certificateSize)
            buffer.get(certificate)
            val privateKey = ByteArray(privateKeySize)
            buffer.get(privateKey)
            return StoredTlsIdentity(certificate, privateKey)
        } finally {
            plain.fill(0)
            encrypted.fill(0)
            record.fill(0)
        }
    }

    @Synchronized
    fun save(identity: StoredTlsIdentity) {
        require(identity.certificateDer.size in 1..MAX_CERTIFICATE_SIZE)
        require(identity.privateKeyDer.size in 1..MAX_PRIVATE_KEY_SIZE)
        val plain = ByteBuffer.allocate(LENGTHS_SIZE + identity.certificateDer.size + identity.privateKeyDer.size)
            .putInt(identity.certificateDer.size)
            .putInt(identity.privateKeyDer.size)
            .put(identity.certificateDer)
            .put(identity.privateKeyDer)
            .array()

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(create = true))
        cipher.updateAAD(HEADER)
        val encrypted = cipher.doFinal(plain)
        plain.fill(0)

        val record = HEADER + cipher.iv + encrypted
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
        check(create) { "Android Keystore wrapping key is missing for an existing TLS identity" }

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
        private const val RECORD_NAME = "tls-identity.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val NONCE_SIZE = 12
        private const val GCM_TAG_BYTES = 16
        private const val TAG_BITS = 128
        private const val LENGTHS_SIZE = 8
        private const val MAX_CERTIFICATE_SIZE = 64 * 1024
        private const val MAX_PRIVATE_KEY_SIZE = 16 * 1024
        private val HEADER = byteArrayOf(0x54, 0x4d, 0x54, 0x01) // TMT + format version
    }
}

data class StoredTlsIdentity(
    val certificateDer: ByteArray,
    val privateKeyDer: ByteArray
)
