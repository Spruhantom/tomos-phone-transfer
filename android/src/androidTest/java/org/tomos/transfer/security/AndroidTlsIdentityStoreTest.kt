package org.tomos.transfer.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AndroidTlsIdentityStoreTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val record = File(context.noBackupFilesDir, "tls-identity.v1")
    private val temporary = File(context.noBackupFilesDir, "tls-identity.v1.tmp")

    @After
    fun cleanRecords() {
        record.delete()
        temporary.delete()
    }

    @Test
    fun missingTlsIdentityReturnsNull() {
        record.delete()
        assertNull(AndroidTlsIdentityStore(context).loadOrNull())
    }

    @Test
    fun savesAndRestoresCertificateAndPrivateKey() {
        record.delete()
        val certificate = byteArrayOf(1, 2, 3, 4, 5)
        val privateKey = ByteArray(48) { (it * 3).toByte() }
        val store = AndroidTlsIdentityStore(context)
        store.save(StoredTlsIdentity(certificate, privateKey))

        val restored = store.loadOrNull()!!

        assertArrayEquals(certificate, restored.certificateDer)
        assertArrayEquals(privateKey, restored.privateKeyDer)
        restored.privateKeyDer.fill(0)
        privateKey.fill(0)
    }

    @Test
    fun rejectsTamperedTlsIdentityCiphertext() {
        record.delete()
        AndroidTlsIdentityStore(context).save(
            StoredTlsIdentity(byteArrayOf(1, 2, 3), ByteArray(32) { it.toByte() })
        )
        val bytes = record.readBytes()
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        record.writeBytes(bytes)

        org.junit.Assert.assertThrows(Exception::class.java) {
            AndroidTlsIdentityStore(context).loadOrNull()
        }
    }

    @Test
    fun rejectsTruncatedTlsIdentityRecord() {
        record.writeBytes(byteArrayOf(0x54, 0x4d, 0x54, 0x01))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            AndroidTlsIdentityStore(context).loadOrNull()
        }
    }
}
