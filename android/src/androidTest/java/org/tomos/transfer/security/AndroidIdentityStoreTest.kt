package org.tomos.transfer.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Context
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AndroidIdentityStoreTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val record = File(context.noBackupFilesDir, "device-identity.v1")
    private val temporary = File(context.noBackupFilesDir, "device-identity.v1.tmp")

    @After
    fun cleanRecords() {
        record.delete()
        temporary.delete()
    }

    @Test
    fun loadOrCreatePersistsStableIdentityAndSeed() {
        record.delete()
        val first = AndroidIdentityStore(context).loadOrCreate()
        val expectedSeed = first.ed25519Seed.copyOf()

        val restored = AndroidIdentityStore(context).loadOrCreate()

        assertEquals(first.deviceId, restored.deviceId)
        assertArrayEquals(expectedSeed, restored.ed25519Seed)
        expectedSeed.fill(0)
        first.ed25519Seed.fill(0)
        restored.ed25519Seed.fill(0)
    }

    @Test
    fun saveReplacesIdentityAtomicallyAndCanBeRestored() {
        record.delete()
        val expectedId = UUID.fromString("9f9a7b8c-1234-4cde-8abc-1234567890ab")
        val expectedSeed = ByteArray(32) { (it + 1).toByte() }
        AndroidIdentityStore(context).save(StoredDeviceIdentity(expectedId, expectedSeed))

        val restored = AndroidIdentityStore(context).loadOrCreate()

        assertEquals(expectedId, restored.deviceId)
        assertArrayEquals(expectedSeed, restored.ed25519Seed)
        restored.ed25519Seed.fill(0)
        expectedSeed.fill(0)
    }

    @Test
    fun rejectsTruncatedIdentityRecord() {
        record.writeBytes(byteArrayOf(0x54, 0x4d, 0x49, 0x01))
        assertThrows(IllegalArgumentException::class.java) {
            AndroidIdentityStore(context).loadOrCreate()
        }
    }

    @Test
    fun rejectsTamperedIdentityCiphertext() {
        record.delete()
        AndroidIdentityStore(context).loadOrCreate().ed25519Seed.fill(0)
        val bytes = record.readBytes()
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        record.writeBytes(bytes)

        assertThrows(Exception::class.java) {
            AndroidIdentityStore(context).loadOrCreate()
        }
    }
}
