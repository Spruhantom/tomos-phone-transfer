package org.tomos.transfer.pairing

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class PairingQrParserTest {
    @Test
    fun parsesValidInvitation() {
        val invitation = PairingQrParser.parse(payload())
        assertEquals("192.168.1.20", invitation.host)
        assertEquals(43120, invitation.port)
        assertEquals(UUID.fromString(DEVICE_ID).toString(), invitation.deviceId)
        assertEquals(64, invitation.tlsFingerprint.length)
    }

    @Test
    fun rejectsWrongScheme() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingQrParser.parse("https://example.test/pair")
        }
    }

    @Test
    fun rejectsExpiredInvitation() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingQrParser.parse(payload(expiresAt = 1))
        }
    }

    @Test
    fun rejectsUnsupportedVersion() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingQrParser.parse(payload(version = 2))
        }
    }

    @Test
    fun rejectsInvalidPort() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingQrParser.parse(payload(port = 65536))
        }
    }

    @Test
    fun rejectsCertificateFingerprintMismatch() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingQrParser.parse(payload(fingerprintOverride = "00".repeat(32)))
        }
    }

    @Test
    fun rejectsMalformedDeviceIdentity() {
        assertThrows(Exception::class.java) {
            PairingQrParser.parse(payload(deviceId = "not-a-uuid"))
        }
    }

    private fun payload(
        version: Int = 1,
        port: Int = 43120,
        expiresAt: Long = System.currentTimeMillis() / 1000 + 120,
        fingerprintOverride: String? = null,
        deviceId: String = DEVICE_ID
    ): String {
        val certificate = "test-certificate-der".toByteArray()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate)
            .joinToString("") { "%02x".format(it) }
        val json = JSONObject()
            .put("version", version)
            .put("identity", JSONObject()
                .put("device_id", deviceId)
                .put("public_key", JSONArray((0..31).toList())))
            .put("host", "192.168.1.20")
            .put("port", port)
            .put("tls_certificate", Base64.encodeToString(certificate, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            .put("tls_fingerprint", fingerprintOverride ?: fingerprint)
            .put("token", Base64.encodeToString(ByteArray(32) { it.toByte() }, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            .put("expires_at", expiresAt)
        val encoded = Base64.encodeToString(json.toString().toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return "tomos-transfer://pair/$encoded"
    }

    companion object {
        private const val DEVICE_ID = "9f9a7b8c-1234-4cde-8abc-1234567890ab"
    }
}
