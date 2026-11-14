package org.tomos.transfer.pairing

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.time.Instant

/**
 * Parses and validates the public QR invitation envelope before the Rust bridge
 * is asked to connect. This is input validation, not peer authentication:
 * certificate pinning and Ed25519 challenge proof remain mandatory in Rust.
 */
data class ScannedInvitation(
    val deviceId: String,
    val host: String,
    val port: Int,
    val tlsFingerprint: String,
    val expiresAt: Long,
    val token: String,
    val encodedPayload: String
)

object PairingQrParser {
    private const val PREFIX = "tomos-transfer://pair/"

    fun parse(raw: String): ScannedInvitation {
        require(raw.startsWith(PREFIX)) { "This is not a TomOS Transfer QR code" }
        val encoded = raw.removePrefix(PREFIX)
        require(encoded.isNotBlank() && encoded.length <= 16_384) { "Invalid QR payload size" }
        val jsonBytes = Base64.decode(
            encoded.replace('-', '+').replace('_', '/').let { value ->
                value + "=".repeat((4 - value.length % 4) % 4)
            },
            Base64.NO_WRAP
        )
        val json = JSONObject(jsonBytes.toString(Charsets.UTF_8))
        require(json.optInt("version") == 1) { "Unsupported pairing protocol version" }

        val identity = json.getJSONObject("identity")
        val deviceId = identity.getString("device_id")
        val publicKey = identity.getString("public_key")
        require(publicKey.isNotBlank()) { "Missing device identity key" }

        val host = json.getString("host")
        require(host.isNotBlank() && host.length <= 253 && !host.contains('/')) { "Invalid device address" }
        val port = json.getInt("port")
        require(port in 1..65535) { "Invalid device port" }

        val certificateEncoded = json.getString("tls_certificate")
        val certificate = Base64.decode(
            certificateEncoded.replace('-', '+').replace('_', '/').let { value ->
                value + "=".repeat((4 - value.length % 4) % 4)
            },
            Base64.NO_WRAP
        )
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(certificate)
            .joinToString("") { "%02x".format(it) }
        val declaredFingerprint = json.getString("tls_fingerprint").lowercase()
        require(MessageDigest.isEqual(
            fingerprint.toByteArray(Charsets.US_ASCII),
            declaredFingerprint.toByteArray(Charsets.US_ASCII)
        )) { "QR certificate fingerprint does not match its certificate" }

        val expiresAt = json.getLong("expires_at")
        require(expiresAt > Instant.now().epochSecond) { "This pairing QR code has expired" }
        require(expiresAt <= Instant.now().epochSecond + 600) { "Pairing QR expiry is invalid" }
        val token = json.getString("token")
        require(Base64.decode(
            token.replace('-', '+').replace('_', '/').let { value ->
                value + "=".repeat((4 - value.length % 4) % 4)
            },
            Base64.NO_WRAP
        ).size == 32) { "Invalid one-time pairing token" }

        return ScannedInvitation(deviceId, host, port, fingerprint, expiresAt, token, raw)
    }
}
