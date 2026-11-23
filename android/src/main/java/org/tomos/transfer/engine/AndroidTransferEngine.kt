package org.tomos.transfer.engine

import android.content.ContentResolver
import android.net.Uri
import org.json.JSONObject
import org.tomos.transfer.security.AndroidIdentityStore
import org.tomos.transfer.security.AndroidTlsIdentityStore
import uniffi.tomos_transfer_core.TlsIdentityHandle
import uniffi.tomos_transfer_core.TransferCallbacks
import uniffi.tomos_transfer_core.TransferIdentity
import uniffi.tomos_transfer_core.TransferProgressCallbacks
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

/**
 * Android adapter around the shared Rust transfer engine.
 *
 * All blocking native calls must be invoked from Dispatchers.IO (or another
 * worker thread). Approval callbacks are synchronous by contract and should
 * marshal the prompt to the UI thread, then wait for the user's decision.
 */
class AndroidTransferEngine(
    private val contentResolver: ContentResolver,
    private val identityStore: AndroidIdentityStore,
    private val tlsIdentityStore: AndroidTlsIdentityStore,
    private val filesDir: File,
    private val approval: ApprovalHandler,
    private val onProgress: (TransferProgress) -> Unit
) {
    private var identity: TransferIdentity? = null
    private var tlsIdentity: TlsIdentityHandle? = null

    @Synchronized
    fun restoreIdentity(): TransferIdentity {
        identity?.let { return it }
        val stored = identityStore.loadOrCreate()
        val seed = stored.ed25519Seed.copyOf()
        return try {
            TransferIdentity.restore(stored.deviceId.toString(), seed).also {
                identity = it
            }
        } finally {
            seed.fill(0)
            stored.ed25519Seed.fill(0)
        }
    }

    @Synchronized
    private fun restoreTlsIdentity(): TlsIdentityHandle {
        tlsIdentity?.let { return it }
        val store = tlsIdentityStore
        val restored = store.loadOrNull()?.let { saved ->
            val certificate = saved.certificateDer.copyOf()
            val privateKey = saved.privateKeyDer.copyOf()
            try {
                TlsIdentityHandle.restore(certificate, privateKey)
            } finally {
                certificate.fill(0)
                privateKey.fill(0)
                saved.privateKeyDer.fill(0)
            }
        } ?: TlsIdentityHandle.generate().also { generated ->
            val certificate = generated.certificateDer()
            val privateKey = generated.privateKeyDerForSecureStorage()
            try {
                store.save(
                    org.tomos.transfer.security.StoredTlsIdentity(
                        certificateDer = certificate,
                        privateKeyDer = privateKey
                    )
                )
            } finally {
                privateKey.fill(0)
            }
        }
        tlsIdentity = restored
        return restored
    }

    /**
     * Starts a one-shot receiver and returns the exact QR payload bound to its
     * listening socket. The caller must display this payload as a QR code.
     */
    @Synchronized
    fun createReceiver(advertisedHost: String, lifetimeSeconds: ULong = 300uL): PreparedReceiver {
        require(advertisedHost.isNotBlank()) { "A reachable local network address is required" }
        val nativeIdentity = restoreIdentity()
        val receiver = nativeIdentity.createReceiver(
            advertisedHost,
            "0.0.0.0:0",
            restoreTlsIdentity(),
            lifetimeSeconds
        ) ?: error("The native engine could not bind a receiving socket")
        val payload = receiver.pairingPayload()
        check(payload.startsWith("tomos-transfer://pair/")) {
            "The native engine returned an invalid pairing invitation"
        }
        return PreparedReceiver(receiver, payload, receiver.port())
    }

    /** Blocks until one authenticated incoming transfer completes or fails. */
    fun receiveOnce(prepared: PreparedReceiver): TransferResult {
        val destination = File(filesDir, "received").apply { mkdirs() }
        val state = File(filesDir, "transfer-state").apply { mkdirs() }
        val result = prepared.receiver.receiveOnce(
            destination.absolutePath,
            state.absolutePath,
            object : TransferCallbacks {
                override fun approvePeer(deviceId: String, publicKey: ByteArray): Boolean =
                    this@AndroidTransferEngine.approval.approvePeer(deviceId, publicKey.copyOf())

                override fun approveFile(fileName: String, sizeBytes: ULong, sha256: String): Boolean =
                    this@AndroidTransferEngine.approval.approveFile(fileName, sizeBytes.toLong(), sha256)

                override fun onProgress(bytesReceived: ULong, totalBytes: ULong, bytesPerSecond: ULong) {
                    this@AndroidTransferEngine.onProgress(
                        TransferProgress(
                            bytesTransferred = bytesReceived.toLong(),
                            totalBytes = totalBytes.toLong(),
                            bytesPerSecond = bytesPerSecond.toLong()
                        )
                    )
                }
            }
        )
        return parseResult(result)
    }

    /**
     * Stages a content:// URI into private cache, then passes only that
     * app-owned path to Rust. The temporary copy is removed after send returns.
     */
    fun sendFile(
        invitationPayload: String,
        sourceUri: Uri,
        transferId: UUID = UUID.randomUUID()
    ): TransferResult {
        val nativeIdentity = restoreIdentity()
        val staged = stageUri(sourceUri)
        return try {
            val result = nativeIdentity.sendFile(
                invitationPayload,
                staged.file.absolutePath,
                staged.displayName,
                transferId.toString(),
                object : TransferProgressCallbacks {
                    override fun onProgress(bytesSent: ULong, totalBytes: ULong, bytesPerSecond: ULong) {
                        this@AndroidTransferEngine.onProgress(
                            TransferProgress(
                                bytesTransferred = bytesSent.toLong(),
                                totalBytes = totalBytes.toLong(),
                                bytesPerSecond = bytesPerSecond.toLong()
                            )
                        )
                    }
                }
            )
            parseResult(result)
        } finally {
            staged.file.delete()
        }
    }

    @Synchronized
    fun close() {
        identity?.close()
        identity = null
        tlsIdentity?.close()
        tlsIdentity = null
    }

    private fun stageUri(uri: Uri): StagedFile {
        val displayName = contentResolver.query(
            uri,
            arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        } ?: uri.lastPathSegment ?: "transfer-file"

        val safeName = displayName.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[\\\\u0000-\\\\u001f]"), "_")
            .take(180)
            .ifBlank { "transfer-file" }
        val stagingDir = File(filesDir, "outgoing-staging").apply { mkdirs() }
        val staged = File.createTempFile("outgoing-", ".part", stagingDir)
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(staged).use { output -> input.copyTo(output) }
            } ?: error("Android could not open the selected file")
            check(staged.isFile) { "Selected file is unavailable" }
            return StagedFile(staged, safeName)
        } catch (failure: Exception) {
            staged.delete()
            throw failure
        }
    }

    private fun parseResult(raw: String): TransferResult {
        val json = JSONObject(raw)
        if (!json.optBoolean("ok", false)) {
            throw IllegalStateException(json.optString("error", "Native transfer failed"))
        }
        return TransferResult(
            peerDeviceId = json.optString("peer_device_id").takeIf { it.isNotBlank() },
            path = json.optString("path").takeIf { it.isNotBlank() },
            bytesTransferred = json.optLong("bytes_received", 0L),
            sha256 = json.optString("sha256").takeIf { it.isNotBlank() },
            transferId = json.optString("transfer_id").takeIf { it.isNotBlank() }
        )
    }
}

interface ApprovalHandler {
    fun approvePeer(deviceId: String, publicKey: ByteArray): Boolean
    fun approveFile(fileName: String, sizeBytes: Long, sha256: String): Boolean
}

data class PreparedReceiver internal constructor(
    internal val receiver: uniffi.tomos_transfer_core.TransferReceiver,
    val pairingPayload: String,
    val port: UShort
)

data class TransferProgress(
    val bytesTransferred: Long,
    val totalBytes: Long,
    val bytesPerSecond: Long
) {
    val fraction: Float
        get() = if (totalBytes <= 0L) 0f else (bytesTransferred.toFloat() / totalBytes).coerceIn(0f, 1f)
}

data class TransferResult(
    val peerDeviceId: String?,
    val path: String?,
    val bytesTransferred: Long,
    val sha256: String?,
    val transferId: String?
)

private data class StagedFile(val file: File, val displayName: String)
