package org.tomos.transfer

import android.app.AlertDialog
import android.content.DialogInterface
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.tomos.transfer.discovery.AndroidDiscovery
import org.tomos.transfer.discovery.NearbyTransferDevice
import org.tomos.transfer.engine.AndroidTransferEngine
import org.tomos.transfer.engine.ApprovalHandler
import org.tomos.transfer.engine.PreparedReceiver
import org.tomos.transfer.engine.TransferProgress
import org.tomos.transfer.engine.TransferResult
import org.tomos.transfer.pairing.PairingQrParser
import org.tomos.transfer.security.AndroidIdentityStore
import org.tomos.transfer.security.AndroidTlsIdentityStore
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {
    private var identityStatus by mutableStateOf("Preparing secure device identity…")
    private var pairingStatus by mutableStateOf("Scan another device's QR code, or create a receiver QR code.")
    private var scannedDevice by mutableStateOf<String?>(null)
    private var scannedPayload by mutableStateOf<String?>(null)
    private var selectedFile by mutableStateOf<Uri?>(null)
    private var selectedFileName by mutableStateOf<String?>(null)
    private var receiverQr by mutableStateOf<Bitmap?>(null)
    private var receiverStatus by mutableStateOf("Not receiving")
    private var transferStatus by mutableStateOf("No transfer started")
    private var transferProgress by mutableStateOf<TransferProgress?>(null)
    private var activeReceiver: PreparedReceiver? = null
    private val nearbyDevices = mutableStateListOf<NearbyTransferDevice>()
    private val activityScope = MainScope()
    private var discovery: AndroidDiscovery? = null
    private lateinit var transferEngine: AndroidTransferEngine

    private val qrScanner = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@registerForActivityResult
        runCatching { PairingQrParser.parse(contents) }
            .onSuccess { invitation ->
                scannedDevice = invitation.deviceId
                scannedPayload = invitation.encodedPayload
                pairingStatus = "Invitation validated for ${invitation.host}:${invitation.port}. The native engine will verify the pinned TLS certificate and device identity during connection."
            }
            .onFailure { error ->
                scannedDevice = null
                scannedPayload = null
                pairingStatus = "Pairing QR rejected: ${error.message ?: "invalid invitation"}"
            }
    }

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            selectedFile = uri
            selectedFileName = contentResolver.query(
                uri,
                arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
                null,
                null,
                null
            )?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
                ?: uri.lastPathSegment
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        transferEngine = AndroidTransferEngine(
            contentResolver = contentResolver,
            identityStore = AndroidIdentityStore(applicationContext),
            tlsIdentityStore = AndroidTlsIdentityStore(applicationContext),
            filesDir = filesDir,
            approval = object : ApprovalHandler {
                override fun approvePeer(deviceId: String, publicKey: ByteArray): Boolean =
                    requestApproval(
                        "Trust incoming device?",
                        "Device ID: $deviceId\n\nOnly approve if you expected this transfer and can verify the peer."
                    )

                override fun approveFile(fileName: String, sizeBytes: Long, sha256: String): Boolean =
                    requestApproval(
                        "Accept incoming file?",
                        "File: $fileName\nSize: ${sizeBytes.coerceAtLeast(0)} bytes\nSHA-256: $sha256"
                    )
            },
            onProgress = { progress ->
                runOnUiThread { transferProgress = progress }
            }
        )

        discovery = AndroidDiscovery(applicationContext) { device ->
            runOnUiThread {
                if (nearbyDevices.none { it.serviceName == device.serviceName && it.host == device.host }) {
                    nearbyDevices.add(device)
                }
            }
        }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        item {
                            Text("TomOS Transfer", style = MaterialTheme.typography.headlineLarge)
                            Text("Private, direct device-to-device transfers", style = MaterialTheme.typography.bodyLarge)
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Device security", style = MaterialTheme.typography.titleMedium)
                                    Text(identityStatus)
                                    Text("Device identity and TLS keys are protected using Android Keystore-backed encrypted storage.",
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Receive a file", style = MaterialTheme.typography.titleMedium)
                                    Text(receiverStatus)
                                    receiverQr?.let { bitmap ->
                                        Image(
                                            bitmap = bitmap.asImageBitmap(),
                                            contentDescription = "TomOS Transfer pairing QR code",
                                            modifier = Modifier.size(240.dp)
                                        )
                                        Text("Scan this QR code on the sending device. Keep both devices on the same trusted network.")
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(
                                            onClick = { startReceiver() },
                                            enabled = activeReceiver == null
                                        ) { Text("Create receive QR") }
                                        OutlinedButton(
                                            onClick = { stopReceiver() },
                                            enabled = activeReceiver != null
                                        ) { Text("Stop receiver") }
                                    }
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Send a file", style = MaterialTheme.typography.titleMedium)
                                    Text(pairingStatus, style = MaterialTheme.typography.bodyMedium)
                                    scannedDevice?.let { Text("Paired device ID: $it", style = MaterialTheme.typography.labelSmall) }
                                    Button(onClick = {
                                        val options = ScanOptions().apply {
                                            setPrompt("Scan a TomOS Transfer pairing QR code")
                                            setBeepEnabled(false)
                                            setOrientationLocked(false)
                                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        }
                                        qrScanner.launch(options)
                                    }, modifier = Modifier.fillMaxWidth()) {
                                        Text("Scan receiver QR code")
                                    }
                                    Text(selectedFileName ?: "No file selected")
                                    OutlinedButton(
                                        onClick = { filePicker.launch(arrayOf("*/*")) },
                                        modifier = Modifier.fillMaxWidth()
                                    ) { Text("Choose file") }
                                    Button(
                                        onClick = { sendSelectedFile() },
                                        enabled = scannedPayload != null && selectedFile != null,
                                        modifier = Modifier.fillMaxWidth()
                                    ) { Text("Send securely") }
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Transfer status", style = MaterialTheme.typography.titleMedium)
                                    Text(transferStatus)
                                    transferProgress?.let { progress ->
                                        LinearProgressIndicator(
                                            progress = { progress.fraction },
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                        Text("${progress.bytesTransferred} / ${progress.totalBytes} bytes · ${progress.bytesPerSecond} B/s",
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Nearby devices", style = MaterialTheme.typography.titleMedium)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(onClick = {
                                            nearbyDevices.clear()
                                            discovery?.start()
                                        }) { Text("Find devices") }
                                        OutlinedButton(onClick = {
                                            discovery?.stop()
                                            nearbyDevices.clear()
                                        }) { Text("Stop discovery") }
                                    }
                                    if (nearbyDevices.isEmpty()) Text("No devices discovered yet.")
                                    nearbyDevices.forEach { device ->
                                        Text("${device.serviceName} — ${device.host}:${device.port}")
                                    }
                                    Text("Discovery records are hints only. A QR invitation is required to establish trust.",
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                        item { Spacer(Modifier.height(8.dp)) }
                    }
                }
            }
        }

        activityScope.launch {
            runCatching { withContext(Dispatchers.IO) { transferEngine.restoreIdentity() } }
                .onSuccess { identityStatus = "Secure device identity ready" }
                .onFailure { error ->
                    identityStatus = "Secure identity unavailable: ${error.message ?: "unknown error"}"
                }
        }
    }

    private fun startReceiver() {
        if (activeReceiver != null) return
        receiverStatus = "Preparing secure receiver…"
        activityScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val host = findAdvertisedIpv4Address()
                    val receiver = transferEngine.createReceiver(host)
                    val bitmap = BarcodeEncoder().encodeBitmap(
                        receiver.pairingPayload,
                        BarcodeFormat.QR_CODE,
                        720,
                        720
                    )
                    receiver to bitmap
                }
            }.onSuccess { (receiver, bitmap) ->
                activeReceiver = receiver
                receiverQr = bitmap
                val advertised = runCatching {
                    discovery?.startAdvertising(receiver.port.toInt())
                    discovery?.start()
                }.isSuccess
                receiverStatus = if (advertised) {
                    "Waiting for one authenticated incoming transfer on port ${receiver.port}; nearby discovery is active"
                } else {
                    "Waiting for one authenticated incoming transfer on port ${receiver.port}; QR pairing remains available"
                }
                activityScope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) { transferEngine.receiveOnce(receiver) }
                    }.onSuccess { result ->
                        transferStatus = describeResult("Received", result)
                        receiverStatus = "Transfer completed"
                    }.onFailure { error ->
                        transferStatus = "Receive failed: ${error.message ?: "unknown error"}"
                        receiverStatus = "Receiver stopped"
                    }
                    if (activeReceiver === receiver) {
                        activeReceiver = null
                        receiverQr = null
                        discovery?.stopAdvertising()
                        withContext(Dispatchers.IO) { receiver.close() }
                    }
                }
            }.onFailure { error ->
                receiverStatus = "Could not start receiver: ${error.message ?: "unknown error"}"
            }
        }
    }

    private fun stopReceiver() {
        val receiver = activeReceiver ?: return
        activeReceiver = null
        receiverQr = null
        discovery?.stopAdvertising()
        receiverStatus = "Closing receiver…"
        activityScope.launch(Dispatchers.IO) {
            runCatching { receiver.close() }
        }
        receiverStatus = "Receiver closed. If a native receive call does not return, fully close the app before retrying."
    }

    private fun sendSelectedFile() {
        val invitation = scannedPayload ?: return
        val uri = selectedFile ?: return
        transferStatus = "Preparing file and connecting securely…"
        transferProgress = null
        activityScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { transferEngine.sendFile(invitation, uri) }
            }.onSuccess { result ->
                transferStatus = describeResult("Sent", result)
            }.onFailure { error ->
                transferStatus = "Send failed: ${error.message ?: "unknown error"}"
            }
        }
    }

    private fun requestApproval(title: String, message: String): Boolean {
        if (isFinishing || isDestroyed) return false
        val latch = CountDownLatch(1)
        val approved = AtomicBoolean(false)
        runOnUiThread {
            if (isFinishing || isDestroyed) {
                latch.countDown()
            } else {
                AlertDialog.Builder(this)
                    .setTitle(title)
                    .setMessage(message)
                    .setPositiveButton("Approve") { _: DialogInterface, _: Int ->
                        approved.set(true)
                        latch.countDown()
                    }
                    .setNegativeButton("Reject") { _: DialogInterface, _: Int ->
                        latch.countDown()
                    }
                    .setOnCancelListener { latch.countDown() }
                    .show()
            }
        }
        return try {
            latch.await(2, TimeUnit.MINUTES) && approved.get()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun findAdvertisedIpv4Address(): String {
        val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
        val address = interfaces.asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { Collections.list(it.inetAddresses).asSequence() }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { !it.isLoopbackAddress && !it.isLinkLocalAddress }
        return address?.hostAddress
            ?: throw IllegalStateException("No active Wi-Fi or LAN IPv4 address was found")
    }

    private fun describeResult(prefix: String, result: TransferResult): String =
        "$prefix ${result.bytesTransferred} bytes" +
            (result.peerDeviceId?.let { " with device $it" } ?: "") +
            (result.sha256?.let { "\nSHA-256: $it" } ?: "") +
            (result.path?.let { "\nSaved at: $it" } ?: "")

    override fun onDestroy() {
        discovery?.close()
        discovery = null
        val receiver = activeReceiver
        activeReceiver = null
        Thread {
            runCatching { receiver?.close() }
            runCatching { transferEngine.close() }
        }.start()
        activityScope.cancel()
        super.onDestroy()
    }
}
