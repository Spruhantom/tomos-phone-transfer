package org.tomos.transfer

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.tomos.transfer.discovery.AndroidDiscovery
import org.tomos.transfer.discovery.NearbyTransferDevice
import org.tomos.transfer.pairing.PairingQrParser
import org.tomos.transfer.security.AndroidIdentityStore
import java.util.UUID

class MainActivity : ComponentActivity() {
    private var identityStatus by mutableStateOf("Preparing secure device identity…")
    private var deviceId by mutableStateOf<UUID?>(null)
    private var selectedFile by mutableStateOf<Uri?>(null)
    private var selectedFileName by mutableStateOf<String?>(null)
    private var pairingStatus by mutableStateOf("Scan a trusted device's QR code to begin pairing.")
    private var scannedDevice by mutableStateOf<String?>(null)
    private val nearbyDevices = mutableStateListOf<NearbyTransferDevice>()
    private val activityScope = MainScope()
    private var discovery: AndroidDiscovery? = null

    private val qrScanner = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents ?: return@registerForActivityResult
        runCatching { PairingQrParser.parse(contents) }
            .onSuccess { invitation ->
                scannedDevice = invitation.deviceId
                pairingStatus = "Invitation validated for ${invitation.host}:${invitation.port}. TLS and identity authentication are still required."
            }
            .onFailure { error ->
                scannedDevice = null
                pairingStatus = "Pairing QR rejected: ${error.message ?: "invalid invitation"}"
            }
    }

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            selectedFile = uri
            selectedFileName = contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
                ?: uri.lastPathSegment
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
                                    deviceId?.let { Text("Device ID: $it", style = MaterialTheme.typography.labelSmall) }
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Pair a device", style = MaterialTheme.typography.titleMedium)
                                    Text(pairingStatus, style = MaterialTheme.typography.bodyMedium)
                                    scannedDevice?.let { Text("Peer identity: $it", style = MaterialTheme.typography.labelSmall) }
                                    Button(onClick = {
                                        val options = ScanOptions().apply {
                                            setPrompt("Scan a TomOS Transfer pairing QR code")
                                            setBeepEnabled(false)
                                            setOrientationLocked(false)
                                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        }
                                        qrScanner.launch(options)
                                    }, modifier = Modifier.fillMaxWidth()) {
                                        Text("Scan pairing QR code")
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
                                        }) { Text("Stop") }
                                    }
                                    if (nearbyDevices.isEmpty()) Text("No devices discovered yet.")
                                    nearbyDevices.forEach { device ->
                                        Text("${device.serviceName} — ${device.host}:${device.port}")
                                    }
                                    Text("Discovery results are untrusted until QR-pinned TLS and device authentication succeed.",
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                        item {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Text("Send a file", style = MaterialTheme.typography.titleMedium)
                                    Text(selectedFileName ?: "No file selected")
                                    Button(onClick = { filePicker.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                                        Text("Choose file")
                                    }
                                    Text("File selection is ready. Transfer starts only after secure pairing is connected to the Rust engine.",
                                        style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            }
        }

        activityScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    AndroidIdentityStore(applicationContext).loadOrCreate()
                }
            }.onSuccess { identity ->
                deviceId = identity.deviceId
                identityStatus = "Secure identity stored on this device"
            }.onFailure { error ->
                identityStatus = "Secure identity unavailable: ${error.message ?: "unknown error"}"
            }
        }
    }

    override fun onDestroy() {
        discovery?.stop()
        discovery = null
        activityScope.cancel()
        super.onDestroy()
    }
}
