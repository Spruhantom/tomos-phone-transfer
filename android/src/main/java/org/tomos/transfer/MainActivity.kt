package org.tomos.transfer

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.tomos.transfer.security.AndroidIdentityStore
import java.util.UUID

class MainActivity : ComponentActivity() {
    private var identityStatus by mutableStateOf("Preparing secure device identity…")
    private var deviceId by mutableStateOf<UUID?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                LaunchedEffect(Unit) {
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

                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text("TomOS Transfer", style = MaterialTheme.typography.headlineLarge)
                        Text(
                            "Move files directly between your Android and Linux devices.",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("Device security", style = MaterialTheme.typography.titleMedium)
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(identityStatus, style = MaterialTheme.typography.bodyMedium)
                                deviceId?.let {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("Device ID: $it", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("Transfer engine", style = MaterialTheme.typography.titleMedium)
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    "Secure pairing and transfer are being connected to the shared Rust engine. " +
                                        "No transfer is started until that native bridge is available.",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
