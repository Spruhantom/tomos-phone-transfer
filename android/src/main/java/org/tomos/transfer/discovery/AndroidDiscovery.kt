package org.tomos.transfer.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import java.util.concurrent.Executor
import java.util.concurrent.Executors

data class NearbyTransferDevice(
    val serviceName: String,
    val host: String,
    val port: Int,
    val deviceId: String?
)

/**
 * Android DNS-SD discovery adapter for _tomos-transfer._tcp.
 * Discovery records are untrusted hints: callers must still use QR-pinned TLS
 * and Rust Ed25519 authentication before transferring any data.
 */
class AndroidDiscovery(context: Context, private val onDevice: (NearbyTransferDevice) -> Unit) {
    private val manager = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val executor: Executor = Executors.newSingleThreadExecutor()
    @Volatile private var listener: NsdManager.DiscoveryListener? = null

    fun start() {
        if (listener != null) return
        val discovery = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { stop() }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) { stop() }
            override fun onDiscoveryStopped(serviceType: String) { listener = null }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (serviceInfo.serviceType.trimEnd('.') != SERVICE_TYPE.trimEnd('.')) return
                // Android 14 introduced the callback-based resolver. On older
                // versions we deliberately do not use the deprecated resolver;
                // QR pairing remains available and is the trust anchor.
                if (Build.VERSION.SDK_INT < 34) return
                manager.resolveService(serviceInfo, executor, object : NsdManager.ServiceInfoCallback {
                    override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) = Unit
                    override fun onServiceUpdated(serviceInfo: NsdServiceInfo) = publish(serviceInfo)
                    override fun onServiceLost() = Unit
                    override fun onServiceInfoCallbackUnregistered() = Unit
                })
            }
        }
        listener = discovery
        manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
    }

    private fun publish(info: NsdServiceInfo) {
        val host = if (Build.VERSION.SDK_INT >= 34) {
            info.hostAddresses.firstOrNull()?.hostAddress
        } else null
        onDevice(NearbyTransferDevice(info.serviceName, host ?: return, info.port, null))
    }

    fun stop() {
        listener?.let { runCatching { manager.stopServiceDiscovery(it) } }
        listener = null
    }

    companion object {
        private const val SERVICE_TYPE = "_tomos-transfer._tcp."
    }
}
