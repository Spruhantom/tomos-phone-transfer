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
 * and the Rust Ed25519 authentication protocol before transferring any data.
 */
class AndroidDiscovery(context: Context, private val onDevice: (NearbyTransferDevice) -> Unit) {
    private val manager = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val executor: Executor = Executors.newSingleThreadExecutor()
    @Volatile private var listener: NsdManager.DiscoveryListener? = null

    @Suppress("DEPRECATION")
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
                if (Build.VERSION.SDK_INT >= 34) {
                    manager.resolveService(serviceInfo, executor, object : NsdManager.ServiceInfoCallback {
                        override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) = Unit
                        override fun onServiceUpdated(serviceInfo: NsdServiceInfo) = publish(serviceInfo)
                        override fun onServiceLost() = Unit
                        override fun onServiceInfoCallbackUnregistered() = Unit
                    })
                } else {
                    manager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) = Unit
                        override fun onServiceResolved(info: NsdServiceInfo) = publish(info)
                    })
                }
            }
        }
        listener = discovery
        manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
    }

    private fun publish(info: NsdServiceInfo) {
        val host = if (Build.VERSION.SDK_INT >= 34) {
            info.hostAddresses.firstOrNull()?.hostAddress
        } else {
            @Suppress("DEPRECATION")
            info.host?.hostAddress
        } ?: return
        val deviceId = runCatching {
            if (Build.VERSION.SDK_INT >= 21) info.getAttribute("device_id")?.toString(Charsets.UTF_8) else null
        }.getOrNull()
        onDevice(NearbyTransferDevice(info.serviceName, host, info.port, deviceId))
    }

    fun stop() {
        listener?.let { runCatching { manager.stopServiceDiscovery(it) } }
        listener = null
    }

    companion object {
        private const val SERVICE_TYPE = "_tomos-transfer._tcp."
    }
}
