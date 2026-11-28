package org.tomos.transfer.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.Executors

data class NearbyTransferDevice(
    val serviceName: String,
    val host: String,
    val port: Int,
    val deviceId: String?
)

/**
 * Android DNS-SD discovery and advertising for _tomos-transfer._tcp.
 *
 * Discovery records are untrusted hints. A QR invitation and the Rust
 * certificate-pinning/Ed25519 authentication flow remain mandatory.
 */
class AndroidDiscovery(context: Context, private val onDevice: (NearbyTransferDevice) -> Unit) {
    private val manager = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val executor: Executor = Executors.newSingleThreadExecutor()
    @Volatile private var discoveryListener: NsdManager.DiscoveryListener? = null
    @Volatile private var registrationListener: NsdManager.RegistrationListener? = null
    private val serviceInfoCallbacks = ConcurrentHashMap<String, NsdManager.ServiceInfoCallback>()

    @Synchronized
    fun start() {
        if (discoveryListener != null) return
        val discovery = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                synchronized(this@AndroidDiscovery) { discoveryListener = null }
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                synchronized(this@AndroidDiscovery) { discoveryListener = null }
            }
            override fun onDiscoveryStopped(serviceType: String) {
                synchronized(this@AndroidDiscovery) { discoveryListener = null }
            }
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (serviceInfo.serviceType.trimEnd('.') != SERVICE_TYPE.trimEnd('.')) return
                resolve(serviceInfo)
            }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                serviceInfoCallbacks.remove(serviceInfo.serviceName)?.let { callback ->
                    runCatching { manager.unregisterServiceInfoCallback(callback) }
                }
            }
        }
        discoveryListener = discovery
        try {
            manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
        } catch (failure: RuntimeException) {
            discoveryListener = null
            throw failure
        }
    }

    /**
     * Advertises the currently active receiver. This never conveys trust:
     * clients must still scan and validate the receiver's one-time QR code.
     */
    @Synchronized
    fun startAdvertising(port: Int, deviceId: String? = null) {
        require(port in 1..65535) { "Invalid TomOS Transfer discovery port" }
        if (registrationListener != null) return

        val service = NsdServiceInfo().apply {
            serviceName = "TomOS Transfer"
            serviceType = SERVICE_TYPE
            setPort(port)
            deviceId?.takeIf { it.isNotBlank() }?.let {
                setAttribute("device_id", it.take(255))
            }
        }
        val registration = object : NsdManager.RegistrationListener {
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                synchronized(this@AndroidDiscovery) {
                    if (registrationListener === this) registrationListener = null
                }
            }
            override fun onServiceRegistered(serviceInfo: NsdServiceInfo) = Unit
            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {
                synchronized(this@AndroidDiscovery) {
                    if (registrationListener === this) registrationListener = null
                }
            }
            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
        }
        registrationListener = registration
        try {
            manager.registerService(service, NsdManager.PROTOCOL_DNS_SD, registration)
        } catch (failure: RuntimeException) {
            registrationListener = null
            throw failure
        }
    }

    private fun resolve(info: NsdServiceInfo) {
        if (Build.VERSION.SDK_INT >= 34) {
            val key = info.serviceName
            val callback = object : NsdManager.ServiceInfoCallback {
                override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                    serviceInfoCallbacks.remove(key, this)
                }
                override fun onServiceUpdated(serviceInfo: NsdServiceInfo) = publish(serviceInfo)
                override fun onServiceLost() {
                    serviceInfoCallbacks.remove(key, this)
                    runCatching { manager.unregisterServiceInfoCallback(this) }
                }
                override fun onServiceInfoCallbackUnregistered() {
                    serviceInfoCallbacks.remove(key, this)
                }
            }
            if (serviceInfoCallbacks.putIfAbsent(key, callback) == null) {
                try {
                    manager.registerServiceInfoCallback(info, executor, callback)
                } catch (failure: RuntimeException) {
                    serviceInfoCallbacks.remove(key, callback)
                }
            }
        } else {
            @Suppress("DEPRECATION")
            manager.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
                override fun onServiceResolved(serviceInfo: NsdServiceInfo) = publish(serviceInfo)
            })
        }
    }

    private fun publish(info: NsdServiceInfo) {
        val host = if (Build.VERSION.SDK_INT >= 34) {
            info.hostAddresses.firstOrNull()?.hostAddress
        } else {
            @Suppress("DEPRECATION")
            info.host?.hostAddress
        } ?: return
        val deviceId = runCatching { info.attributes["device_id"]?.toString(Charsets.UTF_8) }.getOrNull()
        onDevice(NearbyTransferDevice(info.serviceName, host, info.port, deviceId))
    }

    @Synchronized
    fun stopAdvertising() {
        registrationListener?.let { listener ->
            runCatching { manager.unregisterService(listener) }
        }
        registrationListener = null
    }

    @Synchronized
    fun stop() {
        discoveryListener?.let { listener ->
            runCatching { manager.stopServiceDiscovery(listener) }
        }
        discoveryListener = null
        serviceInfoCallbacks.values.toList().forEach { callback ->
            runCatching { manager.unregisterServiceInfoCallback(callback) }
        }
        serviceInfoCallbacks.clear()
    }

    fun close() {
        stop()
        stopAdvertising()
        (executor as? java.util.concurrent.ExecutorService)?.shutdownNow()
    }

    companion object {
        private const val SERVICE_TYPE = "_tomos-transfer._tcp."
    }
}
