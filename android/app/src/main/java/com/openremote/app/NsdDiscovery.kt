package com.openremote.app

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager

/**
 * mDNS discovery of "_androidtvremote2._tcp." via Android's NsdManager
 * (evidence: the Google Home app browses the same service type; REA classes
 * defpackage.assz/astd with log tags "AtvRemote.MdnsClient"/"MdnsDvcScnner").
 */
class NsdDiscovery(private val context: Context) {
    data class TV(val name: String, val host: String, val port: Int)

    interface Listener {
        fun onFound(tv: TV)
        fun onLost(name: String)
        fun onScanStarted()
        fun onScanFailed(error: Int)
    }

    private val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private var listening = false
    private var multicastLock: WifiManager.MulticastLock? = null

    companion object {
        const val SERVICE_TYPE = "_androidtvremote2._tcp."
    }

    fun start(listener: Listener) {
        if (listening) return
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("openremote-mdns").apply {
            setReferenceCounted(false)
            acquire()
        }
        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = listener.onScanStarted()
            override fun onStartDiscoveryFailed(serviceType: String, error: Int) =
                listener.onScanFailed(error)
            override fun onStopDiscoveryFailed(serviceType: String, error: Int) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onServiceLost(serviceInfo: NsdServiceInfo) =
                listener.onLost(serviceInfo.serviceName)
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(info: NsdServiceInfo, error: Int) {}
                    override fun onServiceResolved(info: NsdServiceInfo) {
                        val host = info.host?.hostAddress ?: return
                        listener.onFound(TV(info.serviceName, host, info.port))
                    }
                })
            }
        }
        nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
        listening = true
    }

    fun stop() {
        multicastLock?.release()
        multicastLock = null
        listening = false
        // Discovery stops when the NsdManager listener is abandoned / app task ends.
    }
}
