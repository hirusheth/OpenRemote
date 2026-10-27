package com.openremote.app

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * First screen: discover TVs via mDNS (NsdManager), or connect by IP.
 * Tapping a TV starts the session; if the TV doesn't know this phone yet it
 * routes to PairingActivity first.
 */
class DiscoveryActivity : AppCompatActivity() {

    private lateinit var discovery: NsdDiscovery
    private val devices = LinkedHashMap<String, NsdDiscovery.TV>()

    private lateinit var deviceList: LinearLayout
    private lateinit var progress: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_discovery)
        deviceList = findViewById(R.id.deviceList)
        progress = findViewById(R.id.progress)
        discovery = NsdDiscovery(this)

        findViewById<Button>(R.id.btnConnectIp).setOnClickListener {
            val ip = findViewById<EditText>(R.id.ipInput).text.toString().trim()
            if (ip.isNotEmpty()) openRemote(NsdDiscovery.TV(name = ip, host = ip, port = 6467))
        }
    }

    override fun onResume() {
        super.onResume()
        devices.clear()
        refreshList()
        progress.visibility = View.VISIBLE
        discovery.start(object : NsdDiscovery.Listener {
            override fun onScanStarted() {}
            override fun onScanFailed(error: Int) {
                runOnUiThread {
                    Toast.makeText(
                        this@DiscoveryActivity,
                        "mDNS scan failed (error $error) - use the IP field below",
                        Toast.LENGTH_LONG
                    ).show()
                    progress.visibility = View.GONE
                }
            }

            override fun onFound(tv: NsdDiscovery.TV) {
                runOnUiThread {
                    progress.visibility = View.GONE
                    devices[tv.name] = tv
                    refreshList()
                }
            }

            override fun onLost(name: String) {
                runOnUiThread {
                    devices.remove(name)
                    refreshList()
                }
            }
        })
    }

    override fun onPause() {
        super.onPause()
        discovery.stop()
    }

    private fun refreshList() {
        deviceList.removeAllViews()
        if (devices.isEmpty()) {
            val hint = TextView(this).apply {
                text = getString(R.string.scanning)
                setTextColor(resources.getColor(R.color.text_secondary, theme))
                textSize = 14f
                setPadding(0, 12, 0, 12)
            }
            deviceList.addView(hint)
        }
        for (tv in devices.values) {
            val row = TextView(this).apply {
                text = "${tv.name}\n${tv.host}:${tv.port}"
                setTextColor(resources.getColor(R.color.text_primary, theme))
                textSize = 16f
                setOnClickListener { openRemote(tv) }
            }
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            params.setMargins(0, 8, 0, 8)
            row.layoutParams = params
            row.setPadding(28, 32, 28, 32)
            row.setBackgroundResource(R.drawable.bg_trackpad)
            deviceList.addView(row)
        }
    }

    private fun openRemote(tv: NsdDiscovery.TV) {
        CoroutineScope(Dispatchers.Main).launch {
            val paired = withContext(Dispatchers.IO) { probeSession(tv) }
            val target = if (paired) RemoteActivity::class.java else PairingActivity::class.java
            startActivity(
                Intent(this@DiscoveryActivity, target)
                    .putExtra("host", tv.host)
                    .putExtra("port", tv.port)
                    .putExtra("name", tv.name)
            )
        }
    }

    /** True when the TV accepts a session from this phone (i.e. already paired). */
    private fun probeSession(tv: NsdDiscovery.TV): Boolean {
        var configured = false
        val done = CountDownLatch(1)
        val client = RemoteClient(this, tv.host, tv.port, object : RemoteClient.Callbacks {
            override fun onConfigured(capabilities: Int, deviceInfo: Wire.DeviceInfo?) {
                configured = true
                done.countDown()
            }

            override fun onStarted(started: Boolean) {}
            override fun onVolume(level: Int, max: Int, muted: Boolean) {}
            override fun onCurrentApp(packageName: String) {}
            override fun onVoiceBegin(sessionId: Int) {}
            override fun onClosed(exception: Exception?) {
                if (!configured) done.countDown()
            }
        })
        try {
            client.connect()
            done.await(8, TimeUnit.SECONDS)
        } catch (_: Exception) {
        } finally {
            client.close()
        }
        return configured
    }
}
