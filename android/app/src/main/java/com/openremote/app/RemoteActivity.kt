package com.openremote.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * The remote screen — 1:1 with the classic Android TV remote: dark trackpad
 * with center dot, back/home/assistant circles, mute + volume pill, top bar
 * with close / device name / power / overflow.
 */
class RemoteActivity : AppCompatActivity(), TrackpadView.Listener, RemoteClient.Callbacks {

    private var host: String = ""
    private var port: Int = 6467
    private var deviceName: String = ""

    private lateinit var nameView: TextView

    private var voiceActive = false
    private var client: RemoteClient? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_remote)
        host = intent.getStringExtra("host") ?: ""
        port = intent.getIntExtra("port", 6467)
        deviceName = intent.getStringExtra("name") ?: ""
        nameView = findViewById(R.id.tvName)
        nameView.text = deviceName.uppercase()

        val trackpad = findViewById<TrackpadView>(R.id.trackpad)
        trackpad.listener = this

        fun key(code: Int): View.OnClickListener = View.OnClickListener { client?.sendKey(code) }

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener(key(4))   // BACK
        findViewById<ImageButton>(R.id.btnHome).setOnClickListener(key(3))   // HOME
        findViewById<ImageButton>(R.id.btnPower).setOnClickListener(key(26)) // POWER
        findViewById<ImageButton>(R.id.btnMute).setOnClickListener(key(164)) // VOLUME_MUTE
        findViewById<ImageButton>(R.id.btnVolumeUp).setOnClickListener(key(24))
        findViewById<ImageButton>(R.id.btnVolumeDown).setOnClickListener(key(25))
        findViewById<ImageButton>(R.id.btnClose).setOnClickListener { finish() }
        findViewById<ImageButton>(R.id.btnOverflow).setOnClickListener {
            Toast.makeText(this, "OpenRemote for Android - Android TV Remote v2",
                Toast.LENGTH_SHORT).show()
        }

        // Assistant: hold to talk.
        val assistant = findViewById<ImageButton>(R.id.btnAssistant)
        assistant.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> startVoice()
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> stopVoice()
            }
            view.performClick()
            true
        }

        connect()
    }

    private fun connect() {
        val c = RemoteClient(this, host, port, this)
        client = c
        Thread({
            try {
                c.connect()
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Connection failed: ${e.message}",
                        Toast.LENGTH_LONG).show()
                    finish()
                }
            }
        }, "openremote-connect").start()
    }

    override fun onDirection(direction: TrackpadView.Direction) {
        val code = when (direction) {
            TrackpadView.Direction.UP -> 19
            TrackpadView.Direction.DOWN -> 20
            TrackpadView.Direction.LEFT -> 21
            TrackpadView.Direction.RIGHT -> 22
        }
        client?.sendKey(code)
    }

    override fun onTap() {
        client?.sendKey(23) // DPAD_CENTER
    }

    // ------------------------------------------------------------- voice

    private fun startVoice() {
        if (voiceActive) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.RECORD_AUDIO), 1
            )
            return
        }
        voiceActive = true
        client?.startVoice(
            onReady = {
                runOnUiThread { client?.startMic() }
            },
            onError = { message ->
                runOnUiThread {
                    voiceActive = false
                    Toast.makeText(this, "Voice: $message", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    private fun stopVoice() {
        if (!voiceActive) return
        voiceActive = false
        client?.endVoice()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 1) {
            if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
                startVoice()
            } else {
                Toast.makeText(this, "Microphone permission needed for voice",
                    Toast.LENGTH_SHORT).show()
            }
        }
    }

    // --------------------------------------------------- session callbacks

    override fun onConfigured(capabilities: Int, deviceInfo: Wire.DeviceInfo?) {
        runOnUiThread {
            val model = deviceInfo?.let { "${it.vendor} ${it.model}".trim() }
            if (!model.isNullOrBlank()) nameView.text = model.uppercase()
        }
    }

    override fun onStarted(started: Boolean) {}

    override fun onVolume(level: Int, max: Int, muted: Boolean) {}

    override fun onVoiceBegin(sessionId: Int) {}

    override fun onCurrentApp(packageName: String) {}

    override fun onClosed(exception: Exception?) {
        runOnUiThread {
            Toast.makeText(this, "Connection closed", Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVoice()
        client?.close()
    }
}
