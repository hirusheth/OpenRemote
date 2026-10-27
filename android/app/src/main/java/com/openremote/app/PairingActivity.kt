package com.openremote.app

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket

/**
 * POLO pairing screen, two-phase like the original app:
 * 1. handshake until the TV shows the PIN ("A PIN appears on your TV")
 * 2. user types the PIN -> secret -> certificate registered.
 */
class PairingActivity : AppCompatActivity() {

    private var host: String = ""
    private var port: Int = 6467
    private var name: String = ""

    private lateinit var status: TextView
    private lateinit var pinInput: EditText
    private lateinit var button: Button

    private var confirmDeferred: CompletableDeferred<String>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)
        host = intent.getStringExtra("host") ?: ""
        port = intent.getIntExtra("port", 6467)
        name = intent.getStringExtra("name") ?: ""
        status = findViewById(R.id.pairStatus)
        pinInput = findViewById(R.id.pinInput)
        button = findViewById(R.id.btnPair)
        pinInput.visibility = View.GONE
        button.text = "Start pairing"
        button.setOnClickListener {
            val deferred = confirmDeferred
            if (deferred != null) {
                val pin = pinInput.text.toString().trim()
                if (pin.length != 6) {
                    Toast.makeText(this, "PIN must be 6 hex digits", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                deferred.complete(pin)
            } else {
                startPairing()
            }
        }
    }

    private fun startPairing() {
        button.isEnabled = false
        status.text = "Starting pairing..."
        CoroutineScope(Dispatchers.Main).launch {
            try {
                withContext(Dispatchers.IO) { runPairing() }
                status.text = "Paired! Your TV now trusts this phone."
                Toast.makeText(this@PairingActivity, "Paired!", Toast.LENGTH_SHORT).show()
                startActivity(
                    android.content.Intent(this@PairingActivity, RemoteActivity::class.java)
                        .putExtra("host", host)
                        .putExtra("port", port)
                        .putExtra("name", name)
                )
                finish()
            } catch (e: Exception) {
                status.text = "Pairing failed: ${e.message}"
                button.isEnabled = true
                confirmDeferred = null
            }
        }
    }

    private suspend fun runPairing() {
        val sslContext = ClientCert.sslContext(this)
        val factory = sslContext.socketFactory
        val sock = factory.createSocket() as SSLSocket
        sock.connect(java.net.InetSocketAddress(host, port), 10_000)
        sock.startHandshake()
        val input = java.io.DataInputStream(java.io.BufferedInputStream(sock.getInputStream()))
        val output = sock.getOutputStream()

        fun send(message: ByteArray) {
            synchronized(output) {
                output.write(Wire.delimited(message))
                output.flush()
            }
        }

        fun readMessage(): List<Wire.Field> {
            var length = 0
            var shift = 0
            while (true) {
                val b = input.readByte().toInt() and 0xFF
                length = length or ((b and 0x7F) shl shift)
                shift += 7
                if (b and 0x80 == 0) break
                if (shift >= 35) throw IllegalArgumentException("varint too long")
            }
            val payload = ByteArray(length)
            input.readFully(payload)
            return Wire.parseFields(payload)
        }

        val clientCert = ClientCert.clientCertificate(this)
        val serverCert: X509Certificate = sock.session.peerCertificates[0] as X509Certificate

        // Phase 1: request -> ack -> options -> configuration -> configuration_ack.
        send(Polo.encodePairingRequest("OpenRemote"))
        var pinShown = false
        while (!pinShown) {
            val fields = readMessage()
            if (Polo.statusOf(fields) != Polo.STATUS_OK) {
                throw IllegalStateException("TV rejected the pairing")
            }
            when {
                Polo.hasField(fields, Polo.F_PAIRING_REQUEST_ACK) -> send(Polo.encodeOptions())
                Polo.hasField(fields, Polo.F_OPTIONS) -> send(Polo.encodeConfiguration())
                Polo.hasField(fields, Polo.F_CONFIGURATION_ACK) -> pinShown = true
            }
        }

        // Phase 2: the PIN is on the TV screen - wait for the user.
        withContext(Dispatchers.Main) {
            status.text = "A 6-digit PIN is now shown on your TV. Type it below."
            pinInput.visibility = View.VISIBLE
            button.text = "Confirm PIN"
            button.isEnabled = true
        }
        val deferred = CompletableDeferred<String>()
        confirmDeferred = deferred
        val pin = deferred.await()

        // Phase 3: secret -> secret_ack.
        Polo.validatePinFormat(pin, clientCert, serverCert)
        send(Polo.encodeSecret(Polo.pairingSecret(clientCert, serverCert, pin)))
        while (true) {
            val fields = readMessage()
            if (Polo.statusOf(fields) != Polo.STATUS_OK) {
                throw IllegalStateException("TV rejected the PIN")
            }
            if (Polo.hasField(fields, Polo.F_SECRET_ACK)) break
        }
        confirmDeferred = null
        sock.close()
    }
}
