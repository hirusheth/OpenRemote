package com.openremote.app

import android.content.Context
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * The remote session: TLS socket to the TV, length-delimited protobuf
 * framing, the configure handshake, keep-alive ping answers, key/text/voice
 * sending. Kotlin port of atv_remote/client.py.
 *
 * Evidence (REA, Google Home 4.34.22.2): asru.b() = TLS SSLSocket with client
 * certificate + keepAlive + tcpNoDelay; asrs.handleMessage = writeDelimitedTo;
 * asrd.f = configure handshake state machine.
 */
class RemoteClient(
    private val context: Context,
    private val host: String,
    private val port: Int,
    private val callbacks: Callbacks,
) {
    interface Callbacks {
        fun onConfigured(capabilities: Int, deviceInfo: Wire.DeviceInfo?)
        fun onStarted(started: Boolean)
        fun onVolume(level: Int, max: Int, muted: Boolean)
        fun onCurrentApp(packageName: String)
        fun onVoiceBegin(sessionId: Int)
        fun onClosed(exception: Exception?)
    }

    private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: OutputStream? = null
    private var readerThread: Thread? = null
    private val writeLock = Any()
    @Volatile private var closed = false

    private var imeCounter = 0
    private var imeFieldCounter = 0
    private var voiceSession: Int? = null

    fun connect() {
        val sslContext = ClientCert.sslContext(context)
        val factory = sslContext.socketFactory
        val sock = factory.createSocket() as SSLSocket
        sock.keepAlive = true
        sock.tcpNoDelay = true
        sock.connect(InetSocketAddress(host, port), 10_000)
        sock.startHandshake()
        socket = sock
        input = DataInputStream(BufferedInputStream(sock.getInputStream()))
        output = sock.getOutputStream()
        readerThread = Thread({ readLoop() }, "openremote-reader").apply {
            isDaemon = true
            start()
        }
    }

    fun close() {
        closed = true
        try { socket?.close() } catch (_: Exception) {}
    }

    fun sendKey(keyCode: Int, direction: Wire.Direction = Wire.Direction.SHORT) =
        send(Wire.keyInject(keyCode, direction))

    fun sendText(text: String) =
        send(buildImeBatchEdit(imeCounter, imeFieldCounter, text))

    fun sendAppLink(link: String) =
        send(Wire.messageField(Wire.F_APP_LINK, Wire.bytesField(1, link)))

    // ------------------------------------------------------------------ voice

    @Volatile private var micThread: Thread? = null

    /** Send KEYCODE_SEARCH, wait for remote_voice_begin, echo it. */
    fun startVoice(onReady: (Int) -> Unit, onError: (String) -> Unit) {
        val waiter = Thread({
            try {
                val latch = java.util.concurrent.CountDownLatch(1)
                var sessionId = -1
                synchronized(this) { pendingVoiceBegin = { id ->
                    sessionId = id; latch.countDown()
                } }
                send(Wire.keyInject(84)) // KEYCODE_SEARCH
                if (!latch.await(2, java.util.concurrent.TimeUnit.SECONDS)) {
                    onError("No voice session from the TV")
                    return@Thread
                }
                synchronized(this) { pendingVoiceBegin = null }
                voiceSession = sessionId
                send(Wire.voiceBegin(sessionId))
                onReady(sessionId)
            } catch (e: Exception) {
                onError(e.message ?: "voice failed")
            }
        }, "openremote-voice-start")
        waiter.start()
    }

    @Volatile private var pendingVoiceBegin: ((Int) -> Unit)? = null

    fun endVoice() {
        val session = voiceSession ?: return
        voiceSession = null
        stopMic()
        send(Wire.voiceEnd(session))
    }

    private fun sendVoiceChunk(samples: ByteArray) {
        val session = voiceSession ?: return
        var offset = 0
        while (offset < samples.size) {
            val end = minOf(offset + 20 * 1024, samples.size)
            var chunk = samples.copyOfRange(offset, end)
            if (chunk.size < 8 * 1024) chunk = chunk.copyOf(8 * 1024) // zero-pad
            send(Wire.voicePayload(session, chunk))
            offset = end
        }
    }

    /** Streams 16-bit PCM 8 kHz mono from the microphone until stopped. */
    fun startMic() {
        if (micThread != null) return
        val minBuf = AudioRecord.getMinBufferSize(
            8000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
        )
        val record = AudioRecord(
            MediaRecorder.AudioSource.MIC, 8000,
            AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
            maxOf(minBuf, 8192)
        )
        if (record.state != AudioRecord.STATE_INITIALIZED) {
            record.release()
            return
        }
        val buffer = ByteArray(4096)
        val pending = java.io.ByteArrayOutputStream()
        micThread = Thread({
            record.startRecording()
            while (voiceSession != null && !closed) {
                val n = record.read(buffer, 0, buffer.size)
                if (n > 0) pending.write(buffer, 0, n)
                if (pending.size() >= 8 * 1024) {
                    sendVoiceChunk(pending.toByteArray())
                    pending.reset()
                }
            }
            if (pending.size() > 0) sendVoiceChunk(pending.toByteArray())
            record.stop()
            record.release()
        }, "openremote-mic")
        micThread?.start()
    }

    fun stopMic() {
        micThread?.interrupt()
        micThread = null
    }

    // -------------------------------------------------------------- internals

    private fun buildImeBatchEdit(imeCounter: Int, fieldCounter: Int, text: String): ByteArray {
        val param = maxOf(text.length - 1, 0)
        val imeObject =
            Wire.varintField(1, param) + Wire.varintField(2, param) + Wire.bytesField(3, text)
        val editInfo = Wire.varintField(1, 1) + Wire.messageField(2, imeObject)
        val batch = Wire.varintField(1, imeCounter) + Wire.varintField(2, fieldCounter) +
            Wire.messageField(3, editInfo)
        return Wire.messageField(Wire.F_IME_BATCH_EDIT, batch)
    }

    private fun send(message: ByteArray) {
        synchronized(writeLock) {
            val out = output ?: return
            out.write(Wire.delimited(message))
            out.flush()
        }
    }

    private fun readLoop() {
        var lastException: Exception? = null
        try {
            val input = this.input!!
            while (!closed) {
                // varint length prefix, then payload (writeDelimitedTo framing)
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
                handleMessage(Wire.parseInbound(payload))
            }
        } catch (e: EOFException) {
        } catch (e: Exception) {
            lastException = e
        }
        stopMic()
        if (!closed) callbacks.onClosed(lastException)
    }

    private fun handleMessage(message: Wire.Inbound) {
        when (message.oneof) {
            Wire.F_CONFIGURE -> {
                val (mask, info) = Wire.configureOf(message.field(Wire.F_CONFIGURE))
                    ?: return
                val offer = RemoteConfig.capabilityMask()
                send(Wire.configure(offer and mask, "OpenRemote", "OpenRemote",
                    "com.openremote.app", "0.4.0"))
                callbacks.onConfigured(mask, info)
            }
            Wire.F_SET_ACTIVE -> {
                (Wire.varintOf(message.field(Wire.F_SET_ACTIVE)))?.let {
                    send(Wire.setActive(it))
                }
            }
            Wire.F_PING_REQUEST -> {
                Wire.pingVal1Of(message.field(Wire.F_PING_REQUEST))?.let {
                    send(Wire.pingResponse(it))
                }
            }
            Wire.F_START -> {
                Wire.startedOf(message.field(Wire.F_START))?.let { callbacks.onStarted(it) }
            }
            Wire.F_SET_VOLUME -> {
                Wire.volumeOf(message.field(Wire.F_SET_VOLUME))?.let { (level, max, muted) ->
                    callbacks.onVolume(level, max, muted)
                }
            }
            Wire.F_IME_BATCH_EDIT -> {
                val counters = Wire.imeCountersOf(message.field(Wire.F_IME_BATCH_EDIT))
                if (counters != null) { imeCounter = counters.first; imeFieldCounter = counters.second }
            }
            Wire.F_IME_KEY_INJECT -> {
                Wire.currentAppOf(message.field(Wire.F_IME_KEY_INJECT))?.let {
                    callbacks.onCurrentApp(it)
                }
            }
            Wire.F_VOICE_BEGIN -> {
                Wire.voiceSessionIdOf(message.field(Wire.F_VOICE_BEGIN))?.let { id ->
                    pendingVoiceBegin?.invoke(id)
                }
            }
        }
    }

    private object RemoteConfig {
        fun capabilityMask(): Int =
            Wire.Capability.INPUT or Wire.Capability.IME or Wire.Capability.VOICE or
                Wire.Capability.POWER or Wire.Capability.VOLUME
    }
}
