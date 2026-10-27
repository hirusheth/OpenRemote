package com.openremote.app

import java.io.ByteArrayOutputStream

/**
 * Hand-rolled protobuf wire codec for the Android TV Remote v2 protocol.
 * Kotlin port of atv_remote/wire.py (same field numbers, same framing).
 */
object Wire {
    // RemoteMessage oneof field numbers
    const val F_CONFIGURE = 1
    const val F_SET_ACTIVE = 2
    const val F_ERROR = 3
    const val F_PING_REQUEST = 8
    const val F_PING_RESPONSE = 9
    const val F_KEY_INJECT = 10
    const val F_IME_KEY_INJECT = 20
    const val F_IME_BATCH_EDIT = 21
    const val F_VOICE_BEGIN = 30
    const val F_VOICE_PAYLOAD = 31
    const val F_VOICE_END = 32
    const val F_START = 40
    const val F_SET_VOLUME = 50
    const val F_APP_LINK = 90

    enum class Direction(val value: Int) { UNKNOWN(0), START_LONG(1), END_LONG(2), SHORT(3) }

    /** Capability bits (evidence: REA ev_2ecec7ed, defpackage.asub). */
    object Capability {
        const val INPUT = 0x2
        const val IME = 0x4
        const val VOICE = 0x8
        const val PTT_ASSISTANT = 0x10
        const val POWER = 0x20
        const val VOLUME = 0x40
        const val GAMEPAD = 0x100
        const val APP_LINK = 0x800
    }

    fun encodeVarint(value: Int): ByteArray {
        var v = value
        val out = ByteArrayOutputStream()
        while (true) {
            val bits = v and 0x7F
            v = v ushr 7
            if (v != 0) out.write(bits or 0x80) else { out.write(bits); break }
        }
        return out.toByteArray()
    }

    fun decodeVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var p = offset
        while (true) {
            if (p >= data.size) throw IllegalArgumentException("truncated varint")
            val b = data[p].toInt() and 0xFF
            p++
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
            if (b and 0x80 == 0) return result to p
        }
    }

    fun varintField(field: Int, value: Int): ByteArray =
        encodeVarint((field shl 3) or 0) + encodeVarint(value)

    fun bytesField(field: Int, value: ByteArray): ByteArray =
        encodeVarint((field shl 3) or 2) + encodeVarint(value.size) + value

    fun bytesField(field: Int, value: String): ByteArray = bytesField(field, value.toByteArray(Charsets.UTF_8))

    fun messageField(field: Int, encoded: ByteArray): ByteArray = bytesField(field, encoded)

    fun delimited(message: ByteArray): ByteArray = encodeVarint(message.size) + message

    /** One parsed wire field. */
    data class Field(val number: Int, val wireType: Int, val payload: ByteArray)

    fun parseFields(data: ByteArray): List<Field> {
        val out = mutableListOf<Field>()
        var offset = 0
        while (offset < data.size) {
            val (key, o1) = decodeVarint(data, offset)
            val number = (key shr 3).toInt()
            val wireType = (key and 0x7).toInt()
            offset = o1
            when (wireType) {
                0 -> {
                    val (v, o2) = decodeVarint(data, offset)
                    out.add(Field(number, 0, encodeVarint(v.toInt())))
                    offset = o2
                }
                1 -> { out.add(Field(number, 1, data.copyOfRange(offset, offset + 8))); offset += 8 }
                2 -> {
                    val (len, o2) = decodeVarint(data, offset)
                    offset = o2
                    out.add(Field(number, 2, data.copyOfRange(offset, offset + len.toInt())))
                    offset += len.toInt()
                }
                5 -> { out.add(Field(number, 5, data.copyOfRange(offset, offset + 4))); offset += 4 }
                else -> throw IllegalArgumentException("unsupported wire type $wireType")
            }
        }
        return out
    }

    fun varintOf(field: Field?): Int? {
        if (field == null || field.wireType != 0) return null
        val (v, _) = decodeVarint(field.payload, 0)
        return v.toInt()
    }

    fun bytesOf(field: Field?): ByteArray? {
        if (field == null || field.wireType != 2) return null
        return field.payload
    }

    // ---------------------------------------------------------------- outbound

    fun keyInject(keyCode: Int, direction: Direction = Direction.SHORT): ByteArray =
        messageField(
            F_KEY_INJECT,
            varintField(1, keyCode) + varintField(2, direction.value)
        )

    fun pingResponse(val1: Int): ByteArray = varintField(F_PING_RESPONSE, val1)

    fun setActive(mask: Int): ByteArray = varintField(F_SET_ACTIVE, mask)

    fun configure(
        capabilityMask: Int,
        model: String,
        vendor: String,
        packageName: String,
        appVersion: String,
    ): ByteArray =
        messageField(
            F_CONFIGURE,
            varintField(1, capabilityMask) +
                messageField(
                    2,
                    bytesField(1, model) + bytesField(2, vendor) +
                        varintField(3, 1) + bytesField(4, "1") +
                        bytesField(5, packageName) + bytesField(6, appVersion)
                )
        )

    fun voiceBegin(sessionId: Int, packageName: String = "com.openremote.app"): ByteArray =
        messageField(F_VOICE_BEGIN, varintField(1, sessionId) + bytesField(2, packageName))

    fun voicePayload(sessionId: Int, samples: ByteArray): ByteArray =
        messageField(F_VOICE_PAYLOAD, varintField(1, sessionId) + bytesField(2, samples))

    fun voiceEnd(sessionId: Int): ByteArray = messageField(F_VOICE_END, varintField(1, sessionId))

    // ---------------------------------------------------------------- inbound

    data class Inbound(val oneof: Int, val fields: List<Field>) {
        fun field(number: Int): Field? = fields.firstOrNull { it.number == number }
    }

    fun parseInbound(data: ByteArray): Inbound {
        val fields = parseFields(data)
        return Inbound(oneof = fields.maxOfOrNull { it.number } ?: 0, fields = fields)
    }

    data class DeviceInfo(val model: String, val vendor: String, val appVersion: String)

    fun deviceInfoOf(field: Field?): DeviceInfo? {
        val raw = bytesOf(field) ?: return null
        var model = ""; var vendor = ""; var appVersion = ""
        for (f in parseFields(raw)) {
            when (f.number) {
                1 -> bytesOf(f)?.let { model = String(it) }
                2 -> bytesOf(f)?.let { vendor = String(it) }
                6 -> bytesOf(f)?.let { appVersion = String(it) }
            }
        }
        return DeviceInfo(model, vendor, appVersion)
    }

    fun configureOf(field: Field?): Pair<Int, DeviceInfo?>? {
        val raw = bytesOf(field) ?: return null
        var mask = 0
        var info: DeviceInfo? = null
        for (f in parseFields(raw)) {
            if (f.number == 1) mask = varintOf(f) ?: 0
            if (f.number == 2) info = deviceInfoOf(f)
        }
        return mask to info
    }

    fun startedOf(field: Field?): Boolean? {
        val raw = bytesOf(field) ?: return null
        for (f in parseFields(raw)) if (f.number == 1) return (varintOf(f) ?: 0) != 0
        return null
    }

    fun pingVal1Of(field: Field?): Int? {
        val raw = bytesOf(field) ?: return null
        for (f in parseFields(raw)) if (f.number == 1) return varintOf(f)
        return null
    }

    fun volumeOf(field: Field?): Triple<Int, Int, Boolean>? {
        val raw = bytesOf(field) ?: return null
        var max = 0; var level = 0; var muted = false
        for (f in parseFields(raw)) when (f.number) {
            6 -> max = varintOf(f) ?: 0
            7 -> level = varintOf(f) ?: 0
            8 -> muted = (varintOf(f) ?: 0) != 0
        }
        return Triple(level, max, muted)
    }

    fun voiceSessionIdOf(field: Field?): Int? {
        val raw = bytesOf(field) ?: return null
        for (f in parseFields(raw)) if (f.number == 1) return varintOf(f)
        return null
    }

    /** RemoteImeBatchEdit: ime_counter = 1, field_counter = 2. */
    fun imeCountersOf(field: Field?): Pair<Int, Int>? {
        val raw = bytesOf(field) ?: return null
        var ime = 0
        var fieldCounter = 0
        for (f in parseFields(raw)) when (f.number) {
            1 -> ime = varintOf(f) ?: 0
            2 -> fieldCounter = varintOf(f) ?: 0
        }
        return ime to fieldCounter
    }

    /** RemoteImeKeyInject -> RemoteAppInfo.app_package (field 12). */
    fun currentAppOf(field: Field?): String? {
        val appInfo = bytesOf(field) ?: return null
        for (f in parseFields(appInfo)) if (f.number == 12) {
            return bytesOf(f)?.toString(Charsets.UTF_8)
        }
        return null
    }
}
