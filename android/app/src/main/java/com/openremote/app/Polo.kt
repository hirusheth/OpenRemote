package com.openremote.app

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

/**
 * POLO pairing protocol (client side). Kotlin port of atv_remote/pairing.py.
 */
object Polo {
    const val STATUS_OK = 200
    const val SERVICE_NAME = "atvremote"

    const val F_PROTOCOL_VERSION = 1
    const val F_STATUS = 2
    const val F_PAIRING_REQUEST = 10
    const val F_PAIRING_REQUEST_ACK = 11
    const val F_OPTIONS = 20
    const val F_CONFIGURATION = 30
    const val F_CONFIGURATION_ACK = 31
    const val F_SECRET = 40
    const val F_SECRET_ACK = 41

    private fun outer(fields: ByteArray, status: Int = STATUS_OK): ByteArray =
        Wire.varintField(F_PROTOCOL_VERSION, 2) + Wire.varintField(F_STATUS, status) + fields

    fun encodePairingRequest(clientName: String): ByteArray =
        outer(
            Wire.messageField(
                F_PAIRING_REQUEST,
                Wire.bytesField(1, SERVICE_NAME) + Wire.bytesField(2, clientName)
            )
        )

    fun encodeOptions(): ByteArray {
        // Options{input_encodings[0]{type: HEX(3), symbol_length: 6}, preferred_role: INPUT(1)}
        val encoding = Wire.varintField(1, 3) + Wire.varintField(2, 6)
        val options = Wire.messageField(1, encoding) + Wire.varintField(3, 1)
        return outer(Wire.messageField(F_OPTIONS, options))
    }

    fun encodeConfiguration(): ByteArray {
        val encoding = Wire.varintField(1, 3) + Wire.varintField(2, 6)
        val configuration = Wire.messageField(1, encoding) + Wire.varintField(2, 1)
        return outer(Wire.messageField(F_CONFIGURATION, configuration))
    }

    fun encodeSecret(secret: ByteArray): ByteArray =
        outer(Wire.messageField(F_SECRET, Wire.bytesField(1, secret)))

    fun isPairingMessage(payload: ByteArray): Boolean {
        val key = Wire.decodeVarint(payload, 0).first
        return (key and 0x7).toInt() == 0 && (key shr 3).toInt() == F_PROTOCOL_VERSION
    }

    fun parseOuter(payload: ByteArray): List<Wire.Field> = Wire.parseFields(payload)

    fun statusOf(fields: List<Wire.Field>): Int {
        val f = fields.firstOrNull { it.number == F_STATUS } ?: return STATUS_OK
        return Wire.varintOf(f) ?: STATUS_OK
    }

    fun hasField(fields: List<Wire.Field>, number: Int) = fields.any { it.number == number }

    /** Minimal hex encoding of a BigInteger (like Python f"{v:X}" + fromhex). */
    private fun minimalHexBytes(v: BigInteger): ByteArray {
        var hex = v.toString(16)
        if (hex.length % 2 == 1) hex = "0$hex"
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    fun publicKeyOf(cert: X509Certificate): RSAPublicKey =
        cert.publicKey as RSAPublicKey

    /**
     * The pairing secret: sha256(client_mod || client_exp || server_mod ||
     * server_exp || pin[2:]) — port of pairing_secret() / server_pairing_secret().
     */
    fun pairingSecret(
        clientCert: Certificate,
        serverCert: Certificate,
        pin: String,
    ): ByteArray {
        val clientPub = (clientCert as X509Certificate).publicKey as RSAPublicKey
        val serverPub = (serverCert as X509Certificate).publicKey as RSAPublicKey
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(minimalHexBytes(clientPub.modulus))
        digest.update(minimalHexBytes(BigInteger("0" + clientPub.publicExponent.toString(16))))
        digest.update(minimalHexBytes(serverPub.modulus))
        digest.update(minimalHexBytes(BigInteger("0" + serverPub.publicExponent.toString(16))))
        digest.update(hexToBytes(pin.substring(2)))
        return digest.digest()
    }

    /** Throws when the PIN's check digits do not match the computed hash. */
    fun validatePinFormat(pin: String, clientCert: Certificate, serverCert: Certificate) {
        if (pin.length != 6) throw IllegalArgumentException("PIN must be exactly 6 hex digits")
        Integer.parseInt(pin, 16) // throws on non-hex
        val secret = pairingSecret(clientCert, serverCert, pin)
        val check = pin.substring(0, 2).toInt(16)
        if ((secret[0].toInt() and 0xFF) != check) {
            throw IllegalArgumentException("pairing PIN does not match the expected hash")
        }
    }

    fun hexToBytes(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }
}
