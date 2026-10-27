package com.openremote.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Client certificate for the TLS remote channel, generated once and stored in
 * the Android KeyStore (the platform issues the self-signed X509 certificate
 * automatically). The pairing secret uses the certificate's public modulus
 * and exponent; the private key never leaves the keystore.
 *
 * Evidence: the Google Home app presents a client certificate during the TLS
 * handshake (REA ev_f2bc304a: SSLSocket from KeyManagers loaded by
 * defpackage.asqa).
 */
object ClientCert {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "openremote_client"
    private const val TLS_TYPE = "TLS"

    /** A trust manager that accepts the TV's self-signed certificate. */
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun ensureKeystore(context: Context): KeyStore {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(ALIAS)) {
            val now = System.currentTimeMillis()
            val spec = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(2048)
                .setCertificateSubject(javax.security.auth.x500.X500Principal("CN=OpenRemote"))
                .setCertificateNotBefore(java.util.Date(now - 86_400_000L))
                .setCertificateNotAfter(java.util.Date(now + 10L * 365 * 86_400_000L))
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE
            )
            generator.initialize(spec, SecureRandom())
            generator.generateKeyPair()
        }
        return ks
    }

    fun clientCertificate(context: Context): X509Certificate {
        val ks = ensureKeystore(context)
        return ks.getCertificate(ALIAS) as X509Certificate
    }

    fun sslContext(context: Context): SSLContext {
        val ks = ensureKeystore(context)
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, null)
        val ctx = SSLContext.getInstance(TLS_TYPE)
        ctx.init(kmf.keyManagers, arrayOf<TrustManager>(trustAll), null)
        return ctx
    }
}
