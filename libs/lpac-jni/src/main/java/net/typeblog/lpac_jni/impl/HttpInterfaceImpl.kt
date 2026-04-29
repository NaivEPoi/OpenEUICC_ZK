package net.typeblog.lpac_jni.impl

import android.util.Log
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import net.typeblog.lpac_jni.HttpInterface
import java.net.URL
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory

class HttpInterfaceImpl(
    private val verboseLoggingFlow: Flow<Boolean>,
    private val ignoreTLSCertificateFlow: Flow<Boolean>
) : HttpInterface {
    companion object {
        private const val TAG = "HttpInterfaceImpl"
    }

    private lateinit var trustManagers: Array<TrustManager>

    private fun rewriteTestHostToLoopback(originalUrl: String): String {
        return try {
            val u = URL(originalUrl)
            if (!u.host.endsWith(".example.com")) {
                originalUrl
            } else {
                val portPart = if (u.port != -1) ":${u.port}" else ""
                val pathAndQuery = u.file.ifEmpty { "" }
                "${u.protocol}://127.0.0.1$portPart$pathAndQuery"
            }
        } catch (_: Exception) {
            originalUrl
        }
    }

    override fun transmit(
        url: String,
        tx: ByteArray,
        headers: Array<String>
    ): HttpInterface.HttpResponse {
        // When "Ignore TLS certificate" is on (developer/test mode), redirect any
        // *.example.com URL to 127.0.0.1. Test SM-DP+/MNO/PCA setups commonly use
        // those placeholder hostnames; combined with `adb reverse tcp:<port> tcp:<port>`
        // the request is forwarded to the laptop where the test server is running.
        val effectiveUrl = if (runBlocking { ignoreTLSCertificateFlow.first() }) {
            rewriteTestHostToLoopback(url)
        } else url
        Log.d(TAG, "transmit(url = $effectiveUrl${if (effectiveUrl != url) " <- rewritten from $url" else ""})")

        if (runBlocking { verboseLoggingFlow.first() }) {
            Log.d(TAG, "HTTP tx = ${tx.decodeToString(throwOnInvalidSequence = false)}")
        }

        val parsedUrl = URL(effectiveUrl)
        if (parsedUrl.protocol != "https") {
            throw IllegalArgumentException("SM-DP+ servers must use the HTTPS protocol")
        }

        try {
            val conn = parsedUrl.openConnection() as HttpsURLConnection
            conn.connectTimeout = 2000

            if (url.contains("handleNotification")) {
                conn.connectTimeout = 1000
                conn.readTimeout = 1000
            }

            conn.sslSocketFactory = getSocketFactory()
            // When the user has enabled "Ignore TLS certificate", also bypass hostname
            // verification — otherwise URLs whose host (e.g. an IP address typed by the
            // user) doesn't match the cert's SAN will still throw SSLPeerUnverifiedException
            // even though the cert chain itself is being skipped.
            if (runBlocking { ignoreTLSCertificateFlow.first() }) {
                conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
            conn.requestMethod = "POST"
            conn.doInput = true
            conn.doOutput = true

            for (h in headers) {
                val s = h.split(":", limit = 2)
                conn.setRequestProperty(s[0], s[1])
            }

            conn.outputStream.write(tx)
            conn.outputStream.flush()
            conn.outputStream.close()

            Log.d(TAG, "transmit responseCode = ${conn.responseCode}")

            // For non-2xx, HttpURLConnection routes the body to errorStream.
            // Capture it so we can see backend rejection messages instead of swallowing them.
            val rcode = conn.responseCode
            val stream = if (rcode in 200..299) conn.inputStream else conn.errorStream
            val bytes = stream?.readBytes() ?: ByteArray(0)
            if (rcode !in 200..299) {
                Log.w(
                    TAG,
                    "HTTP $rcode body = ${bytes.decodeToString(throwOnInvalidSequence = false)}"
                )
            } else if (runBlocking { verboseLoggingFlow.first() }) {
                Log.d(
                    TAG,
                    "HTTP response body = ${bytes.decodeToString(throwOnInvalidSequence = false)}"
                )
            }

            return HttpInterface.HttpResponse(rcode, bytes)
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
    }

    private fun getSocketFactory(): SSLSocketFactory {
        val trustManagers =
            if (runBlocking { ignoreTLSCertificateFlow.first() }) {
                arrayOf(AllowAllTrustManager())
            } else {
                this.trustManagers
            }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustManagers, SecureRandom())
        return sslContext.socketFactory
    }

    override fun usePublicKeyIds(pkids: Array<String>) {
        val trustManagerFactory = TrustManagerFactory.getInstance("PKIX").apply {
            init(keyIdToKeystore(pkids))
        }
        trustManagers = trustManagerFactory.trustManagers
    }
}