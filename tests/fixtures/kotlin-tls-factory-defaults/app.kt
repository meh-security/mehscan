package quality.tlsfactorydefaults

import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

fun globalFactory(port: Int): String {
    val saved = HttpsURLConnection.getDefaultSSLSocketFactory()
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    try {
        HttpsURLConnection.setDefaultSSLSocketFactory(context.socketFactory)
        val connection = URL("https://localhost:$port/").openConnection() as HttpsURLConnection
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultSSLSocketFactory(saved) }
}

fun existingFactory(port: Int): String {
    val saved = HttpsURLConnection.getDefaultSSLSocketFactory()
    val connection = URL("https://localhost:$port/").openConnection() as HttpsURLConnection
    connection.sslSocketFactory = saved
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    try {
        HttpsURLConnection.setDefaultSSLSocketFactory(context.socketFactory)
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultSSLSocketFactory(saved) }
}

fun defaultContextConsumed(port: Int): String {
    val saved = SSLContext.getDefault()
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    try {
        SSLContext.setDefault(context)
        val connection = URL("https://localhost:$port/").openConnection() as HttpsURLConnection
        connection.sslSocketFactory = SSLContext.getDefault().socketFactory
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { SSLContext.setDefault(saved) }
}

fun capturedFactory(port: Int): String {
    val saved = SSLContext.getDefault()
    val captured = HttpsURLConnection.getDefaultSSLSocketFactory()
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    try {
        SSLContext.setDefault(context)
        val connection = URL("https://localhost:$port/").openConnection() as HttpsURLConnection
        connection.sslSocketFactory = captured
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { SSLContext.setDefault(saved) }
}
