package quality.tlstrust

import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

fun trustAll(connection: HttpsURLConnection): String {
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun providerDefaults(connection: HttpsURLConnection): String {
    val context = SSLContext.getInstance("TLS")
    context.init(null, null, null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun providerValidated(connection: HttpsURLConnection, store: KeyStore): String {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(store)
    val context = SSLContext.getInstance("TLS")
    context.init(null, factory.trustManagers, null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun wrongContext(connection: HttpsURLConnection): String {
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val unused = SSLContext.getInstance("TLS")
    unused.init(null, arrayOf(permissive), null)
    val consumed = SSLContext.getInstance("TLS")
    consumed.init(null, null, null)
    connection.sslSocketFactory = consumed.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun resetContext(connection: HttpsURLConnection): String {
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive), null)
    context.init(null, null, null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun firstPermissive(connection: HttpsURLConnection, store: KeyStore): String {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(store)
    val validating = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(permissive, validating), null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun firstValidating(connection: HttpsURLConnection, store: KeyStore): String {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(store)
    val validating = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    val permissive = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(validating, permissive), null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

fun swallowedValidation(connection: HttpsURLConnection, store: KeyStore): String {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(store)
    val validating = factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    val callback = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = validating.checkClientTrusted(chain, authType)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            try { validating.checkServerTrusted(chain, authType) } catch (ignored: CertificateException) {}
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = validating.acceptedIssuers
    }
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf(callback), null)
    connection.sslSocketFactory = context.socketFactory
    return connection.inputStream.bufferedReader().use { it.readText() }
}

class Other { fun init(keys: Any?, trust: Any?, random: Any?) {} }
fun lookalike(other: Other) = other.init(null, null, null)
