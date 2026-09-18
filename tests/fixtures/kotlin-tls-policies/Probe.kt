package quality.tls

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.net.InetSocketAddress
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.TrustManagerFactory

fun main(args: Array<String>) {
    val password = "fixture-only".toCharArray()
    val keys = KeyStore.getInstance("PKCS12")
    Files.newInputStream(Path.of(args.single())).use { keys.load(it, password) }
    val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    managers.init(keys, password)
    val serverContext = SSLContext.getInstance("TLS")
    serverContext.init(managers.keyManagers, null, null)
    // Trust only the generated fixture certificate, preserving chain validation.
    val trust = KeyStore.getInstance("PKCS12")
    trust.load(null, null)
    trust.setCertificateEntry("fixture", keys.getCertificate("fixture"))
    val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagers.init(trust)
    val clientContext = SSLContext.getInstance("TLS")
    clientContext.init(null, trustManagers.trustManagers, null)
    val server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    server.httpsConfigurator = HttpsConfigurator(serverContext)
    server.createContext("/") { exchange ->
        val bytes = "fixture-only-tls".toByteArray()
        exchange.sendResponseHeaders(200, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }
    server.start()
    val opened = mutableListOf<HttpsURLConnection>()
    fun connection(host: String): HttpsURLConnection {
        val c = URL("https://$host:${server.address.port}/").openConnection() as HttpsURLConnection
        c.sslSocketFactory = clientContext.socketFactory
        c.connectTimeout = 5000
        c.readTimeout = 5000
        opened.add(c)
        return c
    }
    try {
        check(rawTls(connection("127.0.0.1")) == "fixture-only-tls")
        check(wrongConnection(connection("localhost"), connection("127.0.0.1")) == "fixture-only-tls")
        try {
            safeTls(connection("127.0.0.1"))
            error("Hostname mismatch must be rejected")
        } catch (_: SSLHandshakeException) { }
        check(safeTls(connection("localhost")) == "fixture-only-tls")
        println("TLS policy runtime: 4 checks passed")
    } finally {
        opened.forEach { it.disconnect() }
        server.stop(0)
    }
}
