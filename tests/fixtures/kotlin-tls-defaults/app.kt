package quality.tlsdefaults

import java.net.URL
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

fun globalHostname(port: Int, matching: Boolean): String {
    val saved = HttpsURLConnection.getDefaultHostnameVerifier()
    try {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        val host = if (matching) "localhost" else "127.0.0.1"
        val connection = URL("https://$host:$port/").openConnection() as HttpsURLConnection
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultHostnameVerifier(saved) }
}

fun restoredBeforeOpen(port: Int, matching: Boolean): String {
    val saved = HttpsURLConnection.getDefaultHostnameVerifier()
    try {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> false }
        val host = if (matching) "localhost" else "127.0.0.1"
        val connection = URL("https://$host:$port/").openConnection() as HttpsURLConnection
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultHostnameVerifier(saved) }
}

fun existingConnection(port: Int, matching: Boolean): String {
    val saved = HttpsURLConnection.getDefaultHostnameVerifier()
    val host = if (matching) "localhost" else "127.0.0.1"
    val connection = URL("https://$host:$port/").openConnection() as HttpsURLConnection
    connection.hostnameVerifier = HostnameVerifier { _, _ -> false }
    try {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultHostnameVerifier(saved) }
}

fun instanceOverride(port: Int, matching: Boolean): String {
    val saved = HttpsURLConnection.getDefaultHostnameVerifier()
    try {
        HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
        val host = if (matching) "localhost" else "127.0.0.1"
        val connection = URL("https://$host:$port/").openConnection() as HttpsURLConnection
        connection.hostnameVerifier = HostnameVerifier { _, _ -> false }
        return connection.inputStream.bufferedReader().use { it.readText() }
    } finally { HttpsURLConnection.setDefaultHostnameVerifier(saved) }
}

class Other { fun setDefaultHostnameVerifier(policy: HostnameVerifier) {} }
fun lookalike(other: Other) = other.setDefaultHostnameVerifier { _, _ -> true }
