package quality.tls

import javax.net.ssl.HttpsURLConnection

fun rawTls(connection: HttpsURLConnection): String {
    connection.setHostnameVerifier { _, _ -> true }
    return connection.getInputStream().bufferedReader().use { it.readText() }
}

fun safeTls(connection: HttpsURLConnection): String {
    connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier())
    return connection.getInputStream().bufferedReader().use { it.readText() }
}

fun wrongConnection(guarded: HttpsURLConnection, exposed: HttpsURLConnection): String {
    guarded.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier())
    exposed.setHostnameVerifier { _, _ -> true }
    return exposed.getInputStream().bufferedReader().use { it.readText() }
}
