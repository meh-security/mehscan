package quality.ktorbuilders

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.request.request
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.server.application.ApplicationCall

suspend fun rawFactory(call: ApplicationCall): String {
    val destination = call.request.queryParameters["url"]!!
    val client = HttpClient(CIO)
    try {
        return client.get(destination).bodyAsText()
    } finally {
        client.close()
    }
}

suspend fun rawBuilder(call: ApplicationCall): String {
    val destination = call.request.queryParameters["url"]!!
    val client = HttpClient(CIO) { expectSuccess = true }
    try {
        return client.get { url(destination) }.bodyAsText()
    } finally {
        client.close()
    }
}

suspend fun replacedBuilder(call: ApplicationCall, replacement: String): String {
    val initial = call.request.queryParameters["url"]!!
    val client = HttpClient(CIO)
    try {
        return client.get(initial) { url(replacement) }.bodyAsText()
    } finally {
        client.close()
    }
}

suspend fun fixedBuilder(call: ApplicationCall): String {
    val ignored = call.request.queryParameters["url"]
    val client = HttpClient(CIO)
    try {
        return client.request { url("http://127.0.0.1:9/fixed") }.bodyAsText()
    } finally {
        client.close()
    }
}
