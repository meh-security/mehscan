package quality.ktor

import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.response.respondBytes
import io.ktor.http.withCharset
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.routing.routing
import io.ktor.server.routing.get as routeGet

fun Application.dslCommands() {
    routing {
        routeGet("/command") {
            val command = call.request.queryParameters["command"] ?: "whoami"
            val result = Runtime.getRuntime().exec(command).inputStream.bufferedReader().readText()
            call.respondText(result)
        }
    }
}

suspend fun queryCommand(call: ApplicationCall) {
    val command = call.request.queryParameters["command"]!!
    Runtime.getRuntime().exec(command)
}
suspend fun pathCommand(call: ApplicationCall) {
    val command = call.parameters["command"]!!
    Runtime.getRuntime().exec(command)
}
suspend fun bodyCommand(call: ApplicationCall) {
    val command = call.receiveText()
    Runtime.getRuntime().exec(command)
}
suspend fun rawRedirect(call: ApplicationCall) {
    val destination = call.request.queryParameters["destination"]!!
    call.respondRedirect(permanent = false, url = destination)
}
suspend fun fixedRedirect(call: ApplicationCall) = call.respondRedirect("/home")
suspend fun rawHtml(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]!!
    call.respondText(contentType = ContentType.Text.Html, text = "<p>$name</p>")
}
suspend fun plainText(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]!!
    call.respondText(name, ContentType.Text.Plain)
}
suspend fun rawBytes(call: ApplicationCall) {
    val value = call.request.queryParameters["value"]!!
    try {
        val decoded = java.util.Base64.getUrlDecoder().decode(value)
        call.respondBytes(decoded, contentType = ContentType.Text.Html.withCharset(Charsets.UTF_8))
    } catch (_: IllegalArgumentException) {
        call.respondText("Invalid Base64", contentType = ContentType.Text.Html)
    }
}
suspend fun fixedHtml(call: ApplicationCall) = call.respondText("<p>Hello</p>", ContentType.Text.Html)
suspend fun rawClient(call: ApplicationCall, client: HttpClient) {
    val endpoint = call.request.queryParameters["endpoint"]!!
    client.get(urlString = endpoint)
}
suspend fun fixedClient(client: HttpClient) = client.get("https://example.com/fixed")

class OtherCall { val parameters = mapOf("command" to "fixed"); fun receiveText() = "fixed"; fun respondRedirect(url: String) = url }
fun lookalike(call: OtherCall) { call.receiveText(); call.respondRedirect("/fixed"); call.parameters["command"] }
