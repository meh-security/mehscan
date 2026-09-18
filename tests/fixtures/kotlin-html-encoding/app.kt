import org.owasp.encoder.Encode as Html
import io.ktor.server.application.ApplicationCall

import io.ktor.server.response.respondText
import io.ktor.http.ContentType

suspend fun encodedHtml(call: ApplicationCall) {
    // Caller query value is emitted only as HTML text content.
    val name = call.request.queryParameters["name"]!!
    val encoded = Html.forHtmlContent(name)
    call.respondText("<p>$encoded</p>", ContentType.Text.Html)
}
suspend fun discardedEncoding(call: ApplicationCall) {
    // Caller query value is emitted raw; the encoding return value is discarded.
    val name = call.request.queryParameters["name"]!!
    Html.forHtml(name)
    call.respondText("<p>$name</p>", ContentType.Text.Html)
}
suspend fun wrongValue(call: ApplicationCall) {
    // The encoded fixed string is independent of the raw caller query value.
    val name = call.request.queryParameters["name"]!!
    val encoded = Html.forHtml("fixed")
    call.respondText("<p>$encoded $name</p>", ContentType.Text.Html)
}
suspend fun wrongContext(call: ApplicationCall) {
    // HTML content encoding leaves apostrophes unchanged; this is JavaScript code in a script element.
    val name = call.request.queryParameters["name"]!!
    val encoded = Html.forHtmlContent(name)
    call.respondText("<script>const name = '$encoded';</script>", ContentType.Text.Html)
}
class Encode { fun forHtml(value: String) = value }
fun foreign(encoder: Encode) = encoder.forHtml("fixed")
