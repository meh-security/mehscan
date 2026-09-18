package quality.scopes

import io.ktor.server.application.ApplicationCall
import kotlin.let
import kotlin.also
import kotlin.let as bind

fun rawLet(call: ApplicationCall) {
    val command = call.request.queryParameters["command"] ?: "whoami"
    command.let { selected -> Runtime.getRuntime().exec(selected) }
}

fun rawImplicit(call: ApplicationCall) {
    val command = call.request.queryParameters["command"] ?: "whoami"
    command.also { Runtime.getRuntime().exec(it) }
}

fun rawAlias(call: ApplicationCall) {
    val command = call.request.queryParameters["command"] ?: "whoami"
    command.bind { selected -> Runtime.getRuntime().exec(selected) }
}

fun fixedLet(call: ApplicationCall) {
    val ignored = call.request.queryParameters["command"]
    ignored.let { "whoami" }.let { fixed -> Runtime.getRuntime().exec(fixed) }
}

class Other {
    fun let(block: (String) -> Unit) { block("whoami") }
}
fun lookalike(other: Other) { other.let { Runtime.getRuntime().exec(it) } }
