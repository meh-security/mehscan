package quality.webflux

import java.net.URL
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

class FunctionalRoutes(private val fixed: String) {
    fun rawQuery(request: ServerRequest): Mono<ServerResponse> = Mono.defer {
        val target = request.queryParam("url").orElse(fixed)
        val body = URL(target).openStream().bufferedReader().use { it.readText() }
        ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(body)
    }

    fun approvedQuery(request: ServerRequest): Mono<ServerResponse> = Mono.defer {
        val choice = request.queryParam("choice").orElse("fixture")
        require(choice == "fixture")
        val body = URL(fixed).openStream().bufferedReader().use { it.readText() }
        ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(body)
    }

    fun rawBody(request: ServerRequest): Mono<ServerResponse> =
        request.bodyToMono(String::class.java).flatMap { target ->
            val body = URL(target).openStream().bufferedReader().use { it.readText() }
            ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(body)
        }

    fun ignoredBody(request: ServerRequest): Mono<ServerResponse> =
        request.bodyToMono(String::class.java).flatMap { ignored ->
            val body = URL(fixed).openStream().bufferedReader().use { it.readText() }
            ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(body)
        }

    fun rawPath(request: ServerRequest): Mono<ServerResponse> = Mono.defer {
        val port = request.pathVariable("port")
        val body = URL("http://127.0.0.1:$port/selected").openStream().bufferedReader().use { it.readText() }
        ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(body)
    }
}

class Other { fun queryParam(key: String): String = key; fun pathVariable(key: String): String = key }
fun lookalike(other: Other): String = other.queryParam("fixed") + other.pathVariable("fixed")
