package quality.webclient

import java.net.URI
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono

@RestController
class ClientRoutes(private val client: WebClient, private val fixed: String) {
    @GetMapping("/query")
    fun rawString(@RequestParam target: String): String =
        client.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!

    @GetMapping("/uri")
    fun rawUri(@RequestParam target: String): String =
        client.get().uri(URI.create(target)).retrieve().bodyToMono(String::class.java).block()!!

    @GetMapping("/builder")
    fun rawBuilder(@RequestParam target: String): String =
        client.get().uri { _ -> URI.create(target) }
            .retrieve().bodyToMono(String::class.java).block()!!

    @GetMapping("/factory")
    fun rawFactory(@RequestParam target: String): String {
        val local = WebClient.create()
        return local.post().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/built")
    fun rawBuilt(@RequestParam target: String): String {
        val local = WebClient.builder()
            .clientConnector(org.springframework.http.client.reactive.JdkClientHttpConnector()).build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/nonnetwork")
    fun nonNetworkFactory(@RequestParam target: String): String {
        val local = WebClient.builder().exchangeFunction(clientExchange()).build()
        return local.post().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/encoded")
    fun pathVariable(@RequestParam value: String): String =
        client.get().uri("http://127.0.0.1/fixed/{value}", mapOf("value" to value))
            .retrieve().bodyToMono(String::class.java).block()!!

    @GetMapping("/lazy")
    fun lazyRequest(@RequestParam target: String): String {
        val unused = client.get().uri(target).retrieve().bodyToMono(String::class.java)
        return "fixed response"
    }

    @GetMapping("/replace")
    fun replaced(@RequestParam target: String): String {
        val spec = client.get()
        spec.uri(target)
        spec.uri(fixed)
        return spec.retrieve().bodyToMono(String::class.java).block()!!
    }
}

// An explicit non-network exchange echoes the planned URI; it never reads a resource.
fun clientExchange(): org.springframework.web.reactive.function.client.ExchangeFunction =
    org.springframework.web.reactive.function.client.ExchangeFunction { request ->
        Mono.just(org.springframework.web.reactive.function.client.ClientResponse
            .create(org.springframework.http.HttpStatus.OK).body(request.url().toString()).build())
    }

class Other { fun uri(value: String): String = value }
fun lookalike(other: Other): String = other.uri("fixed")
