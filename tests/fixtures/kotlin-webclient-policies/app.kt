package quality.webclientpolicies

import java.net.URI
import org.springframework.http.client.reactive.JdkClientHttpConnector
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.DefaultUriBuilderFactory
import org.springframework.web.util.UriBuilder
import org.springframework.web.util.UriBuilderFactory

@RestController
class PolicyRoutes(private val fixed: String) {
    @GetMapping("/default")
    fun defaultBeforeUri(@RequestParam target: String): String {
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .defaultRequest { spec -> (spec as WebClient.RequestHeadersUriSpec<*>).uri(fixed) }
            .build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/filter")
    fun pinnedFilter(@RequestParam target: String): String {
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .filter { request, next ->
                next.exchange(ClientRequest.from(request).url(URI.create(fixed)).build())
            }.build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/wrongfilter")
    fun wrongFilterRequest(@RequestParam target: String): String {
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .filter { request, next ->
                val ignored = ClientRequest.from(request).url(URI.create(fixed)).build()
                next.exchange(request)
            }.build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/laterfilter")
    fun rewriteAfterApproval(@RequestParam target: String): String {
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .filter { request, next ->
                require(request.url().toString() == fixed)
                next.exchange(request)
            }.filter { request, next ->
                next.exchange(ClientRequest.from(request).url(URI.create(target)).build())
            }.build()
        return local.get().uri(fixed).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/removed")
    fun removedFilter(@RequestParam target: String): String {
        val pin = ExchangeFilterFunction { request, next ->
            next.exchange(ClientRequest.from(request).url(URI.create(fixed)).build())
        }
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .filter(pin).filters { filters -> filters.clear() }.build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/base")
    fun absoluteFactory(@RequestParam target: String): String {
        val factory = DefaultUriBuilderFactory(fixed)
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .uriBuilderFactory(factory).build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/pinstring")
    fun pinnedStringFactory(@RequestParam target: String): String {
        val delegate = DefaultUriBuilderFactory(fixed)
        val factory = object : UriBuilderFactory by delegate {
            override fun uriString(uriTemplate: String): UriBuilder = delegate.uriString(fixed)
        }
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .uriBuilderFactory(factory).build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/wrongexpand")
    fun wrongExpandOverride(@RequestParam target: String): String {
        val delegate = DefaultUriBuilderFactory(fixed)
        val factory = object : UriBuilderFactory by delegate {
            override fun expand(uriTemplate: String, vararg uriVariables: Any?): URI = URI.create(fixed)
            override fun expand(uriTemplate: String, uriVariables: Map<String, *>): URI = URI.create(fixed)
        }
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .uriBuilderFactory(factory).build()
        return local.get().uri(target).retrieve().bodyToMono(String::class.java).block()!!
    }

    @GetMapping("/absolutebypass")
    fun absoluteUriBypass(@RequestParam target: String): String {
        val delegate = DefaultUriBuilderFactory(fixed)
        val factory = object : UriBuilderFactory by delegate {
            override fun uriString(uriTemplate: String): UriBuilder = delegate.uriString(fixed)
        }
        val local = WebClient.builder().clientConnector(JdkClientHttpConnector())
            .uriBuilderFactory(factory).build()
        return local.get().uri(URI.create(target)).retrieve().bodyToMono(String::class.java).block()!!
    }
}
