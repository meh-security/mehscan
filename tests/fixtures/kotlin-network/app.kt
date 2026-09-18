package quality.network

import java.net.URI
import java.net.URL as LegacyURL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class NetworkRoutes {
    @GetMapping("/network/raw")
    fun rawStream(@RequestParam url: String): String =
        URI.create(url).toURL().openStream().bufferedReader().use { it.readText() }

    @GetMapping("/network/constructor")
    fun constructorStream(@RequestParam url: String): String {
        val address = LegacyURL(url)
        val copy = address
        return copy.openStream().bufferedReader().use { it.readText() }
    }

    @GetMapping("/network/connection")
    fun rawConnection(@RequestParam url: String): String {
        val address = URI.create(url).toURL()
        val connection = address.openConnection()
        connection.connect()
        return connection.getInputStream().bufferedReader().use { it.readText() }
    }

    @GetMapping("/network/fixed")
    fun fixedStream(@RequestParam url: String): String =
        URI.create("http://127.0.0.1:8100/approved").toURL().openStream().bufferedReader().use { it.readText() }

    @GetMapping("/network/allowlisted")
    fun allowlistedStream(@RequestParam selector: String): String {
        val target: LegacyURL = when (selector) {
            "approved" -> URI.create("http://127.0.0.1:8100/approved").toURL()
            else -> throw IllegalArgumentException("Unsupported selector")
        }
        return target.openStream().bufferedReader().use { it.readText() }
    }

    @GetMapping("/network/construction-only")
    fun connectionOnly(@RequestParam url: String): String {
        val connection = URI.create(url).toURL().openConnection()
        return connection.javaClass.name
    }
}

class OtherURL {
    fun openStream(): String = "fixed custom result"
}
@RestController
class LookalikeRoutes(private val address: OtherURL) {
    @GetMapping("/network/lookalike")
    fun lookalike(@RequestParam url: String): String = address.openStream()
}

class NetworkFetcher {
    fun fetch(url: String): String = runBlocking {
        async(Dispatchers.IO) {
            URI.create(url).toURL().openStream().bufferedReader().use { it.readText() }
        }.await()
    }
}
@RestController
class CoroutineRoutes(private val service: NetworkFetcher) {
    @GetMapping("/network/coroutine")
    fun coroutineRaw(@RequestParam url: String): String = service.fetch(url)
}
