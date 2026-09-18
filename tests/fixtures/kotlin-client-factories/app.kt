package quality.factories

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FactoryRoutes {
    @GetMapping("/client/jdk/raw")
    fun rawJdk(@RequestParam url: String): String {
        val client = HttpClient.newHttpClient()
        val request = HttpRequest.newBuilder(URI.create(url)).GET().build()
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body()
    }

    @GetMapping("/client/jdk/builder")
    fun rawJdkBuilder(@RequestParam url: String): String {
        val builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        val client = builder.followRedirects(HttpClient.Redirect.NEVER).build()
        val request = HttpRequest.newBuilder(URI.create(url)).GET().build()
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).join().body()
    }

    @GetMapping("/client/okhttp/raw")
    fun rawOkhttp(@RequestParam url: String): String {
        val client = OkHttpClient()
        val request = Request.Builder().url(url).build()
        return client.newCall(request).execute().use { it.body!!.string() }
    }

    @GetMapping("/client/okhttp/builder")
    fun rawOkhttpBuilder(@RequestParam url: String): String {
        val client = OkHttpClient.Builder().build()
        val request = Request.Builder().url(url).build()
        return client.newCall(request).execute().use { it.body!!.string() }
    }

    @GetMapping("/client/jdk/fixed")
    fun fixedJdk(@RequestParam ignored: String): String {
        val client = HttpClient.newHttpClient()
        val request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:9/")).GET().build()
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body()
    }

    @GetMapping("/client/okhttp/lazy")
    fun lazyOkhttp(@RequestParam url: String): okhttp3.Call {
        val client = OkHttpClient()
        val request = Request.Builder().url(url).build()
        return client.newCall(request)
    }

    @GetMapping("/process/mutated")
    fun changedCommand(@RequestParam executable: String): String {
        val builder = ProcessBuilder("fixed-unused-command")
        builder.command(executable)
        return builder.start().inputStream.bufferedReader().readText()
    }

    @GetMapping("/process/chained")
    fun chainedCommand(@RequestParam executable: String): String {
        return ProcessBuilder("fixed-unused-command").command(executable).redirectErrorStream(true)
            .start().inputStream.bufferedReader().readText()
    }

    @GetMapping("/process/fixed")
    fun fixedCommand(@RequestParam ignored: String): String {
        return ProcessBuilder("fixed-unused-command").command("whoami").start()
            .inputStream.bufferedReader().readText()
    }
}

class Other { fun newHttpClient() = this; fun build() = this; fun send(a: String, b: String) = a + b }
fun lookalike(factory: Other) = factory.newHttpClient().build().send("fixed", "fixed")
