package quality.factories

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress

fun main() {
    val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    server.createContext("/") { exchange ->
        val bytes = "fixture-only-http".toByteArray()
        exchange.sendResponseHeaders(200, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }
    server.start()
    try {
        val routes = FactoryRoutes()
        val target = "http://127.0.0.1:${server.address.port}/"
        check(routes.rawJdk(target) == "fixture-only-http")
        check(routes.rawJdkBuilder(target) == "fixture-only-http")
        check(routes.rawOkhttp(target) == "fixture-only-http")
        check(routes.rawOkhttpBuilder(target) == "fixture-only-http")
        check(routes.changedCommand("whoami").isNotBlank())
        check(routes.chainedCommand("whoami").isNotBlank())
        check(routes.fixedCommand("ignored-unused").isNotBlank())
        check(!routes.lazyOkhttp(target).isExecuted())
        println("Client/process factory runtime: 8 checks passed")
    } finally {
        server.stop(0)
    }
}
