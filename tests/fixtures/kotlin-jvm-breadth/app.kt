package quality.breadth

import java.io.File
import java.io.ObjectInputStream
import java.net.URLConnection
import javax.xml.parsers.DocumentBuilderFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HostnameVerifier
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class Routes {
    @GetMapping("/process/raw")
    fun rawProcess(@RequestParam executable: String) = ProcessBuilder(executable).start()

    @GetMapping("/process/fixed")
    fun fixedProcess(@RequestParam ignored: String) = ProcessBuilder("whoami").start()

    @GetMapping("/file/raw")
    fun rawRead(@RequestParam name: String) = File(name).readText()

    @GetMapping("/file/fixed")
    fun fixedRead(@RequestParam ignored: String) = File("fixture/public/readme.txt").readText()

    @GetMapping("/file/content")
    fun fixedWrite(@RequestParam content: String) = File("fixture/public/write.txt").writeText(content)
}

fun objectRead(input: ObjectInputStream) = input.readObject()
fun xmlRead(factory: DocumentBuilderFactory, input: java.io.InputStream) = factory.newDocumentBuilder().parse(input)
fun xmlConfiguration(factory: DocumentBuilderFactory) = factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
fun tlsConfiguration(connection: HttpsURLConnection, verifier: HostnameVerifier) = connection.setHostnameVerifier(verifier)
fun connectionRead(connection: URLConnection) = connection.getInputStream()
fun redirect(response: jakarta.servlet.http.HttpServletResponse, location: String) = response.sendRedirect(location)
fun jsonRead(mapper: tools.jackson.databind.ObjectMapper, payload: String) = mapper.readValue(payload, String::class.java)
fun httpRequest(client: java.net.http.HttpClient, request: java.net.http.HttpRequest) = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
fun okhttpRequest(client: okhttp3.OkHttpClient, request: okhttp3.Request) = client.newCall(request).execute()

class Other { fun readObject() = "fixed"; fun readText() = "fixed"; fun start() = "fixed" }
fun lookalikes(other: Other) { other.readObject(); other.readText(); other.start() }
