package quality.xml

import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class XmlRoutes {
    @GetMapping("/xml/raw")
    fun rawXml(@RequestParam xml: String): String {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
        return factory.newDocumentBuilder().parse(InputSource(StringReader(xml))).documentElement.textContent
    }

    @GetMapping("/xml/safe")
    fun safeXml(@RequestParam xml: String): String {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        return factory.newDocumentBuilder().parse(InputSource(StringReader(xml))).documentElement.textContent
    }

    @GetMapping("/xml/wrong-factory")
    fun wrongFactory(@RequestParam xml: String): String {
        val guarded = DocumentBuilderFactory.newInstance()
        guarded.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val exposed = DocumentBuilderFactory.newInstance()
        exposed.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
        return exposed.newDocumentBuilder().parse(InputSource(StringReader(xml))).documentElement.textContent
    }
}
