package quality.xml

import java.nio.file.Files
import org.xml.sax.SAXParseException

/** Isolated direct-call witness; does not claim a deployed Spring endpoint. */
fun main() {
    val marker = Files.createTempFile("mehscan-xml-policy-", ".txt")
    try {
        Files.writeString(marker, "fixture-only-external-entity")
        val xml = """<!DOCTYPE root [<!ENTITY probe SYSTEM "${marker.toUri()}">]><root>&probe;</root>"""
        val routes = XmlRoutes()
        check(routes.rawXml(xml) == "fixture-only-external-entity")
        check(routes.wrongFactory(xml) == "fixture-only-external-entity")
        try {
            routes.safeXml(xml)
            error("DOCTYPE must be rejected")
        } catch (_: SAXParseException) { }
        check(routes.rawXml("<root>fixed</root>") == "fixed")
        check(routes.safeXml("<root>fixed</root>") == "fixed")
        check(routes.wrongFactory("<root>fixed</root>") == "fixed")
        println("XML policy runtime: 6 checks passed")
    } finally {
        Files.deleteIfExists(marker)
    }
}
