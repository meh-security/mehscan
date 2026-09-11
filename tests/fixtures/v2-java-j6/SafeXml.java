import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.validation.SchemaFactory;

class SafeXml {
    Object dom(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(input);
    }

    void sax(InputStream input) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        SAXParser parser = factory.newSAXParser();
        parser.parse(input, new Handler());
    }

    Object stax(InputStream input) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return factory.createXMLStreamReader(input);
    }

    void transform(Source input) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = factory.newTransformer();
        transformer.transform(input, new StreamResult());
    }

    Object schema(Source input) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance("urn:test");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return factory.newSchema(input);
    }

    static class Handler {}
}
