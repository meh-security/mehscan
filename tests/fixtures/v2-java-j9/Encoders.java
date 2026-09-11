import org.apache.commons.text.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.encoder.Encode;
import org.springframework.web.util.HtmlUtils;

class Encoders {
    void encode(String value) {
        Encode.forHtml(value);
        Encode.forHtmlAttribute(value);
        Encode.forJavaScript(value);
        Encode.forUriComponent(value);
        Encode.forCssString(value);
        HtmlUtils.htmlEscape(value);
        StringEscapeUtils.escapeHtml4(value);
        Jsoup.clean(value, Safelist.basic());
    }
}
