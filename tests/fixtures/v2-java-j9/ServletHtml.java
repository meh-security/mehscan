import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class ServletHtml {
    @GetMapping("/unsafe")
    void unsafe(@RequestParam String value, HttpServletResponse response) throws Exception {
        response.setContentType("text/html; charset=UTF-8");
        response.getWriter().write(value);
    }

    @GetMapping("/safe")
    void safe(@RequestParam String value, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        writer.print(Encode.forHtmlContent(value));
    }
}
