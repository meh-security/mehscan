import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

class HtmlFlow {
    void direct(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(request.getParameter("direct"));
    }

    void propagated(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String content = request.getParameter("propagated");
        String alias = content;
        response.getWriter().write(alias);
    }

    void encoded(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String content = Encode.forHtml(request.getParameter("encoded"));
        response.getWriter().write(content);
    }
}
