import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class WebSurfaces {
    void review(String html, String location, HttpServletResponse response,
                HttpServletRequest request) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(html);
        response.sendRedirect(location);
        request.getPart("upload");
    }
}
