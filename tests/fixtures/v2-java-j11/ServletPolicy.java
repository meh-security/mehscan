import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class ServletPolicy {
    void unsafe(HttpServletRequest request, HttpServletResponse response, Cookie cookie) {
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        response.setHeader("X-User", request.getParameter("name"));
        request.getHeader("x-forwarded-host");
        request.getHeader("x-forwarded-proto");
    }

    void safe(Cookie cookie) {
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setAttribute("SameSite", "Strict");
    }
}
