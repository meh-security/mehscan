import java.net.URI;
import java.net.http.HttpRequest;

class OutboundFlow {
    Object direct(HttpServletRequest request) {
        return HttpRequest.newBuilder(request.getParameter("direct"));
    }

    Object propagated(HttpServletRequest request) {
        String requested = request.getParameter("propagated");
        String alias = requested;
        return HttpRequest.newBuilder(alias);
    }

    Object parsed(HttpServletRequest request) {
        URI parsed = URI.create(request.getParameter("parsed"));
        return HttpRequest.newBuilder(parsed);
    }

    boolean validScheme(URI parsed) {
        return parsed.getScheme().equals("https");
    }
}
