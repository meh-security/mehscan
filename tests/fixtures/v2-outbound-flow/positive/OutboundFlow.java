import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;

class OutboundFlow {
    Object direct(HttpServletRequest request, HttpClient client) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(request.getParameter("direct"))).build(), HttpResponse.BodyHandlers.ofString());
    }

    Object propagated(HttpServletRequest request, HttpClient client) throws Exception {
        String requested = request.getParameter("propagated");
        String alias = requested;
        return client.send(HttpRequest.newBuilder(URI.create(alias)).build(), HttpResponse.BodyHandlers.ofString());
    }

    Object parsed(HttpServletRequest request, HttpClient client) throws Exception {
        URI parsed = URI.create(request.getParameter("parsed"));
        return client.send(HttpRequest.newBuilder(parsed).build(), HttpResponse.BodyHandlers.ofString());
    }

    boolean validScheme(URI parsed) {
        return parsed.getScheme().equals("https");
    }
}
