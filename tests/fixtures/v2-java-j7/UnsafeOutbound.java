import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.RequestEntity;

class UnsafeOutbound {
    Object rest(RestTemplate client, String endpoint) {
        return client.getForObject(endpoint, Object.class);
    }

    Object requestEntity(RestTemplate client, RequestEntity<Object> request) {
        return client.exchange(request, Object.class);
    }

    Object reactive(WebClient client, String endpoint) {
        return client.get().uri(endpoint).retrieve();
    }

    Object jdk(String endpoint) {
        return HttpRequest.newBuilder(URI.create(endpoint));
    }

    Object dispatch(HttpClient client, HttpRequest request, Object handler) throws Exception {
        return client.send(request, handler);
    }

    Object url(String endpoint) throws Exception {
        return new URL(endpoint).openConnection();
    }

    Object uri(URI endpoint) throws Exception {
        return endpoint.toURL().openConnection();
    }
}
