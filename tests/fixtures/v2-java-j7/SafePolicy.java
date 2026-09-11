import java.net.InetAddress;
import java.net.URI;
import java.util.Set;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.impl.client.HttpClients;

class SafePolicy {
    boolean scheme(URI endpoint) {
        return endpoint.getScheme().equals("https");
    }

    boolean host(URI endpoint, Set<String> allowed) {
        return allowed.contains(endpoint.getHost());
    }

    boolean privateAddress(InetAddress address) {
        return address.isLoopbackAddress() || address.isSiteLocalAddress();
    }

    Object redirects() {
        return HttpClients.custom().disableRedirectHandling().build();
    }

    Object verifier() {
        return new DefaultHostnameVerifier();
    }
}
