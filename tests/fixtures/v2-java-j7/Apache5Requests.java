import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.HttpClient;

class Apache5Requests {
    Object request(String endpoint) {
        return new HttpPost(endpoint);
    }

    Object dispatch(HttpClient client, HttpPost request) throws Exception {
        return client.execute(request);
    }
}
