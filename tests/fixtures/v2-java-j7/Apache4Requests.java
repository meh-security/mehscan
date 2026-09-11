import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;

class Apache4Requests {
    Object request(String endpoint) {
        return new HttpGet(endpoint);
    }

    Object dispatch(CloseableHttpClient client, HttpGet request) throws Exception {
        return client.execute(request);
    }
}
