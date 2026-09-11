import org.springframework.web.client.RestTemplate;

class NetworkScope {
    private final RestTemplateLookalike client = new RestTemplateLookalike();

    Object review(String endpoint, RestTemplate importedClient) {
        {
            RestTemplate client = importedClient;
        }
        return client.getForObject(endpoint, Object.class);
    }

    static class RestTemplateLookalike {
        Object getForObject(String endpoint, Class<?> type) { return endpoint; }
    }
}

class OtherNetworkScope {
    RestTemplate client;
}
