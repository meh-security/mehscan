class Lookalikes {
    Object run(String endpoint) {
        RestTemplate rest = new RestTemplate();
        rest.getForObject(endpoint, Object.class);
        HttpRequest.newBuilder(endpoint);
        new HttpGet(endpoint);
        TrustAllStrategy trust = new TrustAllStrategy();
        return trust;
    }

    static class RestTemplate { Object getForObject(String value, Class<?> type) { return value; } }
    static class HttpRequest { static Object newBuilder(String value) { return value; } }
    static class HttpGet { HttpGet(String value) {} }
    static class TrustAllStrategy {}
}
