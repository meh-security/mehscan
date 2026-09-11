class TlsClient {
    void configure(Client client) {
        client.hostnameVerifier((host, session) -> true);
    }
}
