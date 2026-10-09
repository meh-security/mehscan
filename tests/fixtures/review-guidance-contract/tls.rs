pub fn client() -> reqwest::ClientBuilder {
    reqwest::Client::builder().danger_accept_invalid_certs(true)
}
