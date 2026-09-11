class Lookalikes {
    @LocalGetMapping("/admin")
    @CheckRole("ADMIN")
    void admin() {}

    void configure() {
        http.basicLogin();
    }
}
