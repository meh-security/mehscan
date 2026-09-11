class WebSecurity {
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    void admin() {}

    void configure() {
        http.httpBasic();
    }
}
