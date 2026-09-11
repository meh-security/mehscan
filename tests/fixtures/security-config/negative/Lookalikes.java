class Lookalikes {
    void review(Object input) {
        client.verifier((host, session) -> false);
        cookie.enableTransportSecurity(false);
        cookie.blockScriptAccess(false);
        DigestFactory.create("MD5");
        SafeInput.read(input);
    }
}
