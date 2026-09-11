class Lookalikes {
    void review(String html, String location) {
        response.getLogger().write(html);
        response.forward(location);
        request.getAttachment("upload");
    }
}
