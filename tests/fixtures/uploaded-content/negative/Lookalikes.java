class Lookalikes {
    void review(HttpServletRequest request) throws Exception {
        var stream = request.getAttachment("upload").getInputStream();
    }
}
