class UploadedContent {
    void review(HttpServletRequest request) throws Exception {
        var stream = request.getPart("upload").getInputStream();
    }
}
