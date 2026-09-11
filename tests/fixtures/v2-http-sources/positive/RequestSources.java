class RequestSources {
    void review(HttpServletRequest request) throws Exception {
        String query = request.getParameter("q");
        var body = request.getInputStream();
        String path = request.getPathInfo();
        String header = request.getHeader("X-Trace");
        var cookies = request.getCookies();
    }
}
