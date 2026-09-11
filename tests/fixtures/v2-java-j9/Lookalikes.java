class HttpServletResponse {
    Writer getWriter() { return new Writer(); }
}
class Writer {
    void write(String value) {}
}
class Encode {
    static String forHtml(String value) { return value; }
}
class ResponseEntity {
    static ResponseEntity ok() { return new ResponseEntity(); }
    ResponseEntity contentType(String value) { return this; }
    void body(String value) {}
}
class Lookalikes {
    void run(HttpServletResponse response, String value) {
        response.getWriter().write(value);
        Encode.forHtml(value);
        ResponseEntity.ok().contentType("text/html").body(value);
    }
}
