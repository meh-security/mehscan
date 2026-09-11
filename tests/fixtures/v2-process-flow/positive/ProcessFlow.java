class ProcessFlow {
    void direct(HttpServletRequest request) throws Exception {
        Runtime.getRuntime().exec(request.getParameter("direct"));
    }

    void propagated(HttpServletRequest request) throws Exception {
        String command = request.getParameter("propagated");
        String alias = command;
        Runtime.getRuntime().exec(alias);
    }

    void separated(HttpServletRequest request) {
        new ProcessBuilder("tool", request.getParameter("argument"));
    }
}
