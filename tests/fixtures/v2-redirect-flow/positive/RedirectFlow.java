class RedirectFlow {
    void direct(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("direct"));
    }

    void propagated(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String requested = request.getParameter("propagated");
        String alias = requested;
        response.sendRedirect(alias);
    }

    void parsed(HttpServletRequest request, HttpServletResponse response) throws Exception {
        URI destination = URI.create(request.getParameter("parsed"));
        response.sendRedirect(destination.toString());
    }

    boolean validLocal(String destination) {
        return !URI.create(destination).isAbsolute();
    }
}
