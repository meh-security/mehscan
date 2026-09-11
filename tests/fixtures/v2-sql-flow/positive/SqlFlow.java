class SqlFlow {
    Object direct(HttpServletRequest request, Statement statement) throws Exception {
        return statement.executeQuery(request.getParameter("direct"));
    }

    void propagated(HttpServletRequest request, Statement statement) throws Exception {
        String query = request.getParameter("propagated");
        String alias = query;
        statement.executeQuery(alias);
    }
}
