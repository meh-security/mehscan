class Lookalikes {
    Object execute(HttpServletRequest request, CustomEngine engine) {
        return engine.eval(request.getParameter("code"));
    }
}
