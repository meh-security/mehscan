class DynamicCodeFlow {
    Object direct(HttpServletRequest request) throws Exception {
        return new ScriptEngineManager()
            .getEngineByName(request.getParameter("language"))
            .eval(request.getParameter("code"));
    }

    Object propagated(HttpServletRequest request) throws Exception {
        String language = request.getParameter("language");
        String code = request.getParameter("code");
        String alias = code;
        return new ScriptEngineManager().getEngineByName(language).eval(alias);
    }

    Object restricted(HttpServletRequest request) throws Exception {
        return new ScriptEngineManager()
            .getEngineByName("javascript")
            .eval(request.getParameter("restricted"));
    }
}
