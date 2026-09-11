def review(request):
    body = request.form["email"]
    query = request.args["q"]
    path = request.view_args["id"]
    header = request.headers["X-Trace"]
    cookie = request.cookies["session"]
    return body, query, path, header, cookie
