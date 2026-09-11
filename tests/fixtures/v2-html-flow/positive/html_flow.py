def direct(request):
    return HTMLResponse(request.args["direct"])


def propagated(request):
    content = request.args["propagated"]
    alias = content
    return HTMLResponse(alias)


def encoded(request):
    content = html.escape(request.args["encoded"])
    return HTMLResponse(content)
