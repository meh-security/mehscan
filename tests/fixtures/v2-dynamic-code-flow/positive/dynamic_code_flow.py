def direct(request):
    return eval(request.form["code"])


def propagated(request):
    code = request.form["code"]
    alias = code
    return eval(alias)


def restricted(request):
    return eval(request.form["restricted"], {"__builtins__": {}})
