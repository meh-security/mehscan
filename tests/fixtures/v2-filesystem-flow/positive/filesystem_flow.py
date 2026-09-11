def direct(request):
    return open(request.args["direct"])


def propagated(request, content):
    requested = request.args["propagated"]
    alias = requested
    with open(alias, "wb") as output:
        output.write(content)


def canonicalized(request):
    canonical = os.path.realpath(request.args["protected"])
    return open(canonical)


def contained(candidate, root):
    return os.path.commonpath([root, candidate]) == root
