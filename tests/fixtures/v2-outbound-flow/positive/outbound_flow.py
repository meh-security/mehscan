def direct(request):
    return requests.get(request.args["direct"])


def propagated(request):
    requested = request.args["propagated"]
    alias = requested
    return requests.get(alias)


def parsed(request):
    destination = urllib.parse.urlsplit(request.args["parsed"])
    return requests.get(destination.geturl())


def valid_scheme(destination):
    return destination.scheme == "https"
