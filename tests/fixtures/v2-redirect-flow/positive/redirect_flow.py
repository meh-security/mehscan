def direct(request):
    return redirect(request.args["direct"])


def propagated(request):
    requested = request.args["propagated"]
    alias = requested
    return redirect(alias)


def parsed(request):
    destination = urllib.parse.urlsplit(request.args["parsed"])
    return redirect(destination.geturl())


def valid_local(destination, allowed_hosts):
    return url_has_allowed_host_and_scheme(destination, allowed_hosts=allowed_hosts)
