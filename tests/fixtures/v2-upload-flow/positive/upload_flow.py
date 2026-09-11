def direct(request, content):
    with open(request.FILES["upload"].name, "w") as output:
        output.write(content)


def propagated(request, content):
    requested = request.FILES["upload"].name
    alias = requested
    with open(alias, "w") as output:
        output.write(content)


def canonicalized(request, content):
    destination = os.path.realpath(request.FILES["upload"].name)
    with open(destination, "w") as output:
        output.write(content)


def valid_basename(filename):
    return os.path.basename(filename) == filename
