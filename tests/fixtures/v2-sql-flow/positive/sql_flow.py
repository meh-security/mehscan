def direct(request, cursor):
    return cursor.execute(request.args["direct"])


def propagated(request, cursor):
    query = request.args["propagated"]
    alias = query
    return cursor.execute(alias)
