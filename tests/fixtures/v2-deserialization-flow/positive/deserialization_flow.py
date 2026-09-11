def direct(request):
    return pickle.loads(request.form["payload"])


def propagated(request):
    serialized = request.form["payload"]
    alias = serialized
    return pickle.loads(alias)


def restricted(request):
    return yaml.safe_load(request.form["restricted"])
