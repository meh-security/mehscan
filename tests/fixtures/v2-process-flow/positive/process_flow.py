def direct(request):
    return os.system(request.args["direct"])


def propagated(request):
    command = request.args["propagated"]
    alias = command
    return os.system(alias)


def separated(request):
    return subprocess.run(["tool", request.args["argument"]], shell=False)
