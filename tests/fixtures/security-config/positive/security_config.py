def review(context, response, serialized):
    context.check_hostname = False
    response.set_cookie("transport", "value", secure=False)
    response.set_cookie("script", "value", httponly=False)
    hashlib.new("md5")
    pickle.loads(serialized)
