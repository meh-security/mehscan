def review(context, response, serialized):
    context.verify_host = False
    response.local_cookie("transport", "value", secure=False)
    response.local_cookie("script", "value", httponly=False)
    hash_factory.new("md5")
    safe_pickle.loads(serialized)
