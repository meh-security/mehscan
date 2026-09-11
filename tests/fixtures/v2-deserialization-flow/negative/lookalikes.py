def parse(request, custom_yaml):
    return custom_yaml.safe_load(request.form["payload"])
