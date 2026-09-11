import base64
import json


def load(request):
    cookie = request.cookies.get("app_session")
    return json.loads(base64.b64decode(cookie))


def create(response, value):
    response.set_cookie("app_session", value)
    return response
