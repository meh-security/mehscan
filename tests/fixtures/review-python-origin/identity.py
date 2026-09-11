import jwt


def issue(payload):
    return jwt.encode(payload, "visible-key", algorithm="HS256")


def verify(token):
    return jwt.decode(token, "visible-key", algorithms=["HS256"])
