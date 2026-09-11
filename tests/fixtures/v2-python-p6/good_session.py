from cryptography.fernet import Fernet

fernet = Fernet(KEY)


def load(request):
    cookie = request.cookies.get("app_session")
    return fernet.decrypt(cookie, ttl=3600)


def create(response, value):
    response.set_cookie(
        "app_session", value, secure=True, httponly=True, samesite="Lax"
    )
    return response
