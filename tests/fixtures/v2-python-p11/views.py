from argon2 import PasswordHasher


def fixed_row_update(request):
    email = request.GET.get("email")
    Otp.objects.filter(id=1).update(email=email)


def password_login(request):
    username = request.POST["username"]
    password = request.POST["password"]
    user = Admin.objects.get(username=username)
    hasher = PasswordHasher()
    hasher.verify(user.password, password)
    return user


def session_resolution(request):
    token = request.COOKIES["session_id"]
    return Session.objects.get(session_id=token)


def combined_credential_lookup(request):
    username = request.POST["username"]
    password = request.POST["password"]
    return User.objects.filter(username=username, password_hash=password).first()


def unsafe_account_lookup(request):
    account_id = request.GET.get("account_id")
    return Account.objects.get(id=account_id)
