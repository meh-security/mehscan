from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def profile(request):
    return render(request, "profile.html", {"name": request.GET.get("name")})


@csrf_exempt
def transfer(request):
    account = Account.objects.get(id=request.POST.get("account"))
    account.balance = request.POST.get("balance")
    account.save()
    return render(request, "done.html")


@csrf_exempt
def delegated(request):
    return perform_account_change(request.POST.get("account"))


@csrf_exempt
def session_change(request):
    if request.method == "POST" and request.user.is_authenticated:
        request.session["display_name"] = request.POST.get("display_name")
    return render(request, "done.html")


@csrf_exempt
def source_writer(request):
    destination = open("generated.py", "w")
    destination.write(request.POST.get("code"))
    return render(request, "done.html")


@csrf_exempt
def evaluator(request):
    return render(request, "done.html", {"value": eval(request.POST.get("value"))})


@csrf_exempt
def image_writer(request):
    image = Image.open(request.FILES["image"])
    image.save(buffered)
    return render(request, "done.html")


@csrf_exempt
def ui(request):
    example = "account.delete()"
    return render(request, "ui.html", {"example": example})
