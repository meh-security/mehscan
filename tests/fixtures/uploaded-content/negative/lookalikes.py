def review(request):
    return request.FILES["upload"].text()
