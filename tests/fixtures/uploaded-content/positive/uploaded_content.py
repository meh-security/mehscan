def review(request):
    return request.FILES["upload"].read()
