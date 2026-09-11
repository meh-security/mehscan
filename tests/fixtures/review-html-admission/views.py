from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string


def safe_response(value):
    rendered = render_to_string("safe.html", {"name": value})
    return HttpResponse(rendered)


def unsafe_response(value):
    rendered = render_to_string("unsafe.html", {"name": value})
    return HttpResponse(rendered)


def delegated_response(value):
    rendered = build_html(value)
    return HttpResponse(rendered)


def logs(request):
    values = request.GET.getlist("value")
    return JsonResponse({"logs": values})
