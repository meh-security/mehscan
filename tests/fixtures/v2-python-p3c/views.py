import subprocess
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import format_html


def unsafe_template(request):
    query = request.GET.get("q", "")
    return render(request, "unsafe.html", {"query": query})


def script_template(request):
    code = request.POST.get("code", "")
    return render(request, "script.html", {"code": code})


def escaped_template(request):
    value = request.GET.get("value", "")
    return render(request, "escaped.html", {"value": value})


def raw_response(request):
    value = request.GET.get("value", "")
    return HttpResponse(value)


def formatted_response(request):
    value = request.GET.get("value", "")
    return HttpResponse(format_html("{}", value))


def command_out(command):
    return subprocess.Popen(command, shell=True)


def command(request):
    host = request.POST.get("host")
    command_line = "nmap " + host
    return command_out(command_line)
