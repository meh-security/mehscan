import os
import requests
from django.shortcuts import redirect


def fixed_boundaries(dynamic_path, dynamic_url):
    open("application.log", "w")
    open("application.log", "r")
    health_url = "https://example.invalid/health"
    requests.get(health_url)

    open(dynamic_path, "w")
    open(dynamic_path, "r")
    requests.get(dynamic_url)


def fixed_local_path(dynamic_leaf):
    base = os.path.dirname(__file__)
    fixed_path = os.path.join(base, "application.log")
    dynamic_path = os.path.join(base, dynamic_leaf)
    open(fixed_path, "w")
    open(dynamic_path, "w")


def redirect_boundaries(identifier, destination):
    redirect("login")
    redirect(f"blog/{identifier}")
    redirect(destination)
