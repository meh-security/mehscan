from django.urls import path

from . import callers

urlpatterns = [
    path("read", callers.read_route),
    path("write", callers.write_route),
]
