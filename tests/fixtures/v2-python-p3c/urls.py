from django.urls import path

from . import views

urlpatterns = [
    path("unsafe", views.unsafe_template),
    path("script", views.script_template),
    path("escaped", views.escaped_template),
    path("raw", views.raw_response),
    path("formatted", views.formatted_response),
    path("command", views.command),
]
