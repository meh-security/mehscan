from django.urls import path

from . import views

urlpatterns = [path("api/logs", views.logs)]
