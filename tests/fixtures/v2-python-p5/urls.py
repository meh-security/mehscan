from django.urls import path

from .views import DefaultProtectedView, PublicView

urlpatterns = [
    path("protected", DefaultProtectedView.as_view()),
    path("public", PublicView.as_view()),
]
