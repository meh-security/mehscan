from django.urls import path

from . import views

urlpatterns = [
    path("profile", views.profile),
    path("transfer", views.transfer),
    path("delegated", views.delegated),
    path("session-change", views.session_change),
    path("source-writer", views.source_writer),
    path("evaluator", views.evaluator),
    path("image-writer", views.image_writer),
    path("ui", views.ui),
]
