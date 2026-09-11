from django.urls import path, re_path
import api.views as api_views

urlpatterns = [
    re_path(r"items/(?P<item_id>[0-9]+)$", api_views.ItemView.as_view()),
    path("admin/", api_views.AdminView.as_view()),
    path("public/", api_views.PublicView.as_view()),
    path("upload/<slug:slug>", api_views.upload),
]
