from django.urls import path

from . import lookups

urlpatterns = [
    path("fixed", lookups.fixed_lookup),
    path("fixed-string", lookups.fixed_string_lookup),
    path("dynamic", lookups.dynamic_lookup),
]
