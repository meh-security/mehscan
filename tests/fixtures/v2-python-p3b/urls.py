from django.urls import path

from . import unsafe

urlpatterns = [
    path("command", unsafe.command),
    path("evaluate", unsafe.evaluate),
    path("restore", unsafe.restore),
    path("yaml", unsafe.yaml_upload),
    path("xml", unsafe.xml_parse),
]
