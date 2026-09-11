from django.urls import path

from .views import AccountView, AdminSerializerView, ProtectedOrderView, UnsafeOrderView

urlpatterns = [
    path("orders/<int:order_id>", UnsafeOrderView.as_view()),
    path("protected/<int:order_id>", ProtectedOrderView.as_view()),
    path("accounts/<int:account_id>", AccountView.as_view()),
    path("admin/profile", AdminSerializerView.as_view()),
]
