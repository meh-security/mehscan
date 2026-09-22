from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Account, Order
from .serializers import ProtectedAdminSerializer, UnsafeAdminSerializer


def jwt_auth_required(function):
    return function


class UnsafeOrderView(APIView):
    @jwt_auth_required
    def get(self, request, order_id=None, user=None):
        order = Order.objects.get(id=order_id)
        return Response({"id": order.id})


class ProtectedOrderView(APIView):
    @jwt_auth_required
    def get(self, request, order_id=None, user=None):
        order = Order.objects.get(id=order_id)
        if user != order.user:
            return Response({"error": "restricted"}, status=403)
        return Response({"id": order.id})


class AccountView(APIView):
    @jwt_auth_required
    def post(self, request, account_id=None, user=None):
        account = Account.objects.get(id=account_id, owner=user)
        payload = request.data
        if account.balance < account.unit_price:
            return Response({"error": "insufficient balance"}, status=400)
        account.balance -= float(account.unit_price * payload["amount"])
        account.save()
        return Response({"balance": account.balance})


class AdminSerializerView(APIView):
    @jwt_auth_required
    def put(self, request, user=None):
        unsafe = UnsafeAdminSerializer(user, data=request.data)
        if unsafe.is_valid():
            unsafe.save()
        protected = ProtectedAdminSerializer(user, data=request.data)
        if protected.is_valid():
            protected.save()
        return Response({"ok": True})
