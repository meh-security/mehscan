import jwt
import requests
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class DefaultProtectedView(APIView):
    def get(self, request):
        return Response({"ok": True})


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"ok": True})


def unsafe_decode(token):
    return jwt.decode(token, options={"verify_signature": False})


def externally_verified_decode(token, verify_url):
    response = requests.post(verify_url, json={"token": token})
    if response.status_code == 200:
        return jwt.decode(token, options={"verify_signature": False})


def verified_decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


def weak_sign(subject):
    return jwt.encode({"sub": subject}, "hardcoded-development-key", algorithm="HS256")
