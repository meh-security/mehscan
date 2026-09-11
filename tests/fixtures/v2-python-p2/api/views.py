from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.views import APIView
from utils.jwt import jwt_auth_required


class ItemView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, item_id):
        return request.query_params.get("q"), item_id

    @jwt_auth_required
    def post(self, request, item_id):
        return request.data["name"], request.META.get("HTTP_AUTHORIZATION"), item_id


class AdminView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return request.GET.get("filter")


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return request.body


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def upload(request, slug):
    return request.FILES.get("document"), slug
