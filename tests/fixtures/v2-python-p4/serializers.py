from rest_framework import serializers

from .models import User


class UnsafeAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "role", "is_staff")
        read_only_fields = ("email",)


class ProtectedAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "role", "is_staff")
        read_only_fields = ("role", "is_staff")
