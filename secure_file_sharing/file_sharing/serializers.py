from rest_framework import serializers
from .models import User, File
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

# Serializer for User Registration
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username', 'email', 'password', 'user_type']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

# Serializer for Login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        return user

# Serializer for File Uploads
class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'name', 'file', 'uploaded_at', 'uploaded_by']
