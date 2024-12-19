from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers
from datetime import timedelta


# Serializer for Register
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email']
        )
        return user

# Serializer for Login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user is not None:
                remember_me = request.data.get('remember_me', False)

                # Adjust token lifetime based on "remember_me"
                if remember_me:
                    access_token_lifetime = timedelta(days=7)  # 7-day token for "remember me"
                    refresh_token_lifetime = timedelta(days=30)  # Optional
                else:
                    access_token_lifetime = timedelta(minutes=1)
                    refresh_token_lifetime = timedelta(days=1)

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                refresh.set_exp(lifetime=refresh_token_lifetime)
                access_token = refresh.access_token
                access_token.set_exp(lifetime=access_token_lifetime)

                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh)
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# auth_app/views.py (Add this to your existing views)
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a protected view, you are authenticated!"})

