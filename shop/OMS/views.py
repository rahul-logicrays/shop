from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import generics, permissions, mixins
from rest_framework.response import Response
from .serializer import RegisterSerializer, UserSerializer
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from .utils import get_tokens_for_user
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)


class RegisterApi(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(
            {
                "user": UserSerializer(
                    user, context=self.get_serializer_context()
                ).data,
                "message": "User Created Successfully.  Now perform Login to get your token",
            }
        )


class LoginAPI(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = [JWTAuthentication]

    def post(self, request, format=None):
        user = request.data.get("username")
        password = request.data.get("password")
        user_obj = User.objects.get(username=user)
        print(user, user_obj)
        user = authenticate(username=user, password=password)
        if user.id:
            token = get_tokens_for_user(user)
            return Response({"msg": "login successful", "token": token})
        # login(request, user_obj)
        return Response(
            {
                "user": user,
                "message": "Login Not sucess fully",
            }
        )


class UserAPIview(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    # authentication_classes = [JWTAuthentication]

    def get(self, request):
        # print(dir(self))
        user = User.objects.get(username=request.user)
        serializer = self.get_serializer(user)
        return Response(
            {
                "user": serializer.data,
                "message": "Login sucess fully",
            },
        )


class LogoutView(generics.GenericAPIView):
    permission_classes = [
        IsAuthenticated,
    ]
    # authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        if self.request.data.get("all"):
            token: OutstandingToken
            for token in OutstandingToken.objects.filter(user=request.user):
                _, _ = BlacklistedToken.objects.get_or_create(token=token)
            return Response({"status": "OK, goodbye, all refresh tokens blacklisted"})
        refresh_token = self.request.data.get("refresh_token")
        token = RefreshToken(token=refresh_token)
        token.blacklist()
        return Response({"status": "OK, goodbye"})
