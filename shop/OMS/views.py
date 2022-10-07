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
    authentication_classes = [JWTAuthentication]

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

    def get(self, request):
        try:
            print("request.user===", request.user)
            token = get_tokens_for_user(request.user)
            print(token)
            # refresh_token = self.request.data["refresh_token"]
            # # refresh_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY2Mjk3NjA5MywiaWF0IjoxNjYyODg5NjkzLCJqdGkiOiI0YzU3MmNmMjZmYzQ0YTZjOTI3YjJkOWE0NDUyYWY4ZiIsInVzZXJfaWQiOjF9.WplA-Gj7qmeOyLjRvnd3JOVNwwxDDlr_7IDzOETGHlg"
            # print("========>>", refresh_token)
            print(token.get("refresh"))
            token = RefreshToken(token.get("refresh"))
            print("============", token)
            token.blacklist()
            return Response(
                {"msg": "Logout Done"}, status=status.HTTP_205_RESET_CONTENT
            )
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
