from django.contrib import admin
from django.urls import path, include
from .views import RegisterApi, LoginAPI, UserAPIview, LogoutView

urlpatterns = [
    path("api/register", RegisterApi.as_view()),
    path("api/login", LoginAPI.as_view()),
    path("api/user", UserAPIview.as_view()),
    path("api/logout", LogoutView.as_view()),
]
