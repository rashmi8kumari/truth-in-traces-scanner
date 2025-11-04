from django.urls import path
from .views import register_user, login_user, scan_system

urlpatterns = [
    path("register/", register_user, name="register_user"),
    path("login/", login_user, name="login_user"),
    path("scan_system/", scan_system, name="scan_system"),
]


