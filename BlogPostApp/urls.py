from django.urls import path
from django.contrib import admin
from rest_framework.urlpatterns import format_suffix_patterns
from .views import (
    BlogPostList,
    BlogPostDetail,
    CommentList,
    CommentDetail,
    LoginView,
    LogoutAllView,
    LogoutView,
    ProfileView,
    RegisterView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
 
urlpatterns = [
    path("profile/", ProfileView.as_view()),
    path("loginuser/", LoginView.as_view()),
    path("registeruser/", RegisterView.as_view()),
    path("blogposts/", BlogPostList.as_view()),
    path("blogposts/<int:pk>/", BlogPostDetail.as_view()),
    path("comments/", CommentList.as_view()),
    path("comments/<int:pk>/", CommentDetail.as_view()),
    path("token-generate/", TokenObtainPairView.as_view(), name="token-generate"),
    path("token-verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("token-refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view()),
    path("logout-all/", LogoutAllView.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)
