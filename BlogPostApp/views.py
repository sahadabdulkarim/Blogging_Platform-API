from django.shortcuts import render

# Create your views here.
from rest_framework import generics, status
from .models import BlogPost, Comment
from .serializers import BlogPostSerializer, CommentSerializer
from django.contrib.auth import login
from django.contrib.auth.models import User
from .serializers import RegisterSerializer, LoginSerializer
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import (
    RefreshToken,
    OutstandingToken,
    BlacklistedToken,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView


from django.contrib.auth import get_user_model
from rest_framework.generics import CreateAPIView


class BlogPostList(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (JWTAuthentication,)
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class BlogPostDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (JWTAuthentication,)
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.author == self.request.user:
            self.perform_destroy(instance)
            print(instance)
        else:
            if self.request.user.is_superuser == True:
                self.perform_destroy(instance)
                return Response({"message": "Blog deleted succesfully by admin ."})
            else:
                return Response(
                    {"message": "You cannot delete Blog created by another User"}
                )
        return Response({"message": "Blog deleted succesfully."})


class CommentList(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (JWTAuthentication,)
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class CommentDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (JWTAuthentication,)
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        user = self.request.user

        # Check if the user is the author of the comment or the blog post
        if instance.author == user or instance.post.author == user:
            self.perform_destroy(instance)
            return Response({"message": "Comment deleted successfully"})
        else:
            if user.is_superuser:
                self.perform_destroy(instance)
                return Response({"message": "Comment deleted successfully by admin."})
            else:
                return Response(
                    {"message": "You cannot delete comments created by another user."}
                )


User = get_user_model()


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def get_permissions(self):
        # Allow normal user registration without authentication
        if self.request.data.get("is_staff", False):
            return [
                IsAuthenticated()
            ]  # Require admin authentication for admin registration
        else:
            return [AllowAny()]  # Allow normal user registration without authentication

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if the requesting user is an authenticated admin for admin registration
        if request.data.get("is_staff", False):
            requesting_user = request.user
            if not requesting_user.is_authenticated or not requesting_user.is_superuser:
                return Response(
                    {
                        "detail": "Only authenticated admin users can register new admin users."
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

        user = serializer.save()
        if request.data.get("is_staff", False):
            subject = "Welcome to our Blog Platform (Admin User)"
            message = f"Hello {user.username},\n\nThank you for registering as an Admin on our Blog Platform."
        else:
            subject = "Welcome to our Blog Platform"
            message = f"Hello {user.username},\n\nThank you for registering on our Blog Platform."

        from_email = settings.EMAIL_HOST_USER
        to_email = [user.email]
        send_mail(subject, message, from_email, to_email)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        login(request, user)

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "status": status.HTTP_200_OK,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
            }
        )


class ProfileView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, format=None):
        user = self.request.user
        context = {
            "User": str(self.request.user),
            "Email": str(self.request.user.email),
            "Username": str(self.request.user.username),
        }
        return Response(context)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"message": "Refresh token is required to logout."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "You have been successfully logged out."},
                status=status.HTTP_205_RESET_CONTENT,
            )

        except Exception as e:
            return Response(
                {"message": "An error occurred during logout."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutAllView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)

        return Response(status=status.HTTP_205_RESET_CONTENT)
