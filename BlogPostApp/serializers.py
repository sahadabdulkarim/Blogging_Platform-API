from rest_framework import serializers
from .models import BlogPost, Comment
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import (
    SerializerMethodField,
)


import logging

logger = logging.getLogger(__name__)


class BlogPostSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source="author.username")
    comment = SerializerMethodField(read_only=True)

    def get_comment(self, obj):
        try:
            if obj:
                owner_item = []
                answer_obj = Comment.objects.filter(post=obj.id)
                for items in answer_obj:
                    owner_item.append(
                        {
                            "id": items.id,
                            "comments": items.content,
                            "author": items.author.username,
                        }
                    )
                return owner_item
            else:
                return None
        except Exception as exception:
            logger.exception(
                "Getting Exception while Fetching choices  as %s", exception
            )
        return None

    class Meta:
        model = BlogPost
        fields = [
            "id",
            "title",
            "content",
            "author",
            "created_at",
            "updated_at",
            "blog_image",
            "comment",
        ]


class CommentSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source="author.username")

    class Meta:
        model = Comment
        fields = ["id", "content", "author", "post", "created_at", "updated_at"]


User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    # Add the is_staff field to the serializer with default value False
    is_staff = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "username",
            "password",
            "is_staff",
        ]
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "email": {"required": True},
            "username": {"required": True},
            "password": {"write_only": True, "required": True},
        }

    def create(self, validated_data):
        email = validated_data["email"]
        username = validated_data["username"]

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                "Email Already taken. Please try another one"
            )
        elif User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Username already taken")
        else:
            # If is_staff is not provided in the request data, set it to False (for regular users)
            is_staff = validated_data.pop("is_staff", False)

            user = User.objects.create(**validated_data)
            user.set_password(validated_data["password"])
            user.is_staff = is_staff  # Set the is_staff attribute
            user.save()
            return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255)
    password = serializers.CharField(
        label=_("Password"),
        style={"input_type": "password"},
        trim_whitespace=False,
        max_length=128,
        write_only=True,
    )

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")
        if username and password:
            user = authenticate(
                request=self.context.get("request"),
                username=username,
                password=password,
            )
            if not user:
                raise serializers.ValidationError("login failed", code="authorization")
        else:
            raise serializers.ValidationError(
                "Username and Password required", code="authorization"
            )
        data["user"] = user
        return data
