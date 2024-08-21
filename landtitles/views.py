from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login as auth_login, logout
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Q
from django.utils.translation import gettext as _

from rest_framework import views, viewsets, status
from rest_framework.authtoken.models import Token  # For token-based authentication
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.serializers import ValidationError as SerializerValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated

from . import serializers
from .models import Profile

User = get_user_model()

def get_and_authenticate_user(identifier: str, password: str):
    """
    identifier can either be username, phone number or email address
    """
    user_not_found_exception = SerializerValidationError("Invalid username or password. Please try again!")
    try:
        user = User.objects.get( Q(username=identifier) | Q(email=identifier) )
        
        user = authenticate(username=user.username, password=password)
        
        if user:
            return user
        raise user_not_found_exception

    except User.DoesNotExist:
        raise user_not_found_exception


def create_user_account(username, password, first_name="", last_name="", email="", phone="", country_code="", **kwargs):
    user = User.objects.create_user(username=username, email=email, password=password, first_name=first_name, last_name=last_name, is_staff=False)
    # create person
    Profile.objects.create(name=first_name, surname=last_name, telephone=phone, user=user, country_code=country_code, **kwargs)
    return user

class AuthViewSet(viewsets.GenericViewSet):
    permision_classes = [AllowAny, ]
    serializer_class = serializers.EmptySerializer
    serializer_classes = {
        'login': serializers.UserLoginSerializer,
        'register': serializers.RegisterSerializer,
        'change_password': serializers.ChangePasswordSerializer,
        # 'update_profile': serializers.UpdateUserSerializer
    }
    queryset = User.objects.all()

    @action(methods=['POST', ], detail=False)
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_and_authenticate_user(**serializer.validated_data)

        auth_login(request, user)

        data = serializers.AuthenticatedUserSerializer(user).data
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def register(self, request):
        serializer: serializers.RegisterSerializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.create(serializer.validated_data)
        
        data = serializers.AuthenticatedUserSerializer(user).data

        return Response(data=data, status=status.HTTP_201_CREATED)

    @action(methods=['POST'], detail=False)
    def logout(self, request):
        logout(request)
        data = {'success': "Logged out successfully"}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def change_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password( serializer.validated_data['new_password'] )
        user.save()

        return Response(data={"message": _("Password changed successfully")})

    @action(methods=["POST"], detail=False, permision_classes=[IsAuthenticated,])
    def update_profile(self, request):
        user = request.user
        user_query = User.objects.filter(id=user.id)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if "profile" in serializer.validated_data:
            profile_object = serializer.validated_data.pop("profile")
            profile_query = Profile.objects.filter(user=user).update(**profile_object)

            if "first_name" in profile_object:
                user_query.update(first_name=profile_object['first_name'])

            if "last_name" in profile_object:
                user_query.update(last_name=profile_object['last_name'])

        if serializer.validated_data:
            user_query.update(**serializer.validated_data)

        user.refresh_from_db()

        return Response(serializers.AuthenticatedUserSerializer(user).data)

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured(_("serializer_classes variable must be a dict mapping"))

        if self.action in self.serializer_classes.keys():
            return self.serializer_classes[self.action]
        
        return super().get_serializer_class()

# class FrontendAppView(TemplateView):
#     template_name = './landfrontend/index.html'