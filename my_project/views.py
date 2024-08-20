from rest_framework import serializers, views, status
from django.views.generic import TemplateView
from rest_framework.response import Response
from django.contrib.auth.models import User  # Django's built-in User model
from django.contrib.auth import authenticate  # For verifying user credentials
from rest_framework.authtoken.models import Token  # For token-based authentication

# Serializer for registering users
class RegisterSerializer(serializers.ModelSerializer):
    # This specifies that the 'password' field should only be used for writing, not for reading (e.g., sending back to the user)
    name = serializers.CharField(write_only=True)
    surname = serializers.CharField(write_only=True)
    address = serializers.CharField(write_only=True)
    email = serializers.CharField(write_only=True)
    telephone = serializers.CharField(write_only=True)
    role = serializers.CharField(write_only=True)
    dob = serializers.CharField(write_only=True)
    birth_location = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User  # This is the model the serializer is based on, Django's built-in User model
        # The fields here correspond to the attributes of the User model in your database
        fields = ('name', 'surname', 'address','email','telephone','role','dob','birth_location','password')  # Modify these if your User model has different or additional fields

    def create(self, validated_data):
        # Creates a new user using the validated data. This function is called when the serializer's `save()` method is called.
        user = User.objects.create_user(**validated_data)
        return user

# View for user registration
class RegisterView(views.APIView):
    def post(self, request):
        # The serializer converts the incoming JSON data into a Python dictionary and validates it
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            # If the data is valid, save it to create a new user
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)  # Respond with the created user's data
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  # If invalid, respond with errors

# View for user login
class LoginView(views.APIView):
    def post(self, request):
        # Extract the username and password from the incoming request data
        name = request.data.get('name')
        password = request.data.get('password')
        # Authenticate the user using the provided credentials
        user = authenticate(username=username, password=password)
        if user:
            # If the credentials are correct, generate or retrieve a token for the user
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})  # Send the token back to the client (your React app)
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)  # If invalid, respond with an error



