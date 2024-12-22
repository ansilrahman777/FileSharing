from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .models import Assignment
from django.contrib.auth import get_user_model

User = get_user_model()

class AssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assignment
        fields = ['user', 'file', 'title', 'uploaded_at']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        user.email_verified = False
        user.save()
        self.send_verification_email(user)
        return user

    def send_verification_email(self, user):
        # Generate access token for user
        token = RefreshToken.for_user(user).access_token
        verification_url = f"http://127.0.0.1:8000/api/verify-email/?token={token}"

        # Send email
        send_mail(
            'Verify Your Email',
            f'Click the link to verify your email: {verification_url}',
            'your-email@example.com',
            [user.email],
            fail_silently=False,
        )

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = User.objects.filter(email=data['email']).first()

        if not user:
            raise serializers.ValidationError('Invalid email or password.')

        if not user.check_password(data['password']):
            raise serializers.ValidationError('Invalid email or password.')

        # if hasattr(user, 'email_verified') and not user.email_verified:
        #     raise serializers.ValidationError('Email is not verified.')

        return data
