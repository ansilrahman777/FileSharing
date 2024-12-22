from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import os
from django.core.exceptions import ValidationError


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    class Meta:
        ordering = ['-date_joined']

    def email_verification(self):
        self.email_verified = True
        self.save()


class Assignment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    title = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        allowed_extensions = ['.pptx', '.docx', '.xlsx']
        ext = os.path.splitext(self.file.name)[1]
        if ext.lower() not in allowed_extensions:
            raise ValidationError(f"Unsupported file type: {ext}. Allowed types are: {', '.join(allowed_extensions)}")

    def __str__(self):
        return self.title
