# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.models import User
from django.db import models

class CustomUser(AbstractUser):
    pass  # Add any additional fields here
    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',  # Change this to avoid conflict
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set_permissions',  # Change this to avoid conflict
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=15)
    surname = models.CharField(max_length=15)
    address = models.CharField(max_length=15)
    email = models.CharField(max_length=15)
    telephone = models.CharField(max_length=15)
    role = models.CharField(max_length=15)
    dob = models.DateField(max_length=15)
    birth_location = models.CharField(max_length=15)
    # Add other fields as needed

    def __str__(self):
        return self.user.username
