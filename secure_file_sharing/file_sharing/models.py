from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission

# User Model
class User(AbstractUser):
    USER_TYPE_CHOICES = [
        ('ops', 'Operation User'),
        ('client', 'Client User'),
    ]
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='ops')

     
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',   
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_permission_set',   
        blank=True,
    )

    def __str__(self):
        return self.username   


# File Model
class File(models.Model):
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to='uploads/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
