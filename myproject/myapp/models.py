import os

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, is_active=True, is_admin=False, **extra_fields):
        if not email:
            raise ValueError('Please Enter Email')
        if not username:
            raise ValueError('Please Enter UserName')

        email = self.normalize_email(email)
        # username = self.model(username = username)
        user = self.model(
            email=email,
            username=username,
            is_active=is_active,
            is_admin=is_admin,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    user_id = models.CharField(max_length=4, primary_key=True)
    # id=models.AutoField(unique=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def save(self, *args, **kwargs):
        # Generate user_id if it's a new user
        if not self.pk:
            last_user = User.objects.order_by('-user_id').first()
            if last_user:
                last_id = int(last_user.user_id[1:])
                self.user_id = 'U{:03d}'.format(last_id + 1)
            else:
                self.user_id = 'U001'

        super().save(*args, **kwargs)


class Grievance(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    gk_id = models.CharField(max_length=5, primary_key=True)
    username = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_date = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.gk_id:
            last_grievance = Grievance.objects.order_by('-gk_id').first()
            if last_grievance:
                last_id = int(last_grievance.gk_id[1:])  # Extract the numeric part
                new_id = f'G{last_id + 1:03}'  # Increment by 1 and format as 'G001'
            else:
                new_id = 'G001'  # If no grievance exists yet, start with 'G001'
            self.gk_id = new_id

        super(Grievance, self).save(*args, **kwargs)


class Role(models.Model):
    role_id = models.CharField(max_length=5, primary_key=True)
    role_name = models.CharField(max_length=255)
    role_desc = models.TextField()


class Resource(models.Model):
    resource_id = models.CharField(max_length=5, primary_key=True)
    resource_name = models.CharField(max_length=255)
    resource_desc = models.TextField()


class RoleResourceMapping(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)


def document_upload_path(instance, filename):
    # Get the file extension
    extension = os.path.splitext(filename)[1][1:].lower()  # Get the file extension without '.'

    # Determine the sub folder based on the file extension
    if extension == 'pdf':
        return f'documents/pdf/{filename}'
    elif extension == 'xlsx' or extension == 'xls':
        return f'documents/excel/{filename}'
    elif extension in ['jpg', 'jpeg', 'png']:
        return f'documents/images/{filename}'
    elif extension == 'doc' or extension == 'docx':
        return f'documents/word/{filename}'
    elif extension == 'ppt' or extension == 'pptx':
        return f'documents/ppt/{filename}'
    else:
        return f'documents/others/{filename}'


class Document(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    category = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    doc = models.FileField(upload_to=document_upload_path)  # FileField for the uploaded document
    doc_type = models.CharField(max_length=100)
    size = models.IntegerField()
    upload_time = models.DateTimeField(auto_now_add=True)  # Timestamp of upload

    def __str__(self):
        return self.name
