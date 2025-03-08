from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Reference to the user who performed the scan
    target = models.CharField(max_length=255)  # The domain or target being scanned
    subdomains = models.TextField()  # Store the list of subdomains as text
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of when the scan was created

    def __str__(self):
        return f"Scan result for {self.target} by {self.user.username} on {self.created_at}"

class NucleiResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Reference to the user
    target = models.CharField(max_length=255)  # Domain being scanned
    subdomain = models.CharField(max_length=255)  # Subdomain being scanned
    bug_class = models.CharField(max_length=255)  # Type of vulnerability class
    scan_results = models.TextField()  # Raw scan results (JSON as string)
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of scan

    def __str__(self):
        return f"Nuclei Scan for {self.subdomain} ({self.bug_class}) by {self.user}"

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # This will store the hashed password

    # Additional fields can be added as needed
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    # Specify related names to avoid conflicts
    groups = models.ManyToManyField(Group, related_name='custom_user_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_set', blank=True)

    def __str__(self):
        return self.username


