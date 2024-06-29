from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class CustomUserManager(BaseUserManager):
    def _create_user(self, phone_number, password,**extra_fields):
        if not phone_number:
            raise ValueError('Users must have a phone number')

        user = self.model(
            phone_number=phone_number,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self,phone_number=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        extra_fields.setdefault('is_admin',False)

        return self._create_user(phone_number,password,**extra_fields)

    def create_superuser(self, phone_number=None, password=None,**extra_fields):

        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_admin',True)

        return self._create_user(phone_number,password,**extra_fields)

class UserRegistration(AbstractBaseUser):
    phone_number = models.CharField(max_length=15, unique=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(blank=True, null=True)
    password=models.CharField(max_length=255,blank=True,null=True)
    
    otp=models.IntegerField(null=True,blank=True)
    otp_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)

    user_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_superuser=models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_registered=models.BooleanField(default=False)
    
    

    objects = CustomUserManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.name

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin

class Contact(models.Model):
    owner = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)

    def __str__(self):
        return f"{self.owner.name}'s contact - {self.name}"

class SpamReport(models.Model):
    reporter = models.ForeignKey(UserRegistration, on_delete=models.CASCADE, related_name='reported_spam')
    phone_number = models.CharField(max_length=15)
    reported_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.reporter.name} reported spam: {self.phone_number}"
