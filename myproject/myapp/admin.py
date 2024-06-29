from django.contrib import admin
from .models import *


admin.site.register(UserRegistration)
admin.site.register(Contact)
admin.site.register(SpamReport)