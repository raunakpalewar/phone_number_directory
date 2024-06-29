from rest_framework import serializers
from .models import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegistration
        fields = ('id', 'phone_number', 'name', 'email')
        extra_kwargs = {
            'email': {'write_only': True}  
        }

class ContactSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())


    class Meta:
        model = Contact
        fields = ('id', 'owner', 'name', 'phone_number', )

class SpamReportSerializer(serializers.ModelSerializer):
    reporter = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())

    class Meta:
        model = SpamReport
        fields = ('id', 'reporter', 'phone_number', 'reported_at')
