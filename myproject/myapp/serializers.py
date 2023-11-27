from rest_framework import serializers
from .models import User, Grievance


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        #    fields=('user_id','email','username','is_active','is_admin')
        #    fields='__all__'
        exclude = ('password', 'last_login', 'is_superuser', 'groups', 'user_permissions')


class GrievanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Grievance
        fields = '__all__'
        # fields =  ('id', 'user', 'title', 'description')
