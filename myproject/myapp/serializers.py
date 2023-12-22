from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer

from .models import User, Grievance, Document


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        #    fields=('user_id','email','username','is_active','is_admin')
        #    fields='__all__'
        exclude = ('password', 'last_login', 'is_superuser', 'groups', 'user_permissions')


class GrievanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Grievance
        exclude = ['gk_id']
        # fields =  ('id', 'user', 'title', 'description')


class CustomTokenObtainPairSerializer(TokenObtainSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['username'] = user.username
        data['userid'] = user.id
        data['email'] = user.email
        return data


class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = '__all__'
        # exclude = ['doc_type', 'size']
