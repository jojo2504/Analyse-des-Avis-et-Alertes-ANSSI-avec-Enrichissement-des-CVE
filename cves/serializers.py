from rest_framework import serializers
from .models import CVE, EmailGroup

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = '__all__'

class EmailGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailGroup
        fields = '__all__'