from django.urls import path, include
from django.contrib.auth.models import User
from rest_framework import serializers
from courses.models import Subjects


class SubjectsSerializers(serializers.ModelSerializer):
    class Meta:
        model = Subjects
        fields = ['subject_name', 'subject_code', 'number_of_classes']
