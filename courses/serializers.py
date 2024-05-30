from django.urls import path, include
from django.contrib.auth.models import User
from rest_framework import serializers
from courses.models import Subjects


class SubjectsSerializers(serializers.ModelSerializer):
    class Meta:
        model = Subjects
        fields = ['id', 'subject_name', 'subject_code', 'number_of_classes']

    def validate_subject_name(self, value):
        # Ensure subject_name length is between 3 and 100 characters
        if len(value) < 3:
            raise serializers.ValidationError(
                "Subject name must be at least 3 characters long.")
        if len(value) > 100:
            raise serializers.ValidationError(
                "Subject name must not exceed 100 characters.")
        return value

    def validate_subject_code(self, value):
        # Ensure subject_code starts with a letter and is alphanumeric
        if not value[0].isalpha():
            raise serializers.ValidationError(
                "Subject code must start with a letter.")
        if not value.isalnum():
            raise serializers.ValidationError(
                "Subject code should be alphanumeric.")
        return value

    def validate_number_of_classes(self, value):
        # Ensure number_of_classes is a positive integer
        if not isinstance(value, int) or value <= 0:
            raise serializers.ValidationError(
                "Number of classes must be a positive integer.")
        return value

    def validate(self, data):
        # Validate each field individually
        data['subject_name'] = self.validate_subject_name(
            data.get('subject_name'))
        data['subject_code'] = self.validate_subject_code(
            data.get('subject_code'))
        data['number_of_classes'] = self.validate_number_of_classes(
            data.get('number_of_classes'))

        return data
