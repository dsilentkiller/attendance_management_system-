from django.shortcuts import render
from courses.models import Subjects
from courses.serializers import SubjectsSerializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import Http404


class SubjectsListAPI(APIView):
    '''LIST ALL SUBJECTS LIST'''

    def get(self, request, format=None):
        subjects = Subjects.objects.all() #listing all subjects
        serializers = SubjectsSerializers(subjects, many=True) 
        return Response(serializers.data)

    def post(self, request, format=None):
        serializer = SubjectsSerializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SubjectsDetailAPI(APIView):
    '''RETRIVE UPDATE OR DELETE SUBJECT INSTANCE'''

    def get_object(self, pk):
        try:
            return Subjects.objects.get(pk=pk) #return according to id provided
        except Subjects.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        subject = self.get_object(pk)  # take only one subject
        serializer = SubjectsSerializers(subject)
        return Response(serializer.data)
    # update

    def put(self, request, pk, format=None):
        subject = self.get_object(pk)
        serializer = SubjectsSerializers(subject, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# delete

    def delete(self, request, pk, format=None):
        subject = self.get_object(pk)
        subject.delete()  # delete one subject
        return Response(status=status.HTTP_204_NO_CONTENT)
