from django.db import models

# Create your models here.


class Subjects(models.Model):
    subject_name = models.CharField(max_length=100)
    subject_code = models.CharField(max_length=30, unique=True)
    number_of_classes = models.CharField(max_length=500)

    def __str__(self):
        return self.subject_name
