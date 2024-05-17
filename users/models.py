from django.db import models

ROLE = ('Admin', 'Teacher')


class Users(models.Model):
    full_name = models.CharField(max_length=200)
    email = models.CharField(max_length=100, unique=True)
    password =models.CharField(max_length=20)
    role = models.CharField(max_length=100, role=ROLE)

    def _str__(self):
        return f'{self.full_name}{self.email}'
