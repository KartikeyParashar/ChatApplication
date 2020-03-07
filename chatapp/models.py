from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class Details(models.Model):
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=200)
    password = models.IntegerField()

    def __str__(self):
        return self.username


