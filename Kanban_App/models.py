
from django.contrib.auth.models import User
from django.db import models
from datetime import date
from django.conf import settings


class ToDo(models.Model):
    STATUS_CHOISES = [('todo', 'todo'),
                      ('in_progress', 'in progress'),
                      ('await_feedback', 'await feedback'),
                      ('done', 'done')]
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=500)
    created_at = models.DateField(default=date.today)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=14, choices=STATUS_CHOISES, default='todo', blank=False)
    users = models.ManyToManyField(
        User, related_name='users', blank=False)
    # subtasks = models.ManyToManyField(
    #     Subtask, related_name='subtasks', blank=True)

    def __str__(self):
        return str(self.id)+' '+self.title


class Subtask(models.Model):
    STATUS = [('in_progress', 'in progress'), ('done', 'done')]
    message = models.CharField(max_length=200)
    status = models.CharField(
        max_length=14, choices=STATUS, default='', blank=True)
    task = models.ForeignKey(
        ToDo, on_delete=models.CASCADE, related_name='subtasks')

    def __str__(self) -> str:
        return str(self.id)+' ' + self.message
