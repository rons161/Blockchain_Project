import uuid

from django.db import models


# Table for current user and their current balance.
class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=100.00)


# Table for transaction that is created by current user.
class Transaction(models.Model):
    objects = models.Manager()
    sender = models.CharField(max_length=255)
    receiver = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    time = models.DateTimeField(auto_now_add=True)

