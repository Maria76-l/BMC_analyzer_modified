from django.db import models

class CommandPolicy(models.Model):
    command = models.CharField(max_length=100, unique=True)
    frequency = models.IntegerField(default=1)
    criticality = models.FloatField(default=0.5)

    def __str__(self):
        return self.command