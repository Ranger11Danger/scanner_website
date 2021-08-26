from django.db import models

# Create your models here.

class scan(models.Model):
    name = models.TextField()
    user = models.IntegerField()
    slug = models.SlugField()

class port_info(models.Model):
    cve = models.TextField()
    ip = models.TextField()
    port = models.TextField()
    name = models.TextField()
    score = models.IntegerField()
    description = models.TextField()
    solution = models.TextField()
    scan_id = models.SlugField()
    user = models.IntegerField()