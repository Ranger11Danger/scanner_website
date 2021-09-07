import uuid
from django.db import models
# Create your models here.

class scan(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    name = models.TextField()
    user = models.IntegerField()
    slug = models.SlugField()
    address = models.TextField()
    created_at  = models.DateTimeField(auto_now_add=True)

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