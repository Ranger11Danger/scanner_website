# Generated by Django 3.2.6 on 2021-09-01 14:22

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0007_auto_20210901_1421'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='uuid',
            field=models.UUIDField(default=uuid.uuid4, unique=True),
        ),
    ]
