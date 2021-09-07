# Generated by Django 3.2.6 on 2021-09-07 16:20

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='asset_group',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('name', models.TextField()),
                ('user', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='port_info',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cve', models.TextField()),
                ('ip', models.TextField()),
                ('port', models.TextField()),
                ('name', models.TextField()),
                ('score', models.IntegerField()),
                ('description', models.TextField()),
                ('solution', models.TextField()),
                ('scan_id', models.SlugField()),
                ('user', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='scan',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('name', models.TextField()),
                ('user', models.IntegerField()),
                ('slug', models.SlugField()),
                ('address', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='asset',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.TextField()),
                ('user', models.IntegerField()),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dashboard.asset_group')),
            ],
        ),
    ]
