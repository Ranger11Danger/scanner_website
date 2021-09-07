# Generated by Django 3.2.6 on 2021-08-26 16:31

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('category', models.CharField(choices=[('bg-danger', 'Danger'), ('bg-success', 'Success'), ('bg-primary', 'Primary'), ('bg-info', 'Info'), ('bg-dark', 'Dark'), ('bg-warning', 'Warning')], default='bg-info', max_length=255)),
                ('start_date', models.DateTimeField()),
                ('end_date', models.DateTimeField(null=True)),
                ('all_day', models.BooleanField(default=True)),
                ('create_date', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
    ]