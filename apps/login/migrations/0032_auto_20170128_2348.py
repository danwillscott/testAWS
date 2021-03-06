# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-01-28 23:48
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0031_delete_quotejoin'),
    ]

    operations = [
        migrations.CreateModel(
            name='Liked',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quote_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='quoteid', to='login.Quote')),
            ],
        ),
        migrations.RemoveField(
            model_name='users',
            name='liked',
        ),
        migrations.AddField(
            model_name='liked',
            name='user_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='userid', to='login.Users'),
        ),
    ]
