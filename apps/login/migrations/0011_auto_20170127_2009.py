# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-01-27 20:09
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0010_auto_20170127_2007'),
    ]

    operations = [
        migrations.AlterField(
            model_name='liked',
            name='liked_by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='login.Users'),
        ),
    ]
