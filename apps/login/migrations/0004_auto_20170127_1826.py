# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-01-27 18:26
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0003_owner'),
    ]

    operations = [
        migrations.RenameField(
            model_name='quote',
            old_name='name',
            new_name='the_quote',
        ),
    ]
