# Generated by Django 4.2.4 on 2023-11-11 11:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('clientcare', '0007_auditentry'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditentry',
            name='time',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
    ]