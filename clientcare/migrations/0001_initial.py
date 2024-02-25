# Generated by Django 4.2.4 on 2023-08-23 06:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('address', models.TextField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=255)),
                ('hostname', models.CharField(max_length=255)),
                ('uptime', models.CharField(max_length=255, null=True)),
                ('username', models.CharField(max_length=255, null=True)),
                ('password', models.CharField(max_length=255, null=True)),
                ('device_type', models.CharField(max_length=255, null=True)),
                ('last_backup_time', models.DateTimeField(blank=True, null=True)),
                ('vendor', models.CharField(blank=True, max_length=255, null=True)),
                ('position', models.CharField(blank=True, max_length=255, null=True)),
                ('location', models.CharField(blank=True, max_length=255, null=True)),
                ('sshport', models.IntegerField(default=22, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='clientcare.client')),
            ],
        ),
        migrations.CreateModel(
            name='TypeDeviceMapping',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.CharField(max_length=255, unique=True)),
                ('device_type', models.CharField(max_length=255)),
                ('vendor', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='WeeklyBackupData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('week_number', models.PositiveIntegerField(unique=True)),
                ('successful_backups', models.PositiveIntegerField()),
                ('total_devices', models.PositiveIntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=255)),
                ('action', models.CharField(max_length=255)),
                ('status', models.CharField(max_length=255)),
                ('time', models.DateTimeField(null=True)),
                ('messages', models.CharField(blank=True, max_length=255)),
                ('commandline', models.CharField(blank=True, max_length=1000)),
                ('device_id', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='clientcare.device')),
            ],
        ),
        migrations.CreateModel(
            name='Contact',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='contacts', to='clientcare.client')),
            ],
        ),
        migrations.CreateModel(
            name='Backup_file',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('time', models.DateTimeField(auto_now_add=True)),
                ('success', models.BooleanField(default=False)),
                ('file_path', models.CharField(max_length=255)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='clientcare.device')),
            ],
        ),
    ]