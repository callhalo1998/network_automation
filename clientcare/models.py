from __future__ import unicode_literals
from django.conf import settings
from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.db import models
from django.contrib.auth.models import User, AbstractUser
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
import os
import uuid
import logging

logger = logging.getLogger(__name__)

class AuditEntry(models.Model):
    time = models.DateTimeField(auto_now_add=True,null=True)
    action = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(null=True)
    username = models.CharField(max_length=256, null=True)

    def __unicode__(self):
        return '{0} - {1} - {2}'.format(self.action, self.username, self.ip)

    def __str__(self):
        return '{0} - {1} - {2}'.format(self.action, self.username, self.ip)


@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):  
    ip = request.META.get('REMOTE_ADDR')
    AuditEntry.objects.create(action='user_logged_in', ip=ip, username=user.username)
    logger.info(f' Login success: {user.username}')


@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):  
    ip = request.META.get('REMOTE_ADDR')
    AuditEntry.objects.create(action='user_logged_out', ip=ip, username=user.username)
    logger.info(f'Logout: {user.username}')

@receiver(user_login_failed)
def user_login_failed_callback(request,sender, credentials, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    username = credentials.get('username', None)
    AuditEntry.objects.create(action='user_login_failed', username=username,ip=ip)
    logger.warning(f'Failed authentication: {username} from {ip}')

class Client(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(null=True)

    def __str__(self):
        return self.name


class Contact(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='contacts')
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    email = models.EmailField()

    def __str__(self):
        return self.name

class Device(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255)
    uptime = models.CharField(max_length=255,null=True)
    username = models.CharField(max_length=255, null=True)
    password = models.CharField(max_length=255, null=True)
    device_type = models.CharField(max_length=255, null=True)
    last_backup_time = models.DateTimeField(blank=True,null=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    position = models.CharField(max_length=255, blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    sshport = models.IntegerField(default=22, null=True)
    status = models.CharField(max_length=255, null=True)
    search_fields = ['ip_address', 'hostname','device_type','vendor']


    created_at = models.DateTimeField(auto_now_add=True, null=True)
    def __str__(self):
        return "{} - {} - {} - {}".format(self.id, self.ip_address, self.hostname, self.device_type)


class Backup_file(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    file_path = models.CharField(max_length=255)
    
    def get_file_name(self):
        file_name = self.file_path.split('/')[-1]  
        time_part = file_name.split('_')[-1].split('.')[0]
        return time_part
    
    def allow_download(self):
        return self.success

    def __str__(self):
        return "{} - {} - {}".format(self.device.hostname, self.time, "Success" if self.success else "Fail")
    
@receiver(pre_delete, sender=Device)
def delete_device_backup_files(sender, instance, **kwargs):
    # Delete the backup files associated with the device
    backup_files = Backup_file.objects.filter(device=instance)
    for backup_file in backup_files:
        file_path = os.path.join(settings.MEDIA_ROOT, backup_file.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        backup_file.delete()
    

class Log(models.Model):
    device_id = models.ForeignKey(Device, on_delete=models.CASCADE,null=True)
    host = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    time = models.DateTimeField(auto_now_add=True,null=True)
    messages = models.CharField(max_length=255, blank=True)
    commandline = models.CharField(max_length=1000, blank=True)
    by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    def __str__(self):
        return "{} - {} - {}".format(self.host, self.action, self.status)
        
class TypeDeviceMapping(models.Model):
    object_id = models.CharField(max_length=255, unique=True)
    device_type = models.CharField(max_length=255)
    vendor = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.object_id} - {self.device_type} - {self.vendor}"    

class WeeklyBackupData(models.Model):
    week_number = models.PositiveIntegerField(unique=True)
    successful_backups = models.PositiveIntegerField()
    total_devices = models.PositiveIntegerField()