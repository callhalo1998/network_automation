import os
from django.shortcuts import render, get_object_or_404, redirect
from celery_progress.backend import ProgressRecorder
import paramiko
from django.contrib.auth.models import User
from datetime import timedelta, datetime
from celery import shared_task
from .models import Device, Log, Backup_file
from django.utils import timezone
from time import sleep
from ping3 import ping, verbose_ping
import ipaddress
from django.core.exceptions import ObjectDoesNotExist
from clientcare.models import Client, Device, Log, Backup_file
from .utils import Device_snmp
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def go_to_sleep(self, duration):
    progress_recorder = ProgressRecorder(self)
    for i in range (5):    
        sleep(duration)
        progress_recorder.set_progress(i + 1, 5, f'On number {i}')
    return "DOne"

@shared_task(bind=True)
def ping_subnets(self, subnet,user_id):
    user = User.objects.get(id=user_id)
    progress_recorder = ProgressRecorder(self)
    live_ips = []
    devices_to_update = []
    network = ipaddress.ip_network(subnet)
    
    total_hosts = len(list(network.hosts()))
    
    for i, ip in enumerate(network.hosts(), start=1):
        ip = str(ip)
        response_time = ping(ip, timeout=0.1)  # Change the timeout value as needed
        
        if response_time is None or response_time is False:
            pass
        else:
            try:
                snmp_device = Device_snmp(ip=ip, comm='netnam2',timeout=2)
                hostname = snmp_device.getHostName()
                uptime = snmp_device.getUptime()
                object_id = snmp_device.getObjectID()
                vendor = snmp_device.getVendor()
                client_name = hostname[:2]               
                try:
                    client = Client.objects.get(name__contains=client_name)
                except Client.DoesNotExist:
                    # If not, create a new client with the original case of the client_name
                    client = Client.objects.create(name=client_name)
                    
                device, created = Device.objects.get_or_create(ip_address=ip, defaults={
                    'hostname': hostname,
                    'uptime': uptime,
                    'device_type': object_id,
                    'vendor': vendor,
                    'client': client
                })
                if not created:
                    device.hostname = hostname
                    device.uptime = uptime
                    device.device_type = object_id
                    device.vendor = vendor
                    devices_to_update.append(device)

                # Create a log entry for the successful SNMP scan
                log = Log(
                    device_id=device,
                    host=ip,
                    action="Ping alive and snmp scan",
                    status="Success",
                    time=datetime.now(tz=timezone.utc),
                    by = user,
                    messages="No Errors",
                    commandline="Ping alive and snmp scan for device: {}".format(device.hostname)
                )
                log.save()
                print("succuess snmp: {} ".format(device.ip_address))

            except Exception as e:
                logger.error("An error occurred: %s", str(e))
                # Create a log entry for the failed SNMP scan
                log = Log(
                    host=ip,
                    action="Ping alive and snmp scan",
                    status="Failed",
                    by = user,
                    time=datetime.now(tz=timezone.utc),
                    messages=str(e),
                    commandline="SNMP scan for IP: {}".format(ip)
                )
                log.save()
            live_ips.append(ip)
                
        # Use bulk_update to update all devices at once
            Device.objects.bulk_update(devices_to_update, fields=['hostname', 'uptime', 'device_type', 'vendor'])

        # Update progress using ProgressRecorder
        progress_recorder.set_progress(i, total_hosts, f'Ping and snmp {ip}')
    
    return live_ips