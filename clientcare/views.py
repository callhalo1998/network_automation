from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from datetime import datetime
from .models import Device,Log, Backup_file, Client
from .tasks import go_to_sleep,ping_subnets
import time
import paramiko
from django.contrib.auth.decorators import login_required
from .resources import DeviceResource
from paramiko import SSHClient, AutoAddPolicy
import os
from .forms import *
from django.contrib import messages
from django.contrib.auth import views as auth_views 
from django.urls import reverse
from itertools import groupby
from django.core.exceptions import PermissionDenied
from django.conf import settings
import mimetypes , json
from .utils import Device_snmp,ping, is_valid_ipv4,is_valid_ipv4_subnet,convert_devicetype, reset_ap
from django.db.models import Q ,Count
from django.template.loader import render_to_string
import logging, subprocess
import ipaddress
from django.utils import timezone
from celery.result import ResultBase
from netmiko import ConnectHandler
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

logger = logging.getLogger(__name__)

# Add new device
@login_required
def add_device(request):
    submitted = False
    if request.method == "POST":
        form = DeviceForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('add_device?submitted=True')
    else:
        form = DeviceForm
        if 'submitted' in request.GET:
            submitted = True
            
    form = DeviceForm
    return render(request, 'clientcare/add_device.html', {'form':form, 'submitted':submitted})

# Dashboard 
@login_required
def index(request):
    total_devices = Device.objects.values('hostname').distinct().count()
    log_activity = Log.objects.all()
    log_percentage = len(log_activity) * 100 / 10000
    percentage_style = 'width: {}%'.format(log_percentage)
    logs = Log.objects.all().order_by('-time')[:4]
    total_logs = len(logs)
    
    # Query to get unique hostnames and their respective vendors
    devices = Device.objects.values('hostname', 'vendor').distinct()

    # Count the occurrences of each vendor for unique hostnames
    vendors = {}
    for device in devices:
        vendor = device['vendor']
        if vendor:
            if vendor in vendors:
                vendors[vendor] += 1
            else:
                vendors[vendor] = 1


    # Step 3: Prepare Data for the Pie Chart
    vendor_labels = []
    vendor_counts = []
    for vendor, count in vendors.items():
        if vendor:  # Exclude null or empty vendors
            vendor_labels.append(vendor)
            vendor_counts.append(count)
    
    # Convert the Python lists to JSON format
    vendor_labels_json = json.dumps(vendor_labels)
    vendor_counts_json = json.dumps(vendor_counts)

    # Step 4: Add the pie chart data to the context
    context = {
        'total_devices': total_devices,
        'log_percentage': percentage_style,
        'logs': logs,
        'total_log': len(log_activity),
        'vendor_labels': vendor_labels_json,
        'vendor_counts': vendor_counts_json,
    }
    
    return render(request, 'clientcare/index.html', context)

# Select devices and vendors, input usr/pass to execute command
@login_required
def configt(request):
    #for configure terminal
    if request.method == "POST":
        result = []
        selected_devices_id = request.POST.getlist('cxb_devicecft')
        selected_command = request.POST.get('rbconft')
        cisco_command = request.POST['txt_cisco_commandcft'].splitlines()
        #user for excute command
        userlogin = request.POST['txt_username']
        #password for excute command
        passwordlogin = request.POST['txt_password']
        #port for excute command
        portlogin = request.POST['number_port'] 
        sleept = int(request.POST['paramtscft'])
        if selected_command == 'conft':
            for x in selected_devices_id:
                try:
                    alat = get_object_or_404(Device, pk=x)
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(hostname=alat.ip_address, username=userlogin, password=passwordlogin, port=portlogin, allow_agent=False)
                    conn = ssh_client.invoke_shell()
                    conn.send("conf t\n")
                    for cmd in cisco_command:
                        conn.send(cmd + "\n")
                        time.sleep(sleept)
                        log = Log(device_id=alat, host=alat.ip_address, action="Configure Terminal", status="Success",by = request.user, messages="No Errors", commandline=cmd)
                        log.save()
                except Exception as e:
                    log = Log(device_id=alat, host=alat.ip_address, action="Configure Terminal", status="Failed",by = request.user, messages=e, commandline=cisco_command)
                    log.save()
            return redirect('configt')
        if selected_command == 'mikrotik_command':
            for x in selected_devices_id:
                try:
                    alat = get_object_or_404(Device, pk=x)
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(hostname=alat.ip_address, username=userlogin, password=passwordlogin, port=portlogin, allow_agent=False)
                    for cmd in cisco_command:
                        stdin, stdout, stderr = ssh_client.exec_command(cmd + "\n")
                        time.sleep(sleept)
                        log = Log(device_id=alat, host=alat.ip_address, action="Configure Terminal", status="Success",by = request.user,  messages="No Errors", commandline=cmd)
                        log.save()
                except Exception as e:
                    log = Log(device_id=alat, host=alat.ip_address, action="Configure Terminal", status="Failed",by = request.user,  messages=e, commandline=cisco_command)
                    log.save()
            return redirect('configt')
        else:
            for x in selected_devices_id:
                try:
                    alat = get_object_or_404(Device, pk=x)
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(hostname=alat.ip_address, username=alat.username, password=alat.password, allow_agent=False)
                    conn = ssh_client.invoke_shell()
                    conn.send('terminal length 0\n')
                    for cmd in cisco_command:
                        result.append("Result on {}".format(alat.ip_address))
                        conn.send(cmd + "\n")
                        time.sleep(sleept)
                        output = conn.recv(65535)
                        result.append(output.decode())
                        log = Log(device_id=alat, host=alat.ip_address, action="Show Verification", status="Success", by = request.user, messages="No Errors", commandline=cmd)
                        log.save()
                except Exception as e:
                    log = Log(device_id=alat, host=alat.ip_address, action="Show Verification", status="Failed", by = request.user, messages=e, commandline=cisco_command)
                    log.save()
            result = "\n".join(result)
            return render(request, 'clientcare/verify_result.html', {'result':result})
         
    else:
        devi = Device.objects.all()
        logsrec = Log.objects.all().order_by('-time')[:4]
        context = {
            'total_devices': len(devi),
            'devi': devi,
            'total_log': len(logsrec),
            'mode': 'Command Line',
            'logs': logsrec
        }
        return render(request, 'clientcare/conft.html', context)

# Show list of devices base on hostname retrieved from snmp
@login_required
def deviceslist(request):
    query = request.GET.get('q')
    clients = Client.objects.all()
    if query:
        clients = clients.filter(Q(device__hostname__icontains=query) | Q(device__ip_address__icontains=query)).distinct()
        
    clients_per_page = 40
    paginator = Paginator(clients, clients_per_page)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Add devices to each client in the clients list
    for client in page_obj:  # Loop through the paginated clients
        client.devices = Device.objects.filter(client=client)
        client.total_devices = client.devices.values('hostname').distinct().count()

    logsrec = Log.objects.all().order_by('-time')[:4]
    context = {
        'total_clients': len(clients),
        'clients': page_obj,
        'total_log': len(logsrec),
        'logs': logsrec,
        'search_query': query,
    }
    return render(request, 'clientcare/devices-list.html', context)


# Details information about devices such as hostname, uptime, status, vendor, model and search function.
@login_required
def device_detail(request, main_hostname):
    query = request.GET.get('q')
    devices = Device.objects.filter(hostname__startswith=main_hostname)
    request.session['main_hostname'] = main_hostname
    if query:
        devices = devices.filter(Q(hostname__icontains=query) | Q(ip_address__icontains=query) | Q(status__icontains=query) | Q(vendor__icontains=query) | Q(device_type__icontains=query)).distinct()
    unique_hostnames = set(device.hostname for device in devices)
    for device in devices:
        device.backup_files = Backup_file.objects.filter(device=device)
        response_time = ping(device.ip_address, timeout=0.2)
        if response_time is None or response_time is False:
            device.status = 'Timeout'
            
        else:
            device.status = 'Online'
        device.save()

    logsrec = Log.objects.all().order_by('-time')[:4]
    context = {
        'main_hostname': main_hostname,
        'hostnames': unique_hostnames,  
        'devices': devices,
        'search_query': query,
        'total_log': len(logsrec),
        'logs': logsrec,
    }
        
    return render(request, 'clientcare/device-detail.html', context)

# Record logging
@login_required
def log(request):
    logsrec = Log.objects.all().order_by('-time')[:4]
    logs = Log.objects.all().order_by('-time')[:30]
    context = {
        'logs': logsrec,
        'total_log': len(logsrec),
        'logs1': logs
    }
    return render(request, 'clientcare/log.html', context)


@login_required
def verifcli(request, id):
    #for verify cli
    logcli = Log.objects.get(pk = id)
    return render(request, 'clientcare/verify_cli.html', {'logcli': logcli})
        
# Choose backup or reset device's configuration
@login_required
def backupconf(request,hostname):
    if request.method == "POST":
        selected_function = request.POST.get('deviceconf')
        devices = Device.objects.get(hostname=hostname)
        client = request.session.get('main_hostname')
        try: 
            info_device = {'device_type':convert_devicetype(devices.vendor),
                        'host':devices.ip_address, 
                        'username':'your_host', 
                        'password':'your_password',
                        'secret': 'your_secret',
                        'port':'22'}
            if devices.vendor == "RuckusAP":
                pass
            elif devices.vendor == "Mikrotik":
                info_device['port'] = '2294'
                ssh_client = ConnectHandler(**info_device)
            else:
                ssh_client = ConnectHandler(**info_device)
                
            logger.info(f'Success login to device {devices.hostname} by {request.user}')
        except Exception as e:
            messages.error(request, "Error login to {}".format(e))
            log = Log(device_id=devices, host=devices.ip_address, action="Login", status="Failed", by = request.user, messages=str(e))
            log.save()
            logger.error(f'Failed login to device {devices.hostname} by {request.user}')
            return HttpResponseRedirect('/clientcare/device/' + client)
            
        try:
            if selected_function == 'backupconf':  
                try:
                    if devices.vendor == 'Cisco' or devices.vendor == 'cisco_s300':
                        ssh_client.enable()
                        command_backup = 'show running-config'
                    elif devices.vendor == 'Mikrotik':
                        command_backup = '/export'
                    elif devices.vendor == 'Ruckus' or devices.vendor == 'Aruba':
                        command_backup = 'show running-config'
                    backup_data = ssh_client.send_command(command_backup)
                    time.sleep(2)
                    # Save backup data to a file in the database folder
                    backup_filename = f"{devices.hostname}_{datetime.now().strftime('%d:%m:%Y')}.txt"
                    backup_path = os.path.join('backups', backup_filename)
                    
                    with open(backup_path, 'w') as backup_file:
                        backup_file.write(backup_data)
                        
                    backup_file_obj = Backup_file(device=devices, success=True, file_path=backup_path)
                    backup_file_obj.save()
                    
                    log = Log(device_id=devices, host=devices.ip_address, action="Backup Configurations", status="Success", by = request.user, messages="No Errors", commandline=command_backup)
                    log.save()
                    ssh_client.disconnect()
                    logger.info(f'Success Backup Configuration {devices.hostname} by {request.user}')
                    messages.success(request, "Backup Success")
                    
                except Exception as e:
                    log = Log(device_id=devices, host=devices.ip_address, action="Backup Configurations", status="Failed", by = request.user, messages=str(e), commandline=command_backup)
                    log.save()
                    messages.error(request, "Backup Fail {}".format(e))
                    logger.error(f'Failed Backup Configuration {devices.hostname} by {request.user}')
                    HttpResponseRedirect('/clientcare/device/' + client)
                
            if selected_function == 'resetconf': 
                try:
                    if devices.vendor == 'Cisco' or devices.vendor == "cisco_s300":
                        if devices.device_type == 'CBS 350':
                            ssh_client.enable()
                            ssh_client.send_command("delete startup-config",expect_string="delete startup-config")
                            ssh_client.send_command_timing("y", delay_factor=1)
                            ssh_client.send_command_timing("reload in 1", delay_factor=1)
                            ssh_client.send_command_timing("y", delay_factor=1)
                            messages.success(request, "Reset Success after 1 minute")                   
                        else:
                            ssh_client.send_command("delete flash:vlan.dat",expect_string="[vlan.dat]?")
                            ssh_client.send_command_timing("\n", delay_factor=1)
                            ssh_client.send_command_timing("\n", delay_factor=1)
                            ssh_client.send_command("erase startup-config", expect_string="[confirm]") 
                            ssh_client.send_command_timing("\n", delay_factor=1)
                            ssh_client.send_command("reload", expect_string="[confirm]")
                            ssh_client.send_command_timing("\n", delay_factor=1)
                    elif devices.vendor == 'Ruckus':
                        ssh_client.send_command("erase startup-config")
                        ssh_client.send_command("reload after 00:00:1")
                        messages.success(request, "Reset Success after 1 minute")
                    elif devices.vendor == 'Aruba':
                        ssh_client.send_command("erase all zeroize", expect_string="(y/n)?")
                        ssh_client.send_command("y")
                    elif devices.vendor == "RuckusAP":
                        reset_ap(devices.ip_address)
                    elif devices.vendor == "Mikrotik":
                        ssh_client.send_command("/system reset-configuration no-defaults=yes",expect_string="[y/N]")
                        ssh_client.send_command("y")
                    ssh_client.disconnect()
                    # elif devices.vendor == 'Aruba':
                    log = Log(device_id=devices, host=devices.ip_address, action="Reset Configurations", status="Success",  by = request.user, messages="No Errors")
                    log.save()
                    logger.info(f'Success Reset Configuration {devices.hostname} by {request.user}')
                    messages.success(request, "Reset Success")
                except Exception as e:
                    messages.success(request, "Reset Success")
                    logger.error(f'Failed Reset Configuration {devices.hostname} by {request.user}')
                    HttpResponseRedirect('/clientcare/device/' + client)
                
                    
        except Exception as e:
            log = Log(device_id=devices, host=devices.ip_address, action="Error send command to Device", status="Failed",  by = request.user, messages=str(e))
            log.save()

    return HttpResponseRedirect('/clientcare/device/' + client)


# Allow user download backup file from dashboard 
@login_required
def download_file(request, file_path):
    # Get the absolute file path
    absolute_file_path = os.path.join(settings.MEDIA_ROOT, file_path)

    # Check if the file exists
    if os.path.exists(absolute_file_path):
        # Open the file in binary mode for reading
        with open(absolute_file_path, 'rb') as file:
            # Set the appropriate content type for the response
            response = HttpResponse(file.read(), content_type='application/octet-stream')
            # Set the Content-Disposition header to force download
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(absolute_file_path)}"'

        # Add a JavaScript snippet to initiate the file download
        response['Content-Type'] = 'text/html'
        response.write(f'<script>window.location.href = "{request.build_absolute_uri()}";</script>')

        return response

    # If the file doesn't exist, return a 404 response
    return HttpResponse('File not found', status=404)

# Snmp to retrieve information
@login_required
def snmp_scan(request, hostname,timeout=5):
    community_string = 'netnam2'
    devices = Device.objects.filter(hostname=hostname)
    devices_to_update = []

    for device in devices:
        ip_address = device.ip_address
        try:
            snmp_device = Device_snmp(ip=ip_address, comm=community_string,timeout=timeout)
            new_hostname = snmp_device.getHostName()
            uptime = snmp_device.getUptime()
            object_id = snmp_device.getObjectID()
            vendor = snmp_device.getVendor()
            # Check if the client with the first 6 characters of the new_hostname exists
            client_name = new_hostname[:2]
            try:
                client = Client.objects.filter(name__contains=client_name)
            except Client.DoesNotExist:
                # If not, create a new client with the original case of the client_name
                client = Client.objects.create(name=client_name)

            if device.hostname != new_hostname:
                # Situation 3: Update the client for the device with a changed hostname
                device.client = client
            
            # Update the device attributes
            device.hostname = new_hostname
            device.uptime = uptime
            device.device_type = object_id
            device.vendor = vendor
            devices_to_update.append(device)
            # Create a log entry for the successful SNMP scan
            log = Log(
                device_id=device,
                host=device.ip_address,
                action="SNMP Scan",
                status="Success",
                
                by = request.user,
                messages="No Errors",
                commandline="SNMP scan for device: {}".format(device.hostname)
            )
            log.save()

        except Exception as e:
            # Create a log entry for the failed SNMP scan
            log = Log(
                device_id=device,
                host=device.ip_address,
                action="SNMP Scan",
                status="Failed",
                
                messages=str(e),
                by = request.user,
                commandline="SNMP scan for device: {}".format(device.hostname)
            )
            log.save()

            # Return failure response
            return JsonResponse({
                'success': False,
                'message': 'Unreachable Or Deny SNMP On Device'
            })

    Device.objects.bulk_update(devices_to_update, fields=['client', 'hostname', 'uptime', 'device_type', 'vendor'])
    return JsonResponse({
        'success': True,
        'message': 'SNMP successful. New information has been updated'
    })

@login_required
def delete_clients_with_no_devices(request):
    clients_without_devices = Client.objects.filter(device__isnull=True)
    clients_without_devices.delete()
    return HttpResponseRedirect('/clientcare/deviceslist/')


@login_required
def connect_mikrotik(request):
    if request.method == 'POST':
        mikrotik_ip = request.POST['mikrotik_ip']
        ssh_password = request.POST['ssh_password']
        if not is_valid_ipv4(mikrotik_ip):
            messages.add_message(request,messages.ERROR, "Invalid IP address format.")
        else:
            response_time = ping(mikrotik_ip, timeout=2)  # Change the timeout value as needed
            if response_time is None or response_time is False:
                messages.error(request, "Ping timeout to {}".format(mikrotik_ip))
                pass
                return HttpResponseRedirect('/clientcare/wizard/')
            else:    
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    try:
                        ssh_client.connect(
                            hostname=mikrotik_ip,
                            username=request.user.username,
                            password=ssh_password,
                            port=2294
                        )
                    except paramiko.ssh_exception.NoValidConnectionsError:
                        messages.error(request, "Error port SSH, default port: 2294")
                        return HttpResponseRedirect('/clientcare/wizard/')
                
                    command = '/interface pptp-client add connect-to=119.17.252.90 disabled=no name=pptp-out1 user=ets password=ets'
                    stdin, stdout, stderr = ssh_client.exec_command(command)
                    ssh_client.close()
                    try:
                        snmp_device = Device_snmp(ip=mikrotik_ip, comm='netnam2', timeout=2)
                        hostname = snmp_device.getHostName()
                    except Exception as e:
                        messages.error(request, "Can't snmp, please check SNMP your on device")      
                        return HttpResponseRedirect('/clientcare/wizard/')
            
                    messages.success(request, "Successfully connected to {}".format(hostname))
                    return HttpResponseRedirect('/clientcare/wizard/')
                except paramiko.AuthenticationException:
                    messages.error(request, "Error Authentication, Please check again")
                    return HttpResponseRedirect('/clientcare/wizard/')
            
    return HttpResponseRedirect('/clientcare/wizard/')

@login_required
def restart_network(request):
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-networkd'])
        messages.success(request, "Success Restart Network" )
        return HttpResponseRedirect('/clientcare/wizard/')
    except Exception as e:
        messages.success(request, "Error Restart Network" )
        log = Log( messages=str(e))
        log.save()
        return HttpResponseRedirect('/clientcare/wizard/')
        
    
@login_required
def ping_and_snmp(request):
    try:
        subnets = request.POST['subnet']
        if not is_valid_ipv4_subnet(subnets):
            messages.error(request, "Invalid Subnets format.")
            return HttpResponseRedirect('/clientcare/wizard/')
        alive_ips = ping_subnets.delay(subnets,request.user.id)
        return HttpResponseRedirect(reverse('wizard') + f'?task_id={alive_ips.task_id}')
    
    except Exception as e:
        log = Log(action="Ping range subnet",time=timezone.now(),messages=str(e))
        log.save()
        return HttpResponseRedirect('/clientcare/wizard/')
    
@login_required
def wizard(request):
    task_id = request.GET.get('task_id')  # Get the task_id from the URL parameters
    if request.method == 'POST':
        step = int(request.POST['step'])
        if step == 1:   
            return connect_mikrotik(request)
        elif step == 2:
            return restart_network(request)
        elif step == 3:
            # You can use the 'task_id' here as needed
            return ping_and_snmp(request)
        else:
            return JsonResponse({'success': False, 'message': 'Invalid step'})

    return render(request, 'clientcare/wizard.html', {'task_id': task_id})


