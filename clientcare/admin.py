from django.contrib import admin
from .models import Device, Log , Backup_file, TypeDeviceMapping, Client , Contact, WeeklyBackupData, AuditEntry
from import_export.admin import ImportExportModelAdmin


@admin.register(Log)
class LogAdmin(admin.ModelAdmin):
    list_filter = ['status','time']
    list_display = ['host','action','status','by','time']
    
@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_filter = ['device_type','vendor','status']
    search_fields = ['ip_address', 'hostname','device_type','vendor']  # Define the fields to be searched
    list_display = ['client','hostname','ip_address','device_type','vendor','status']

@admin.register(Backup_file)
class BackupAdmin(ImportExportModelAdmin):
    list_display = ['device', 'file_path']
    
    pass

@admin.register(TypeDeviceMapping)
class DevicetypeAdmin(ImportExportModelAdmin):
    pass

@admin.register(Client)
class ClientAdmin(ImportExportModelAdmin):
    search_fields = ['name', 'address']
    list_display = ['name', 'address'] 
    pass

@admin.register(Contact)
class ContactAdmin(ImportExportModelAdmin):
    pass

@admin.register(WeeklyBackupData)
class WeeklyBackupAdmin(ImportExportModelAdmin):
    pass

@admin.register(AuditEntry)
class AuditEntryAdmin(admin.ModelAdmin):
    list_display = ['action', 'username', 'ip','time']
    list_filter = ['action','time','ip','username']