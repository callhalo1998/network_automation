####################################################################################
### Anggi Agista
### email : agista.mailrespon@gmail.com
#####################################################################################
from import_export import resources
from .models import Device,Log,Backup_file

class DeviceResource(resources.ModelResource):
    class Meta:
        model = Device

class LogResource(resources.ModelResource):
    class Meta:
        model = Log

class Backup_fileResource(resources.ModelResource):
    class Meta:
        model = Backup_file