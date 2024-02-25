from django import forms
from django.forms import ModelForm
from django.contrib.auth.models import User
from .models import Device



#Createw a device form

class DeviceForm(ModelForm):
    class Meta:
        model = Device
        fields = ('ip_address','hostname')
        labels = {
        'ip_address':'',
        'hostname':'',
        }

        widgets = {
        'ip_address': forms.TextInput(attrs={'class':'form-inline' ,
        'minlength':'7',
        'maxlength':'15',
        'size':'16',
        'placeholder':'IP Address',
        'pattern':'^((\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$',
         }),
        'hostname': forms.TextInput(attrs={'class':'form-inline',
        'minlength':'1',
        'maxlength':'16',
        'size':'16',
        'placeholder':'Hostname',
         })
         }

    def clean_ipaddress(self): #validates the ip address fieled
        ip_address = self.cleaned_data.get('ip_address')    
        for instance in Device.objects.all():
            if instance.ip_address == ip_address:
                raise forms.ValidationError('IP address already exist !!!')
        return ip_address
    
