from . import views
from django.urls import path, re_path
from django.contrib.auth import views as auth_views
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),
    path('configt/', views.configt, name='configt'),
    path('deviceslist/', views.deviceslist, name='deviceslist'),
    path('log/', views.log, name='log'),
    path('backupconf/<str:hostname>/', views.backupconf, name='backupconf'),
    path('verifcli/<int:id>', views.verifcli),
    path('add_device', views.add_device, name='add_device'),
    path('password_change/', auth_views.PasswordChangeView.as_view(), name="password_change"),
    path('password_change/done', auth_views.PasswordChangeDoneView.as_view(), name="password_change_done"),
    path('device/<str:main_hostname>/', views.device_detail, name='device_detail'),
    path('download/<str:file_path>/', views.download_file, name='download_file'),
    re_path(r'^download/(?P<file_path>.+)/$', views.download_file, name='download_file'),
    path('snmp-scan/<str:hostname>/', views.snmp_scan, name='snmp_scan'),
    path('delete_clients_with_no_devices/', views.delete_clients_with_no_devices, name='delete_clients_with_no_devices'),
    path('wizard/', views.wizard, name='wizard'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
