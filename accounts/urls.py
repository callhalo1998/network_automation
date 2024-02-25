from . import views
from django.urls import path, include

app_name = 'accounts'

urlpatterns = [
    
    path('login/', views.login_view, name='login'),
    path('', include('django.contrib.auth.urls')),
]