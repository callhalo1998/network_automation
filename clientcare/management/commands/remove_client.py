# myapp/management/commands/update_data.py
from django.core.management.base import BaseCommand
from django.db import connections
from ipaddress import IPv4Network
from clientcare.models import Client
import json

        
class Command(BaseCommand):
    help = 'Update data from ClickHouse to PostgreSQL model'
        
    def handle(self, *args, **options):
        # Your ClickHouse query
        get_client = Client.objects.all()
        get_client.delete()

        return "Remove Clients successful"