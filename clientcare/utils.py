import subprocess
import os
import ipaddress
from ping3 import ping, verbose_ping
import multiprocessing
import value
import pexpect

def is_valid_ipv4(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except ValueError:
        return False


def is_valid_ipv4_subnet(subnet):
    try:
        ip, prefix = subnet.split('/')
        if not is_valid_ipv4(ip):
            return False
        prefix = int(prefix)
        if not 0 <= prefix <= 32:
            return False
        ipaddress.IPv4Network(subnet, strict=False)  # Check if the subnet is valid
        return True
    except ValueError:
        return False

def ping_subnets(subnet):
    live_ips = []
    network = ipaddress.ip_network(subnet)
    for ip in network.hosts():
        ip = str(ip)
        response_time = ping(ip, timeout=1)  # Change the timeout value as needed
        if response_time is None or response_time is False:
            pass
        else:
            live_ips.append(ip)
            print(ip)
    return live_ips


def reset_ap(ip):
    try:
        # Spawn an SSH session
        child = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no {ip}')

        # Expect login prompt and provide credentials
        child.expect('Please login:')
        child.sendline('netnam')

        # Expect password prompt and provide password
        child.expect('password :')
        child.sendline('Meeting-netn@m123')

        # Expect the normal AP prompt
        child.expect('rkscli:')

        # Send the reboot command
        child.sendline('set factory')

        # Expect the success message
        child.expect('OK')
        
        child.sendline('reboot')
        child.expect('OK')     
        
        # Print the output before the success message
        print(child.before.decode())

    except pexpect.exceptions.ExceptionPexpect as e:
        print(f"Error: {e}")

    finally:
        # Close the SSH connection
        child.close()

    return None


class Device_snmp:
    def __init__(self, ip, comm,timeout):
        self.ip = ip
        self.comm = comm
        self.timeout = timeout

    def getUptime(self):
        self.uptime = subprocess.run([f'snmpwalk -v2c -c {self.comm} {self.ip} sysUpTimeInstance -Ovq'],
                                     shell=True, capture_output=True, text=True,timeout=self.timeout).stdout.split('\n')[0]
        # uptime format is d:h:m:s
        uptimeStr = self.uptime.split(':')
        days = uptimeStr[0]
        hours = uptimeStr[1]
        minutes = uptimeStr[2]
        seconds = uptimeStr[3].split('.')[0]
        uptimeFormat = f'{days}d,{hours}h:{minutes}m:{seconds}s'
        return uptimeFormat

    def getHostName(self):
        self.hostName = subprocess.run([f'snmpwalk -v2c -c {self.comm} {self.ip} 1.3.6.1.2.1.1.5 -Ovq'],
                                       shell=True, capture_output=True, text=True,timeout=self.timeout).stdout.split('\n')[0]
        return self.hostName

    def getObjectID(self):
        self.ObjectID = subprocess.run([f'snmpwalk -v2c -c {self.comm} {self.ip} sysObjectID -Ovq'],
                                       shell=True, capture_output=True, text=True,timeout=self.timeout).stdout.split('\n')[0].split('enterprises')[-1]


            
        if self.ObjectID == '.14988.1':
            self.ObjectID = subprocess.run([f'snmpwalk -v2c -c {self.comm} {self.ip} sysDescr.0 -Ovq'],
                                       shell=True, capture_output=True, text=True,timeout=self.timeout).stdout.split('\n')[0].split('RouterOS ')[-1]
            deviceType = self.ObjectID
            
        elif self.ObjectID == ".25053.3.1.4":
            deviceType = self.ObjectID
            
        else:
            for key, value in type_devices.items():
                if self.ObjectID == key:
                    deviceType = value[0]
                    break
                else:
                    deviceType = 'NA'
        #deviceType = get_device_type_db(self.ObjectID)[0][0]

        return deviceType
    
    
    def getVendor(self):
        self.ObjectID = subprocess.run([f'snmpwalk -v2c -c {self.comm} {self.ip} sysObjectID -Ovq'],
                                       shell=True, capture_output=True, text=True,timeout=self.timeout).stdout.split('\n')[0].split('enterprises')[-1]


        for key, value in type_devices.items():
            if self.ObjectID == key:
                vendor = value[-1]
                break
            else:
                vendor = 'NA'

        return vendor


#mapping device vendor to device_type netmiko
def convert_devicetype(vendor):
    for key, value in device_type_netmiko.items():
        if vendor == key:
            vendor = value
        else:
            pass
        
    return vendor

device_type_netmiko = {'Cisco':'cisco_ios',
                       'Ruckus':'ruckus_fastiron',
                       'Aruba':'hp_procurve',
                       'Mikrotik':'mikrotik_routeros',
                       }

    
type_devices = {'.2636.1.1.1.4.82.17': ('QFX5110-48S-4C', 'Juniper'),
                '.9.1.695': ('C2960-48TC-L', 'Cisco'),
                '.9.1.2959':('C1000','Cisco'),
                '.17713.21': ('Cambium-Wifi', 'Radio'),
                '.9.1.1191': ('C1900', 'Cisco'),
                '.9.1.1047': ('C1900', 'Cisco'),
                '.9.1.1752': ('C2960+24TC-L', 'Cisco'),
                '.9.1.694': ('C2960-24TC-L', 'Cisco'),
                '.9.1.716': ('C2960-24TT-L', 'Cisco'),
                '.9.1.1365': ('C2960C-8TC-L', 'Cisco'),
                '.9.1.2137': ('C2960CX-8TC-L', 'Cisco'),
                'C2960X-48TS-L': ('C2960X-48TS-L', 'Cisco'),
                'C2960S-24TS-L': ('C2960S-24TS-L', 'Cisco'),
                '.9.1.1257': ('C2960S-24TS-S', 'Cisco'),
                '.9.1.615': ('C3560G-24TS-S', 'Cisco'),
                '.9.1.617': ('C3560G-48TS-S', 'Cisco'),
                '.9.1.1226': ('C3560X-24T-L', 'Cisco'),
                '.9.1.222': ('C7200', 'Cisco'),
                '.9.1.1251': ('ME-3600X-24TS-M', 'Cisco'),
                '.9.1.1117': ('SACS', 'Cisco'),
                '.9.6.1.87.24.1': ('SF200-24', 'Cisco'),
                '.9.6.1.87.48.1': ('SF200-48', 'Cisco'),
                '.9.6.1.82.24.1': ('SF300-24', 'Cisco'),
                '.9.6.1.82.48.1': ('SF300-48', 'Cisco'),
                '.9.6.1.82.8.1': ('SF302-08', 'Cisco'),
                '.9.6.1.82.8.2': ('SF302-08P', 'Cisco'),
                '.9.6.1.83.10.1': ('SG300-10', 'Cisco'),
                '.9.6.1.83.20.1': ('SG300-20', 'Cisco'),
                '.9.6.1.83.28.1': ('SG300-28', 'Cisco'),
                '.9.6.1.83.28.5': ('SG300-28SFP', 'Cisco'),
                '.9.6.1.95.28.8': ('SG350-28SFP', 'Cisco'),
                '.9.6.1.81.28.1': ('SG500-28', 'Cisco'),
                '.25506.11.1.94': ('A3600-24-SFP', 'HP'),
                '.8886.6.140': ('ISCOM2128EA-MA-AC', 'Raisecom'),
                '.8886.6.122': ('ISCOM2828F-AC', 'Raisecom'),
                '.8886.6.97': ('ISCOM2924GF-4GE-AC', 'Raisecom'),
                '.40614': ('Controller-SNMP', 'IStars'),
                '.2636.1.1.1.2.117': ('ACX2200', 'Juniper'),
                '.2636.1.1.1.4.131.1': ('EX3400-24T', 'Juniper'),
                '.2636.1.1.1.2.92': ('EX4550-32F', 'Juniper'),
                '.2636.1.1.1.2.97': ('MX104', 'Juniper'),
                '.2636.1.1.1.2.90': ('MX80', 'Juniper'),
                '.2636.1.1.1.2.110': ('VRR', 'Juniper'),
                '.890.1.5.8.57': ('MES3500-24F', 'Zyxel'),
                '.311.1.1.3.1.3': ('Server-Windows-2012', 'Server-Windows'),
                '.311.1.1.3.1.2': ('Server-Windows-2016', 'Server-Windows'),
                '.38783': ('Controller-SNMP', 'Teracom'),
                '.40614': ('iStars_SWV052', 'IStars'),
                '.6876.4.1': ('VMware-ESXi', 'VMware'),
                '.12780.5.6328': ('MEN6328', 'Voltek'),
                'CCR1009-7G-1C-1S+': ('CCR1009-7G-1C-1S+', 'Mikrotik'),
                'CCR1016-12G': ('CCR1016-12G', 'Mikrotik'),
                'CCR1036-12G-4S': ('CCR1036-12G-4S', 'Mikrotik'),
                'CCR1036-8G-2S+': ('CCR1036-8G-2S+', 'Mikrotik'),
                'RB1100AHx2': ('RB1100AHx2', 'Mikrotik'),
                '.8072.3.2.10': ('Server-Linux', 'Linux'),
                'netSnmpAgentOIDs.10': ('Server-Linux', 'Linux'),
                '.2636.1.1.1.2.86': ('SRX550', 'Juniper'),
                'RB1100x4': ('RB1100x4', 'Mikrotik'),
                '.9.6.1.95.20.1': ('SG350-20', 'Cisco'),
                '.8886.6.243': ('ISCOM2624GF-4C-HI-AC', 'Raisecom'),
                '.8886.6.134': ('ISCOM2948GF-4C-AC/D', 'Raisecom'),
                '.14988.1': ('Mikrotik', 'Mikrotik'),
                '.9.1.2068' : ('Cisco ISR 4331','Cisco'),
                '.9.1.1208': ('C2960S-24TS-L', 'Cisco'),
                '.9.1.2361': ('2960L-8TS-LL', 'Cisco'),
                '.9.1.2159': ('ASR920', 'Cisco'),
                '.9.1.1046': ('C2900', 'Cisco'),
                '.3309.1.4': ('Nomadix EG', 'Nomadix'),
                '.9.1.620': ('C1841', 'Cisco'),
                '.9.6.1.95.28.6': ('SG350-28MP-28', 'Cisco'),
                '.1991.1.3.64.3.1.1.1':('ICX7150-C12-POE','Ruckus'),
                '.1991.1.3.64.1.2.1.2':('ICX7150-C24-POE','Ruckus'),
                '.11.2.3.7.11.182.20':('2540-24G-PoE+','Aruba'),
                '.25053.3.1.4.89':('Ruckus','RuckusAP'),
                '.25506.11.1.164':('HPE-1920S','HP'),
                '.9.6.1.1004.28.5':('CBS 350','cisco_s300'),
                '.9.1.516':('Cisco 3750','Cisco'),
                '.9.1.1757': ('C2960-TC-S','Cisco')}