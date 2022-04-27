################################# Port Scanner #################################

## This is a more general scanner,
# to scan port 80 only when asked, type the range: 80-80 

import nmap
#regex to ensure valid ip.
import re

# regex  pattern to verify valid IPv4 addresses.
ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

# regex  pattern to verify valid range.
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

# Initialising port numbers
port_min = 0
port_max = 65535

open_ports = []

# Ask user to input target ip and repeat if invalid.
while True:
    ip_input = input("\nEnter the target IPv4: ")
    if ip_pattern.search(ip_input):
        print("%s is valid" %(ip_input))
        break

while True:
    port_range = input("Enter the port ranges: (ex: 20-24): ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

nm = nmap.PortScanner()

# scan the ports
for port in range(port_min, port_max + 1):
    try:

        result = nm.scan(ip_input, str(port))
        # use tcp protocol
        port_status = (result['scan'][ip_input]['tcp'][port]['state'])
        print("Port %s is %s" %(port, port_status))
    except:
        print("Cannot scan port %s" %(port))
        

################################# PSDetect #################################
from scapy.all import sniff, TCP, IP
from datetime import datetime
import sys

scanned = {}

def packet_callback(packet):
    try:
        ip = packet[IP].src
        print('IP %s Scanned port %s' %(ip, packet[TCP].dport))
        if scanned.get(ip) is None:
            # scanned.get(any_ip)[0] is the time where the first port was scanned by that IP
            scanned[ip] = [datetime.now(), str(packet[TCP].dport)]


        elif int(scanned.get(ip)[len(scanned.get(ip)) -1]) == int(packet[TCP].dport) -1:
            # if the ip is already in dictionary, and the next port is the prev + 1, then add it to the list
            scanned.get(ip).append(str(packet[TCP].dport))
        
        
        if len(scanned.get(ip)) > 15 and (datetime.now() - scanned.get(ip).total_seconds() <= 300):
            # if the ip scanned 15 consecutive ports within 5 mins (300 secs), then report this ip address
            print('IP %s is port scanning' %str(scanned[packet[IP].src]))
            sys.exit(0)
    except:
        pass
    
# capture only TCP packets
sniff(filter= 'tcp', prn=packet_callback)


################################# PSDetect Cracker #################################
# PSDetect detects port scanners that scan ascending ports, so to crack it, we will implement a descending scan:
## This is a more general scanner,
# to scan port 80 only when asked, type the range: 80-80 
import nmap
#regex to ensure valid ip.
import re

# regex  pattern to verify valid IPv4 addresses.
ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

# regex  pattern to verify valid range.
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

# Initialising port numbers
port_min = 0
port_max = 65535

open_ports = []

# Ask user to input target ip and repeat if invalid.
while True:
    ip_input = input("\nEnter the target IPv4: ")
    if ip_pattern.search(ip_input):
        print("%s is valid" %(ip_input))
        break

while True:
    port_range = input("Enter the port ranges: (ex: 20-24): ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

nm = nmap.PortScanner()

# scan the ports
for port in range(port_max, port_min-1, -1):
    try:

        result = nm.scan(ip_input, str(port))
        # use tcp protocol
        port_status = (result['scan'][ip_input]['tcp'][port]['state'])
        print("Port %s is %s" %(port, port_status))
    except:
        print("Cannot scan port %s" %(port))