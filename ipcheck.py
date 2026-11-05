# This program accepts a defanged IP address and returns a report from virustotal
# Author: Jake Murray

import requests
import json
import ipaddress

API_KEY = ""

# Get defanged IP from User
ip = input("Enter defanged IP address: ")

# Refang IP
ip = ip.replace("[.]", ".")

# Validate IP
ipaddress.ip_address(ip)

# Query VirusTotal
url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)

# display report
if response.status_code == 200:
    report = response.json()
    print(json.dumps(report, indent=4))

else:
    print(f"Error: {response.status_code}")
    print(response.text)


