# This program accepts a defanged IP address and returns a report from virustotal
# Author: Jake Murray

import requests
import json
import ipaddress
import os

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
    report_dump = json.dumps(report, indent=4)
    # print(json.dumps(report, indent=4))
    print(f"URL Owner: {report["data"]["attributes"]["as_owner"]}")
    print(f"URL: {report["data"]["id"]}")
    with open("report.json", "w") as f:
        f.write(report_dump)
else:
    print(f"Error: {response.status_code}")
    print(response.text)


