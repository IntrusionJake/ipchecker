#!/usr/bin/env python3

# This program accepts a defanged IP address and returns a report from virustotal
# Author: Jake Murray

import requests
import json
import ipaddress
import os

API_KEY = os.getenv("VT_API_KEY")

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
    print("#################################################")
    print(f"IP Owner: {report["data"]["attributes"]["as_owner"]}")
    print(f"IP: {report["data"]["id"]}")
    print("\nAnalysis Findings: ")
    analysis_count = 0
    harmless_count = 0
    mal_count = 0
    sus_count = 0
    undet_count = 0
    timeout_count = 0
    for k, v in report['data']['attributes']['last_analysis_results'].items():
        analysis_count += 1
        if v['category'].lower() == 'harmless':
            harmless_count += 1
        elif v['category'].lower() == 'malicious':
            mal_count += 1
        elif v['category'].lower() == 'suspicious':
            sus_count += 1
        elif v['category'].lower() == 'undetected':
            undet_count += 1
        elif v['category'].lower() == 'timeout':
            undet_count += 1
        # print(f"{k}, Status: {v['category'].title()}")
    print(f"\n\tOut of {analysis_count} reports:\n\
\t{harmless_count} reports found this IP to be harmless\n\
\t{mal_count} reports found this IP to be malicious\n\
\t{sus_count} reports found this IP to be suspicious\n\
\t{timeout_count} reports timed out when checking IP\n\
\t{undet_count} reported this IP as undetected")
    print("#################################################")
    with open("report.json", "w") as f:
        f.write(report_dump)
else:
    print(f"Error: {response.status_code}")
    print(response.text)


