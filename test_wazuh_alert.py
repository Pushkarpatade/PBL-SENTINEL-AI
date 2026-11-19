import requests
import json
import time
from datetime import datetime
import os
from project_env import load_backend_env

load_backend_env()

# SentinelAI Wazuh Webhook URL
API_URL = "http://127.0.0.1:8000/api/v1/sensors/wazuh"

# Standard Wazuh JSON Alert Format
wazuh_payload = {
    "timestamp": datetime.now().astimezone().isoformat(),
    "rule": {
        "level": 12,
        "description": "Suspicious Authentication Failure Spike",
        "id": "5710",
        "mitre": {
            "id": ["T1110"],
            "tactic": ["Credential Access"]
        }
    },
    "agent": {
        "id": "001",
        "name": "WIN-SERVER-01",
        "ip": "192.168.0.222"
    },
    "manager": {
        "name": "wazuh-manager"
    }
}

print("=========================================")
print("  WAZUH SIEM ALERT INTEGRATION TESTER    ")
print("=========================================")
print("[*] Sending a synthetic Wazuh-shaped alert to SentinelAI (not a live Wazuh integration)...")

try:
    token = os.environ.get("WAZUH_INGEST_TOKEN", "")
    response = requests.post(API_URL, json=wazuh_payload, headers={"X-API-Key": token}, timeout=10)
    if response.status_code == 200:
        print("[+] SUCCESS! Wazuh alert successfully ingested by SentinelAI Backend.")
        print("[*] Check your React Dashboard to see the new incident!")
    else:
        print(f"[-] Failed with status code: {response.status_code}")
except Exception as e:
    print(f"[-] Connection Error: {e}")
