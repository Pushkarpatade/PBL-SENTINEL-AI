import requests
import json
import time
from datetime import datetime
import os
from project_env import load_backend_env

load_backend_env()

# ========================================================
# SENTINELAI: SURICATA EVE.JSON PIPELINE VERIFICATION TEST
# ========================================================

API_URL = "http://127.0.0.1:8000/api/v1/sensors/suricata"

# Real Suricata EVE JSON alert payload
sample_suricata_alert = {
    "timestamp": datetime.now().astimezone().isoformat(),
    "flow_id": 1948572019485,
    "in_iface": "\\Device\\NPF_{50931B9C-7E19-4B35-8C40-4C47B2D00604}",
    "event_type": "alert",
    "src_ip": "192.168.0.111",
    "src_port": 54832,
    "dest_ip": "192.168.0.123",
    "dest_port": 80,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2000002,
        "rev": 1,
        "signature": "ET SCAN Nmap OS Detection Probe",
        "category": "Attempted Information Leak",
        "severity": 2
    },
    "http": {
        "hostname": "192.168.0.123",
        "url": "/login",
        "http_user_agent": "Mozilla/5.0",
        "http_method": "GET",
        "protocol": "HTTP/1.1",
        "status": 200
    }
}

print("=======================================================")
print("      SENTINELAI: SURICATA INGESTION TEST RUNNER       ")
print("=======================================================")
print("[*] Simulating Suricata EVE.JSON alert ingestion into SentinelAI...")
print(f"[*] Signature: {sample_suricata_alert['alert']['signature']}")
print(f"[*] Attacker:  {sample_suricata_alert['src_ip']}")
print(f"[*] Target:    {sample_suricata_alert['dest_ip']}")

try:
    token = os.environ.get("SURICATA_INGEST_TOKEN", "")
    response = requests.post(
        API_URL,
        json=sample_suricata_alert,
        headers={"X-API-Key": token},
        timeout=10,
    )
    if response.status_code == 200:
        result = response.json()
        print("\n[+] SUCCESS: Suricata alert successfully ingested!")
        print(f"    Event ID: {result.get('event_id')}")
        print(f"    Sensor:   {result.get('sensor')}")
        print("[*] Open your SentinelAI Dashboard (http://localhost:5173) to see the new incident!")
    else:
        print(f"\n[!] Ingestion failed with status code {response.status_code}: {response.text}")
except Exception as e:
    print(f"\n[!] Connection error: {e}")
    print("[!] Ensure the backend server is running on http://127.0.0.1:8000")
