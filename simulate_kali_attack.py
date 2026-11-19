import requests
import json
import time
import os
from project_env import load_backend_env

load_backend_env()

BASE_URL = "http://127.0.0.1:8000/api/v1/sensors"
WAZUH_TOKEN = os.environ.get("WAZUH_INGEST_TOKEN", "")

def simulate_suricata():
    print("[*] Simulating Kali Linux Nmap Scan (Suricata EVE Log)...")
    payload = {
        "timestamp": "2023-10-09T10:00:00.000000",
        "event_type": "alert",
        "src_ip": "192.168.1.100", # Kali IP
        "dest_ip": "10.0.0.1",     # Target IP
        "alert": {
            "signature": "ET SCAN Nmap OS Detection Probe",
            "severity": 2
        }
    }
    try:
        res = requests.post(f"{BASE_URL}/suricata", json=payload, headers={"X-API-Key": os.environ.get("SURICATA_INGEST_TOKEN", "")}, timeout=10)
        print("    ->", res.json())
    except Exception as e:
        print("    -> Error:", e)

def simulate_wazuh():
    print("[*] Simulating Kali Linux Hydra Brute Force (Wazuh Alert)...")
    payload = {
        "timestamp": "2023-10-09T10:05:00.000000",
        "rule": {
            "description": "sshd: multiple authentication failures",
            "level": 10
        },
        "data": {
            "srcip": "192.168.1.100"
        }
    }
    try:
        res = requests.post(f"{BASE_URL}/wazuh", json=payload, headers={"X-API-Key": WAZUH_TOKEN}, timeout=10)
        print("    ->", res.json())
    except Exception as e:
        print("    -> Error:", e)

if __name__ == "__main__":
    print("=========================================")
    print("  KALI LINUX ATTACK SIMULATOR (Phase 8)  ")
    print("=========================================\n")
    
    simulate_suricata()
    time.sleep(2)
    simulate_wazuh()
    
    print("\n[*] Attack simulation complete. Check the SentinelAI Dashboard!")
