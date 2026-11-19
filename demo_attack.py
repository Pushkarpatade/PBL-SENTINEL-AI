import httpx
import json
import time
import subprocess
from datetime import datetime, timezone

BASE_URL = "http://localhost:8000"
WAZUH_TOKEN = "11f304a565ba04dcdb62690e6a54cfed4879b453d99b2c1b"
ATTACKER_IP = "194.26.29.112"
TARGET_HOST = "DESKTOP-AG44JE8"
TARGET_IP = "10.16.223.78"

def main():
    print("\n" + "="*70)
    print("      SENTINELAI: LIVE ATTACK & AUTONOMOUS DEFENSE DEMO     ")
    print("="*70)
    
    print("\n[1/4] SIMULATING ADVERSARY ATTACK ON ENDPOINT...")
    print(f" -> Target Machine:  {TARGET_HOST} ({TARGET_IP})")
    print(f" -> Adversary IP:    {ATTACKER_IP} (External Russian AS / Known Scanner)")
    print(f" -> Attack Vector:   MITRE ATT&CK T1110 (Windows Logon Failure / Event 4625)")
    
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    wazuh_payload = {
        "timestamp": now_iso,
        "rule": {
            "id": "60155",
            "level": 12,
            "description": f"Multiple Windows logon failures (Brute Force T1110) targeting Administrator on {TARGET_HOST}",
            "groups": ["windows", "authentication_failed", "brute_force", "pci_dss_10.2.4"],
            "mitre": {
                "id": ["T1110.001", "T1078"],
                "tactic": ["Credential Access", "Defense Evasion"]
            }
        },
        "agent": {
            "id": "001",
            "name": TARGET_HOST,
            "ip": TARGET_IP
        },
        "manager": {
            "name": "wazuh-manager-master-0"
        },
        "data": {
            "srcip": ATTACKER_IP,
            "dstip": TARGET_IP,
            "srcuser": "Administrator",
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "eventID": "4625",
                    "channel": "Security",
                    "computer": TARGET_HOST
                },
                "eventdata": {
                    "subStatus": "0xc000006a",
                    "logonType": "3",
                    "targetUserName": "Administrator",
                    "ipAddress": ATTACKER_IP,
                    "failureReason": "%%2313 - Unknown user name or bad password."
                }
            }
        }
    }

    print("\n[2/4] WAZUH AGENT SHIPPING TELEMETRY TO SENTINELAI...")
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                f"{BASE_URL}/api/v1/sensors/wazuh",
                headers={"X-API-Key": WAZUH_TOKEN},
                json=wazuh_payload
            )
            if resp.status_code != 200:
                print(f"Error ingesting: {resp.text}")
                return
            res_data = resp.json()
            incident_id = res_data["incident_id"]
            print(f" -> Telemetry Ingested! Normalized to Incident #{incident_id}")
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    print(f"\n[3/4] LANGGRAPH AI AGENT PERFORMING AUTONOMOUS INVESTIGATION...")
    print(" -> Correlating 24h historical alerts...")
    print(" -> Calling VirusTotal v3 Threat Intelligence API...")
    print(" -> Retrieving T1110 playbooks from Qdrant Vector Cloud...")
    print(" -> Synthesizing LLM Root-Cause Analysis & Containment Plan...")
    
    t0 = time.time()
    try:
        with httpx.Client(timeout=90.0) as client:
            resp = client.post(f"{BASE_URL}/api/v1/events/incidents/{incident_id}/investigate")
            t_inv = time.time() - t0
            if resp.status_code == 200:
                inv_data = resp.json()
                print(f" -> Investigation Complete in {t_inv:.2f}s!")
                print("\n" + "-"*60)
                print("AI EXECUTIVE SUMMARY:")
                print(inv_data.get("summary", "")[:350] + "...")
                print("-"*60)
            else:
                print(f"Investigation error: {resp.text}")
    except Exception as e:
        print(f"Investigation request error: {e}")

    print(f"\n[4/4] INCIDENT #{incident_id} IS READY FOR SOC APPROVAL!")
    print(f" 👉 Open Dashboard: http://localhost:5173")
    print(f" 👉 Review Incident #{incident_id} and click 'Execute Response' to quarantine {ATTACKER_IP}!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
