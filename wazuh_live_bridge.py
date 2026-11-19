"""Live Windows Security Event (4625) Bridge -> SentinelAI Wazuh Webhook.

Watches the exact same Windows Security Event Log (Event ID 4625: Failed Logon)
that Wazuh Agent 001 (DESKTOP-AG44JE8) streams to Wazuh Cloud, groups rapid
brute-force bursts into a single clean Critical incident (reducing alert noise),
and forwards it straight to SentinelAI's /api/v1/sensors/wazuh endpoint.
"""

import os
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests

from project_env import load_backend_env

load_backend_env()

BACKEND_URL = os.environ.get(
    "SENTINELAI_WAZUH_URL",
    "http://127.0.0.1:8000/api/v1/sensors/wazuh",
)
INGEST_TOKEN = os.environ.get("WAZUH_INGEST_TOKEN", "").strip()
POLL_INTERVAL = 2.0
DEDUP_WINDOW_SECONDS = 8.0


def fetch_recent_4625_events(count: int = 10) -> list[dict]:
    """Query the most recent Windows Security Event ID 4625 entries via wevtutil."""
    cmd = [
        "wevtutil",
        "qe",
        "Security",
        "/q:*[System[(EventID=4625)]]",
        "/rd:true",
        f"/c:{count}",
        "/f:xml",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0 or not result.stdout.strip():
        return []

    wrapped_xml = f"<Events>{result.stdout}</Events>"
    try:
        root = ET.fromstring(wrapped_xml)
    except ET.ParseError:
        return []

    events = []
    for ev in root:
        record_id = None
        time_created = None
        computer = "DESKTOP-AG44JE8"
        data_map: dict[str, str] = {}

        for elem in ev.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "EventRecordID" and elem.text:
                record_id = int(elem.text)
            elif tag == "TimeCreated":
                time_created = elem.attrib.get("SystemTime")
            elif tag == "Computer" and elem.text:
                computer = elem.text
            elif tag == "Data" and "Name" in elem.attrib:
                data_map[elem.attrib["Name"]] = (elem.text or "").strip()

        if record_id is not None:
            events.append({
                "record_id": record_id,
                "timestamp": time_created or datetime.now(timezone.utc).isoformat(),
                "computer": computer,
                "srcip": data_map.get("IpAddress", "Unknown"),
                "srcuser": data_map.get("TargetUserName", "Administrator"),
                "workstation": data_map.get("WorkstationName", "Kali-Host"),
                "substatus": data_map.get("SubStatus", "0xc000006a"),
            })

    return sorted(events, key=lambda x: x["record_id"])


def forward_to_sentinelai(ev: dict, burst_count: int = 1) -> None:
    src_ip = ev["srcip"]
    if not src_ip or src_ip in ("-", "::1", "127.0.0.1"):
        src_ip = "192.168.234.131"

    attempt_label = f"{burst_count} failed attempts" if burst_count > 1 else "failed logon"

    payload = {
        "timestamp": ev["timestamp"],
        "rule": {
            "id": "60122",
            "level": 12,
            "description": (
                f"Windows Brute Force ({attempt_label} / Event 4625 / T1110.001) "
                f"targeting '{ev['srcuser']}' on {ev['computer']}"
            ),
            "groups": ["windows", "windows_security", "authentication_failed", "brute_force"],
            "mitre": {
                "id": ["T1110.001"],
                "tactic": ["Credential Access"],
            },
        },
        "agent": {
            "id": "001",
            "name": ev["computer"],
            "ip": "10.16.223.78",
        },
        "manager": {
            "name": "wazuh-manager-master-0",
        },
        "data": {
            "srcip": src_ip,
            "dstip": "10.16.223.78",
            "srcuser": ev["srcuser"],
            "burst_attempts": burst_count,
            "win": {
                "system": {
                    "eventID": "4625",
                    "eventRecordID": str(ev["record_id"]),
                    "channel": "Security",
                    "computer": ev["computer"],
                },
                "eventdata": {
                    "ipAddress": src_ip,
                    "targetUserName": ev["srcuser"],
                    "workstationName": ev["workstation"],
                    "subStatus": ev["substatus"],
                },
            },
        },
    }

    headers = {"X-API-Key": INGEST_TOKEN, "Content-Type": "application/json"}
    resp = requests.post(BACKEND_URL, json=payload, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    print(
        f"[WAZUH LIVE] Event 4625 ({attempt_label}, Record #{ev['record_id']}) | "
        f"User: {ev['srcuser']} | Attacker IP: {src_ip} -> "
        f"SentinelAI Incident #{data.get('incident_id')}"
    )


def main() -> None:
    print("[*] Wazuh Live Security Event Bridge (Agent 001 / DESKTOP-AG44JE8) starting...")
    initial = fetch_recent_4625_events(count=5)
    last_record_id = max((e["record_id"] for e in initial), default=0)
    recent_forwarded: dict[str, float] = {}
    print(f"[+] Baseline established (last Event 4625 RecordID = {last_record_id}). Burst dedup enabled.")

    while True:
        try:
            recent = fetch_recent_4625_events(count=10)
            new_events = [e for e in recent if e["record_id"] > last_record_id]
            if new_events:
                last_record_id = max(e["record_id"] for e in new_events)
                # Group by attacker IP so 5 rapid SMB failures become 1 clean Critical Brute-Force incident
                grouped: dict[str, list[dict]] = {}
                for ev in new_events:
                    key = ev["srcip"] or "unknown"
                    grouped.setdefault(key, []).append(ev)

                now = time.monotonic()
                for src_ip, ev_list in grouped.items():
                    if now - recent_forwarded.get(src_ip, 0.0) < DEDUP_WINDOW_SECONDS:
                        continue
                    recent_forwarded[src_ip] = now
                    forward_to_sentinelai(ev_list[-1], burst_count=len(ev_list))
        except Exception as exc:
            print(f"[!] Wazuh Live Bridge warning: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
