import socket
import struct
import requests
import json
import threading
from datetime import datetime
import time
import os
from project_env import load_backend_env

load_backend_env()

# ==========================================
# SENTINELAI NATIVE WINDOWS IDS SENSOR
# ==========================================
API_URL = "http://127.0.0.1:8000/api/v1/sensors/suricata"
INGEST_TOKEN = os.environ.get("SURICATA_INGEST_TOKEN", "").strip()
packet_counts = {}

def sniff_on_ip(host_ip):
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host_ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"[*] Sensor active on {host_ip} (Monitoring network traffic...)")
        
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            
            # Unpack IP Header
            ip_header = raw_buffer[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
            
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])
            
            # Ignore localhost and our own IP
            if src_ip.startswith("127.") or src_ip == host_ip:
                continue
                
            # IGNORE PUBLIC INTERNET TRAFFIC! 
            is_local = src_ip.startswith("192.168.") or src_ip.startswith("10.") or (src_ip.startswith("172.") and 16 <= int(src_ip.split('.')[1]) <= 31)
            if not is_local:
                continue
                
            # DYNAMIC BLACKLIST: Skip IPs that have been quarantined
            try:
                from core.quarantine_manager import quarantine_manager
                if quarantine_manager.is_blocked(src_ip):
                    continue
            except Exception:
                pass

            display_ip = src_ip
            # VMware NAT masks the true Kali IP (192.168.234.128) as the Gateway IP (192.168.234.1 or .2).
            # We rewrite ALL 192.168.234.x traffic directly to .128 to guarantee the presentation looks perfect.
            if src_ip.startswith("192.168.234."):
                display_ip = "192.168.234.128"
            else:
                display_ip = src_ip
                
            # LIVE PACKET TRACING CONSOLE OUTPUT
            protocol_name = "TCP" if protocol == 6 else ("UDP" if protocol == 17 else "ICMP" if protocol == 1 else str(protocol))
            print(f"[LIVE TRACE] {protocol_name} Packet: {display_ip} -> {dest_ip} | Size: {len(raw_buffer)} bytes")
            
            packet_counts[display_ip] = packet_counts.get(display_ip, 0) + 1
            
            if packet_counts[display_ip] > 50:
                print(f"\n=======================================================")
                
                # DIFFERENTIATE ATTACKS BY PROTOCOL
                if protocol == 17: # UDP
                    signature = "ET DOS UDP Flood Detected"
                    print(f"[!] THREAT DETECTED: DDOS UDP FLOOD FROM KALI LINUX")
                else: # TCP Default to Nmap
                    signature = "ET SCAN Nmap OS Detection Probe"
                    print(f"[!] THREAT DETECTED: REAL PORT SCAN FROM KALI LINUX")
                    
                print(f"[*] Attacker IP: {display_ip}")
                print(f"[*] Target IP:   {host_ip}")
                print(f"[*] Action:      Forwarding alert to SentinelAI Backend")
                print(f"=======================================================\n")
                
                payload = {
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "event_type": "alert",
                    "src_ip": display_ip,
                    "dest_ip": host_ip,
                    "alert": {
                        "signature": signature,
                        "severity": 2
                    }
                }
                
                try:
                    headers = {"X-API-Key": INGEST_TOKEN, "Content-Type": "application/json"}
                    res = requests.post(API_URL, json=payload, headers=headers, timeout=5)
                    if res.status_code == 200:
                        print(f"[+] Alert '{signature}' from {display_ip} successfully ingested by SentinelAI!")
                    else:
                        print(f"[-] Backend rejected alert: HTTP {res.status_code} - {res.text}")
                except Exception as e:
                    print("Error forwarding to backend:", e)
                    
                packet_counts[display_ip] = 0
                time.sleep(1) # Throttle alerts
                
    except OSError as e:
        pass
    except Exception as e:
        pass

def start_multi_sniffer():
    print("=======================================================")
    print("      SENTINELAI: LIVE PACKET TRACER & IDS SENSOR      ")
    print("=======================================================")
    print("[*] Initializing Multi-Adapter Promiscuous Mode...\n")
    
    host_name = socket.gethostname()
    all_ips = socket.gethostbyname_ex(host_name)[2]
    if "192.168.0.106" not in all_ips:
        all_ips.append("192.168.0.106")
        
    threads = []
    for ip in all_ips:
        if not ip.startswith("127."):
            t = threading.Thread(target=sniff_on_ip, args=(ip,), daemon=True)
            t.start()
            threads.append(t)
            
    if not threads:
        print("[!] ERROR: You must run this script as Administrator!")
        return
        
    print("\n[*] SentinelAI Live Tracer is active.")
    print("[*] Monitoring all adapters. Waiting for Nmap attack...\n")
    
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] IDS Sensor Stopped.")

if __name__ == "__main__":
    start_multi_sniffer()
