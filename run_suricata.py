import os
import sys
import subprocess
import time
import ctypes
from project_env import load_backend_env

load_backend_env()

SURICATA_BIN = r"C:\Program Files\Suricata\suricata.exe"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJECT_DIR, "suricata_sentinel.yaml")
SHIPPER_SCRIPT = os.path.join(PROJECT_DIR, "suricata_shipper.py")
WAZUH_BRIDGE_SCRIPT = os.path.join(PROJECT_DIR, "wazuh_live_bridge.py")
PYTHON_EXEC = sys.executable

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate():
    """Relaunches the current script as Administrator via UAC"""
    print("[*] Requesting Administrator privileges for Npcap packet capture...")
    params = f'"{os.path.abspath(__file__)}"'
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", PYTHON_EXEC, params, None, 1)
    if ret > 32:
        sys.exit(0)
    else:
        print("[!] UAC elevation was denied or failed.")
        sys.exit(1)

def main():
    if not is_admin():
        elevate()

    print("=======================================================")
    print("      SENTINELAI: SURICATA INTEGRATED IDS RUNNER       ")
    print("=======================================================")
    print(f"[*] Suricata Binary: {SURICATA_BIN}")
    print(f"[*] Configuration:   {CONFIG_FILE}")

    if not os.path.exists(SURICATA_BIN):
        print(f"[!] ERROR: Suricata binary not found at {SURICATA_BIN}")
        input("Press Enter to exit...")
        return

    # Ensure log directory exists
    logs_dir = os.path.join(PROJECT_DIR, "suricata_logs")
    os.makedirs(logs_dir, exist_ok=True)

    print("\n[1/3] Starting Suricata Engine in Promiscuous PCAP Mode...")
    suricata_cmd = [
        SURICATA_BIN,
        "-c", CONFIG_FILE,
        "--pcap"
    ]

    suricata_proc = subprocess.Popen(
        suricata_cmd,
        cwd=PROJECT_DIR,
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    print(f"[+] Suricata Engine running in dedicated console (PID: {suricata_proc.pid})")

    time.sleep(2)

    print("\n[2/3] Starting Real-Time Suricata EVE.JSON Alert Shipper...")
    shipper_cmd = [
        PYTHON_EXEC,
        SHIPPER_SCRIPT
    ]
    
    shipper_proc = subprocess.Popen(
        shipper_cmd,
        cwd=PROJECT_DIR
    )
    print(f"[+] Suricata Shipper running (PID: {shipper_proc.pid})")

    print("\n[3/3] Starting Live Wazuh/Windows Security Event (4625) Bridge...")
    wazuh_bridge_proc = subprocess.Popen(
        [PYTHON_EXEC, WAZUH_BRIDGE_SCRIPT],
        cwd=PROJECT_DIR
    )
    print(f"[+] Wazuh Live Event Bridge running (PID: {wazuh_bridge_proc.pid})")

    print("\n[*] SentinelAI Dual-Sensor Live Defense (Suricata NIDS + Wazuh EDR) is LIVE!")
    print("[*] Network attacks -> Suricata -> SentinelAI Dashboard")
    print("[*] Host login attacks (Event 4625) -> Wazuh Cloud + SentinelAI Dashboard simultaneously!")
    print("[*] Press Ctrl+C in this window to stop all sensors.\n")

    try:
        while True:
            if suricata_proc.poll() is not None:
                print(f"[!] Suricata engine exited with code: {suricata_proc.poll()}")
                break
            if shipper_proc.poll() is not None:
                print(f"[!] Shipper exited with code: {shipper_proc.poll()}")
                break
            if wazuh_bridge_proc.poll() is not None:
                print(f"[!] Wazuh Live Bridge exited with code: {wazuh_bridge_proc.poll()}")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Terminating Suricata, Shipper, and Wazuh Bridge...")
    finally:
        for proc in (suricata_proc, shipper_proc, wazuh_bridge_proc):
            try:
                proc.terminate()
            except Exception:
                pass
        print("[+] Clean shutdown complete.")

if __name__ == "__main__":
    main()
