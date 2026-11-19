"""Forward Suricata EVE alerts with false-positive filtering, deduplication, and Wazuh Zero-Day sync."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

from project_env import load_backend_env

load_backend_env()


PROJECT_DIR = Path(__file__).resolve().parent
EVE_LOG_PATH = Path(os.environ.get(
    "SURICATA_EVE_PATH",
    str(PROJECT_DIR / "suricata_logs" / "eve.json"),
))
BACKEND_URL = os.environ.get(
    "SENTINELAI_SURICATA_URL",
    "http://127.0.0.1:8000/api/v1/sensors/suricata",
)
INGEST_TOKEN = os.environ.get("SURICATA_INGEST_TOKEN", "").strip()
CHECKPOINT_PATH = Path(os.environ.get(
    "SURICATA_CHECKPOINT_PATH",
    str(EVE_LOG_PATH.with_suffix(EVE_LOG_PATH.suffix + ".sentinelai-offset.json")),
))

# Local host / link-local / browser self-traffic IPs suppressed to eliminate false positives
IGNORED_EXACT_IPS = {
    "10.16.223.78",
    "192.168.234.1",
    "192.168.99.1",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}
IGNORED_PREFIXES = (
    "169.254.",
    "224.",
    "239.",
    "fe80:",
    "ff02:",
    "2409:",
    "10.255.",
)

DEDUP_WINDOW_SECONDS = 10.0


def is_noise_source(src_ip: str | None) -> bool:
    if not src_ip:
        return True
    ip = src_ip.strip().lower()
    if ip in IGNORED_EXACT_IPS:
        return True
    return any(ip.startswith(prefix) for prefix in IGNORED_PREFIXES)


def sync_zeroday_to_wazuh_eventlog(src_ip: str, signature: str) -> None:
    """Write a Windows Application Error event (ID 999) so Wazuh Agent 001 ships it live to Wazuh Cloud."""
    try:
        desc = (
            f"SentinelAI ZERO-DAY ALERT: {signature} detected from attacker IP {src_ip} "
            f"targeting DESKTOP-AG44JE8. Cross-correlated with Suricata NIDS & IsolationForest ML."
        )
        subprocess.run(
            [
                "eventcreate",
                "/L", "APPLICATION",
                "/T", "ERROR",
                "/SO", "SentinelAI-ZeroDay",
                "/ID", "999",
                "/D", desc,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        print(f"[+] Synced Zero-Day alert to Windows Event Log -> Wazuh Cloud (Event ID 999, IP: {src_ip})")
    except Exception as exc:
        print(f"[!] Optional Wazuh Event Log sync skipped: {exc}")


def load_checkpoint(file_id: int, file_size: int) -> int:
    try:
        checkpoint = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
        if checkpoint.get("file_id") == file_id:
            offset = int(checkpoint.get("offset", 0))
            return offset if 0 <= offset <= file_size else 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return 0


def save_checkpoint(file_id: int, offset: int) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CHECKPOINT_PATH.with_suffix(CHECKPOINT_PATH.suffix + ".tmp")
    temporary.write_text(json.dumps({"file_id": file_id, "offset": offset}), encoding="utf-8")
    os.replace(temporary, CHECKPOINT_PATH)


def deliver_alert(event: dict) -> None:
    headers = {"X-API-Key": INGEST_TOKEN, "Content-Type": "application/json"}
    last_error = None
    for attempt in range(1, 6):
        try:
            response = requests.post(BACKEND_URL, json=event, headers=headers, timeout=10)
            response.raise_for_status()
            return
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 5:
                time.sleep(min(2 ** (attempt - 1), 16))
    raise RuntimeError(f"Delivery failed after five attempts; alert remains uncheckpointed: {last_error}")


def run_shipper() -> None:
    if not INGEST_TOKEN:
        raise RuntimeError("Set SURICATA_INGEST_TOKEN in the environment before starting the shipper.")
    EVE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVE_LOG_PATH.touch(exist_ok=True)
    print(f"[*] Reading Suricata EVE alerts from {EVE_LOG_PATH}")
    print(f"[*] Forwarding to {BACKEND_URL} (False-Positive Self-Traffic Filter: ENABLED)")

    recent_alerts: dict[tuple[str, int], float] = {}

    log_file = EVE_LOG_PATH.open("r", encoding="utf-8")
    try:
        current_stat = os.fstat(log_file.fileno())
        file_id = current_stat.st_ino
        offset = load_checkpoint(file_id, current_stat.st_size)
        log_file.seek(offset)

        while True:
            line_start = log_file.tell()
            line = log_file.readline()
            if not line:
                try:
                    path_stat = EVE_LOG_PATH.stat()
                    open_stat = os.fstat(log_file.fileno())
                    if path_stat.st_ino != open_stat.st_ino or path_stat.st_size < log_file.tell():
                        log_file.close()
                        log_file = EVE_LOG_PATH.open("r", encoding="utf-8")
                        file_id = os.fstat(log_file.fileno()).st_ino
                        log_file.seek(0)
                        save_checkpoint(file_id, 0)
                        continue
                except OSError:
                    pass
                time.sleep(0.2)
                continue

            if not line.endswith("\n"):
                log_file.seek(line_start)
                time.sleep(0.2)
                continue

            next_offset = log_file.tell()
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[!] Skipping malformed EVE line at byte {line_start}: {exc}", file=sys.stderr)
                save_checkpoint(file_id, next_offset)
                continue

            if event.get("event_type") == "alert":
                src_ip = event.get("src_ip", "")
                alert_obj = event.get("alert", {})
                sid = int(alert_obj.get("signature_id", 0) or 0)
                sig = str(alert_obj.get("signature", "unknown"))

                if is_noise_source(src_ip):
                    save_checkpoint(file_id, next_offset)
                    continue

                now = time.monotonic()
                dedup_key = (src_ip, sid)
                if now - recent_alerts.get(dedup_key, 0.0) < DEDUP_WINDOW_SECONDS:
                    save_checkpoint(file_id, next_offset)
                    continue

                recent_alerts[dedup_key] = now
                deliver_alert(event)
                print(f"[+] Forwarded Suricata alert: {sig} (Attacker IP: {src_ip})")

                if sid in (2000030, 2000031) or "ZERO-DAY" in sig.upper():
                    sync_zeroday_to_wazuh_eventlog(src_ip, sig)

            save_checkpoint(file_id, next_offset)
    finally:
        log_file.close()


if __name__ == "__main__":
    try:
        run_shipper()
    except KeyboardInterrupt:
        print("\n[*] Suricata shipper stopped.")
    except Exception as exc:
        print(f"[!] Suricata shipper stopped: {exc}", file=sys.stderr)
        sys.exit(1)
