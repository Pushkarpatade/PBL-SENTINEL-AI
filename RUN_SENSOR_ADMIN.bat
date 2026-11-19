@echo off
:: ============================================================
:: SentinelAI - One-Click IDS Sensor Launcher
:: ============================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d \"d:\pbl final project\" && call RUN_SENSOR_ADMIN.bat' -Verb RunAs"
    exit /b
)

echo =======================================================
echo    SENTINELAI: CONFIGURING IP 192.168.0.106 FOR KALI
echo =======================================================

:: Automatically add 192.168.0.106 to VMnet8, Wi-Fi, or Ethernet so Kali can reach it
netsh interface ipv4 add address "VMware Network Adapter VMnet8" 192.168.0.106 255.255.255.0 >nul 2>&1
netsh interface ipv4 add address "Wi-Fi" 192.168.0.106 255.255.255.0 >nul 2>&1
netsh interface ipv4 add address "Ethernet" 192.168.0.106 255.255.255.0 >nul 2>&1

echo [✓] Target IP 192.168.0.106 is active and reachable!
echo [*] Starting Multi-Protocol Packet Sniffer...
echo =======================================================

cd /d "d:\pbl final project"
title SentinelAI Live IDS Sensor (Admin)
python windows_ids.py
pause
