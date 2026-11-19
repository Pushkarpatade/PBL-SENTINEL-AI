@echo off
title SentinelAI - Suricata Integration Launcher
cd /d "%~dp0"
echo =======================================================
echo     SENTINELAI: LAUNCHING SURICATA INTEGRATION
echo =======================================================
python run_suricata.py
pause
