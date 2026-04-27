#!/bin/bash

echo "[+] Stopping SentinelForge..."

sudo pkill suricata 2>/dev/null
pkill -f realtime_detector.py 2>/dev/null
pkill -f streamlit 2>/dev/null

echo "[+] All services stopped."
