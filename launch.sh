#!/bin/bash
# SentinelForge Live Demo Launcher
# Starts: dashboard + CICIDS streamer + live attack monitor

cd "$(dirname "$0")"
SF_DIR="$(pwd)"

# Kill any previous instances
pkill -f "dashboard.py"     2>/dev/null
pkill -f "streamer.py"     2>/dev/null
pkill -f "live_monitor.py" 2>/dev/null
sleep 1

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   SENTINELFORGE LIVE DEMO STARTING  ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Live monitor needs sudo for auth.log
echo "[*] Starting live attack monitor (needs sudo for auth.log)..."
sudo python3 "$SF_DIR/live_monitor.py" &
MONITOR_PID=$!
echo "[*] Live monitor PID: $MONITOR_PID"

# CICIDS streamer — feeds logs at 0.3s per event
echo "[*] Starting CICIDS log streamer (0.3s/event)..."
python3 "$SF_DIR/streamer.py" 0.3 &
STREAMER_PID=$!
echo "[*] Streamer PID: $STREAMER_PID"

echo ""
echo "  Dashboard: http://localhost:5001"
echo "  CICIDS:    streaming in background"
echo "  Live:      watching /var/log/auth.log"
echo ""
echo "  From Parrot OS, run:"
echo "    nmap -sS -p 22,80,443,5001 192.168.64.6"
echo "    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.6 -t 4"
echo ""
echo "  Ctrl+C to stop all."
echo ""

# Dashboard runs in foreground
python3 "$SF_DIR/dashboard.py"

# Cleanup on exit
kill $MONITOR_PID $STREAMER_PID 2>/dev/null
