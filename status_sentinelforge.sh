#!/bin/bash

echo "==== SentinelForge Status ===="

echo "[Suricata]"
pgrep -fl suricata || echo "Not running"

echo "[Detector]"
pgrep -fl realtime_detector || echo "Not running"

echo "[Dashboard]"
pgrep -fl streamlit || echo "Not running"
