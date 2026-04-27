#!/bin/bash

PROJECT_DIR="$HOME/sentinelforge"
CONFIG_FILE="$PROJECT_DIR/config.yaml"

echo "=========================================="
echo "   SentinelForge Real-Time SOC Platform   "
echo "=========================================="

cd "$PROJECT_DIR" || exit

echo "[+] Creating required folders..."
mkdir -p logs response dashboard detection

echo "[+] Cleaning old runtime logs..."
rm -f logs/enriched_alerts.json
rm -f response/response_log.txt

echo "[+] Checking virtual environment..."
if [ ! -d "venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Installing required Python packages..."
pip install streamlit pandas plotly pyyaml requests > /dev/null 2>&1

INTERFACE=$(python3 - <<EOF
import yaml
with open("$CONFIG_FILE") as f:
    print(yaml.safe_load(f)["interface"])
EOF
)

echo "[+] Using interface from config.yaml: $INTERFACE"

echo "[+] Stopping old Suricata process if running..."
sudo pkill suricata 2>/dev/null

echo "[+] Starting Suricata on interface: $INTERFACE"
sudo suricata -i "$INTERFACE" -c /etc/suricata/suricata.yaml -k none > logs/suricata_runtime.log 2>&1 &

sleep 3

echo "[+] Starting SentinelForge detector..."
sudo venv/bin/python detection/realtime_detector.py > logs/detector_runtime.log 2>&1 &

sleep 2

echo "[+] Starting dashboard..."
streamlit run dashboard/app.py

echo "[+] SentinelForge stopped."
