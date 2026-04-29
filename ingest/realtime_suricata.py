import json
import time
from core.watcher import follow
from core.event_bus import add_event

def watch_suricata(file_path="/var/log/suricata/eve.json"):
    print(f"[SentinelForge] Watching Suricata EVE: {file_path}")

    with open(file_path, "r") as f:
        for line in follow(f):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if data.get("event_type") != "alert":
                continue

            alert = data.get("alert", {})
            src_ip = data.get("src_ip", "unknown")

            event = {
                "source": "suricata",
                "event": "ids_alert",
                "ip": src_ip,
                "timestamp": time.time(),
                "severity": alert.get("severity", 3),
                "signature": alert.get("signature", "unknown"),
                "category": alert.get("category", "unknown"),
                "mitre": "T1046 - Network Service Discovery"
            }

            add_event(event)
            print("[SURICATA EVENT]", event, flush=True)

if __name__ == "__main__":
    watch_suricata()
