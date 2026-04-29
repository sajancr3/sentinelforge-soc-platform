import re
from core.watcher import follow
from core.event_bus import add_event
import time

IP_PATTERN = r"from ([0-9a-fA-F:.]+)"

def watch_auth(file_path="/var/log/auth.log"):
    print("[SentinelForge] Watching auth log...")

    with open(file_path, "r") as f:
        for line in follow(f):
            if "Failed password" in line:
                ip_match = re.findall(IP_PATTERN, line)
                ip = ip_match[0] if ip_match else "unknown"

                event = {
                    "source": "auth",
                    "event": "ssh_failed",
                    "ip": ip,
                    "timestamp": time.time(),
                    "severity": "low"
                }

                add_event(event)
                print("[EVENT]", event, flush=True)

if __name__ == "__main__":
    watch_auth()
