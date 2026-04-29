import json
import os
import time

INCIDENT_DIR = "reports/incidents"

def save_incident(incident, report):
    os.makedirs(INCIDENT_DIR, exist_ok=True)

    safe_ip = incident["ip"].replace(":", "_").replace(".", "_")
    filename = f"incident_{safe_ip}_{int(time.time())}.json"
    path = os.path.join(INCIDENT_DIR, filename)

    data = {
        "incident": incident,
        "report": report
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    return path
