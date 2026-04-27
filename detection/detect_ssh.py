import re
import json
from collections import defaultdict

log_file = "logs/auth.log"
output_file = "logs/alerts.json"

failed_attempts = defaultdict(int)

pattern = r"Failed password.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"

with open(log_file, "r") as f:
    for line in f:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            failed_attempts[ip] += 1

alerts = []

for ip, count in failed_attempts.items():
    if count >= 5:
        alerts.append({
            "alert": "SSH Brute Force Detected",
            "source_ip": ip,
            "attempts": count,
            "severity": "High",
            "mitre": "T1110 - Brute Force",
            "recommendation": "Block source IP and review authentication logs"
        })

with open(output_file, "w") as f:
    json.dump(alerts, f, indent=4)

print(f"Generated {len(alerts)} alert(s). Saved to {output_file}")
