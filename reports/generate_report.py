import json
from datetime import datetime

input_file = "logs/alerts.json"

with open(input_file) as f:
    alerts = json.load(f)

for i, alert in enumerate(alerts):
    filename = f"reports/incident_{i+1}.md"

    report = f"""
# INCIDENT REPORT

## Basic Information
- Date: {datetime.now()}
- Incident Type: {alert['alert']}
- Severity: {alert['severity']}

## Source
- Source IP: {alert['source_ip']}
- Attempts: {alert['attempts']}

## MITRE ATT&CK
- Technique: {alert['mitre']}

## Summary
Multiple failed SSH login attempts detected, indicating a brute force attack.

## Impact
Potential unauthorized access attempt on the system.

## Recommended Actions
- {alert['recommendation']}

## Analyst Notes
- Investigate login attempts
- Check if any login succeeded
- Monitor for repeated activity
"""

    with open(filename, "w") as f:
        f.write(report)

    print(f"Report generated: {filename}")
