import json
import subprocess

input_file = "logs/enriched_alerts.json"
dry_run = True

with open(input_file) as f:
    alerts = json.load(f)

for alert in alerts:
    ip = alert["source_ip"]
    risk = alert.get("risk_level", "Unknown")

    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    print("\nSMART AUTO RESPONSE")
    print("-------------------")
    print(f"Alert: {alert['alert']}")
    print(f"Source IP: {ip}")
    print(f"Risk Level: {risk}")
    print(f"Reputation: {alert.get('ioc_reputation', 'Unknown')}")

    if risk in ["Critical", "High"]:
        if dry_run:
            print("[DRY RUN] Would block IP:")
            print(" ".join(command))
        else:
            subprocess.run(command, check=True)
            print(f"[ACTION TAKEN] Blocked IP: {ip}")
    else:
        print("[NO ACTION] Risk not high enough for blocking.")
