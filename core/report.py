from core.timeline import build_timeline

def generate_report(incident):
    timeline = build_timeline(incident["events"])

    report = []
    report.append("===== SENTINELFORGE INCIDENT REPORT =====")
    report.append(f"IP: {incident['ip']}")
    report.append(f"Risk: {incident['risk']}")
    report.append(f"Score: {incident['risk_score']}")
    report.append(f"Reasons: {', '.join(incident['reasons'])}")
    report.append(f"MITRE: {', '.join(incident['mitre'])}")
    report.append("\n--- Timeline ---")

    for e in timeline:
        report.append(f"{e.get('timestamp')} | {e.get('event')} | {e.get('source')}")

    report.append("\n--- Recommended Action ---")

    if incident["risk"] == "CRITICAL":
        report.append("Block IP immediately (simulated)")
    elif incident["risk"] == "HIGH":
        report.append("Investigate and monitor closely")
    else:
        report.append("Monitor")

    return "\n".join(report)
