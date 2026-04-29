from collections import defaultdict
from core.event_bus import get_events

def correlate():
    events = get_events()
    ip_map = defaultdict(list)

    for e in events:
        ip_map[e["ip"]].append(e)

    incidents = []

    for ip, evts in ip_map.items():
        auth_failures = [e for e in evts if e["event"] == "ssh_failed"]
        ids_alerts = [e for e in evts if e["event"] == "ids_alert"]

        risk_score = 0
        reasons = []

        if len(auth_failures) >= 5:
            risk_score += 60
            reasons.append("SSH brute-force pattern detected")

        if len(ids_alerts) >= 1:
            risk_score += 40
            reasons.append("Suricata IDS alert detected")

        if auth_failures and ids_alerts:
            risk_score += 30
            reasons.append("Multi-source correlation: auth failures + IDS alert from same IP")

        if risk_score >= 90:
            risk = "CRITICAL"
        elif risk_score >= 60:
            risk = "HIGH"
        elif risk_score >= 30:
            risk = "MEDIUM"
        else:
            continue

        incidents.append({
            "ip": ip,
            "risk": risk,
            "risk_score": min(risk_score, 100),
            "event_count": len(evts),
            "reasons": reasons,
            "mitre": list(set(e.get("mitre", "T1110 - Brute Force") for e in evts)),
            "events": evts[-10:]
        })

    return incidents
