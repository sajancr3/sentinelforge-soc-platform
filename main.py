import threading
import time

from ingest.realtime_auth import watch_auth
from ingest.realtime_suricata import watch_suricata
from core.correlator import correlate
from core.report import generate_report
from core.incident_store import save_incident


def run_auth():
    try:
        watch_auth()
    except PermissionError:
        print("[ERROR] Permission denied reading auth.log. Run with sudo.")
    except FileNotFoundError:
        print("[ERROR] auth.log not found.")


def run_suricata():
    try:
        watch_suricata()
    except PermissionError:
        print("[ERROR] Permission denied reading Suricata eve.json. Run with sudo.")
    except FileNotFoundError:
        print("[ERROR] /var/log/suricata/eve.json not found.")


def run_detection():
    seen = set()

    while True:
        incidents = correlate()

        for incident in incidents:
            key = f"{incident['ip']}-{incident['risk_score']}-{incident['event_count']}"

            if key not in seen:
                seen.add(key)

                print("\n🚨 SENTINELFORGE INCIDENT DETECTED")
                print("IP:", incident["ip"])
                print("Risk:", incident["risk"])
                print("Score:", incident["risk_score"])
                print("Reasons:", ", ".join(incident["reasons"]))
                print("MITRE:", ", ".join(incident["mitre"]))
                print("Events:", incident["event_count"])
                print("-" * 60)

                report = generate_report(incident)
                saved_path = save_incident(incident, report)

                print("\n📄 INCIDENT REPORT")
                print(report)
                print(f"\n[Saved] {saved_path}")
                print("=" * 60)

        time.sleep(2)


if __name__ == "__main__":
    print("[SentinelForge] Starting real-time SOC pipeline...")
    print("[SentinelForge] Sources: auth.log + Suricata EVE JSON")
    print("[SentinelForge] Press CTRL+C to stop.")

    threads = [
        threading.Thread(target=run_auth, daemon=True),
        threading.Thread(target=run_suricata, daemon=True),
        threading.Thread(target=run_detection, daemon=True),
    ]

    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SentinelForge] Stopped.")
