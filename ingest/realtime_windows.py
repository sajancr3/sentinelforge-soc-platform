import json
import time
from core.event_bus import add_event


def watch_windows(file_path="samples/windows/security_events.jsonl"):
    print("[SentinelForge] Watching Windows event logs...")

    with open(file_path, "r") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(1)
                continue

            try:
                event = json.loads(line.strip())

                if event.get("event_id") == 4625:
                    event["event"] = "windows_failed_logon"
                    event["mitre"] = "T1110"

                elif event.get("event_id") == 4688:
                    event["event"] = "process_creation"
                    event["mitre"] = "T1059"

                add_event(event)
                print("[WINDOWS EVENT]", event, flush=True)

            except Exception as e:
                print("[WINDOWS ERROR]", e)
