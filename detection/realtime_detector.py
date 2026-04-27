import time
import json
import os
import yaml
import subprocess
import requests
from collections import deque, defaultdict
from datetime import datetime

CONFIG_FILE = "config.yaml"


def load_config():
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)


config = load_config()

SURICATA_LOG = config["logs"]["suricata_log"]
OUTPUT_FILE = config["logs"]["output_file"]
RESPONSE_LOG = config["logs"]["response_log"]

AUTO_BLOCK = config["response"]["auto_block"]
BLOCK_THRESHOLD = config["response"]["block_threshold"]
ALLOWLIST = config["response"]["allowlist"]

DEDUP_WINDOW_SECONDS = config["deduplication"]["window_seconds"]

alerts = []
recent_alerts = deque()

ip_scores = defaultdict(int)
ip_event_counts = defaultdict(int)
ip_attack_types = defaultdict(set)
ip_timeline = defaultdict(list)

geo_cache = {}


def ensure_dirs():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("response", exist_ok=True)


def now():
    return datetime.now().isoformat(timespec="seconds")


def is_private_ip(ip):
    return ip.startswith(("127.", "10.", "192.168.", "172."))


# 🌍 GEOIP FUNCTION
def geoip_lookup(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    if ip in ["unknown", "localhost"] or is_private_ip(ip):
        result = {
            "country": "LAB",
            "city": "Internal Network",
            "isp": "Private Network"
        }
        geo_cache[ip] = result
        return result

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()

        result = {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }

        geo_cache[ip] = result
        return result

    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }


def is_duplicate(alert_name, source_ip):
    current = time.time()

    while recent_alerts and current - recent_alerts[0]["time"] > DEDUP_WINDOW_SECONDS:
        recent_alerts.popleft()

    for item in recent_alerts:
        if item["alert"] == alert_name and item["source_ip"] == source_ip:
            return True

    recent_alerts.append({
        "alert": alert_name,
        "source_ip": source_ip,
        "time": current
    })

    return False


def classify_alert(signature):
    sig = signature.lower()

    if "nmap" in sig or "scan" in sig:
        return ("Nmap Scan Detected", "Recon", 55)

    if "attack_response" in sig:
        return ("Command Output Leak", "Post-Exploitation", 70)

    if "icmp" in sig:
        return ("ICMP Anomaly", "Network Anomaly", 40)

    return ("Generic Alert", "Unknown", 40)


def risk_level(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def attacker_classification(ip):
    if len(ip_attack_types[ip]) >= 3:
        return "Multi-Stage Attacker"
    if ip_event_counts[ip] >= 5:
        return "Persistent Attacker"
    return "Recon Actor"


def safe_to_block(ip):
    if is_private_ip(ip):
        return False
    return True


def block_ip(ip):
    if not safe_to_block(ip):
        return "[SAFEGUARD] Internal IP - Not Blocked"

    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return "[BLOCKED] External IP blocked"


def calculate_score(ip, base, attack_type):
    ip_event_counts[ip] += 1
    ip_attack_types[ip].add(attack_type)

    ip_scores[ip] += base if ip_scores[ip] == 0 else 20

    if ip_event_counts[ip] >= 2:
        ip_scores[ip] += 10

    if ip_event_counts[ip] >= 3:
        ip_scores[ip] += 15

    if len(ip_attack_types[ip]) >= 2:
        ip_scores[ip] += 15

    ip_scores[ip] = min(ip_scores[ip], 100)
    return ip_scores[ip]


def process(line):
    try:
        data = json.loads(line)
    except:
        return

    if data.get("event_type") != "alert":
        return

    sig = data["alert"]["signature"]
    src = data["src_ip"]
    dst = data["dest_ip"]

    name, atype, base = classify_alert(sig)

    if is_duplicate(name, src):
        return

    geo = geoip_lookup(src)
    score = calculate_score(src, base, atype)

    ip_timeline[src].append(name)

    event = {
        "timestamp": now(),
        "alert": name,
        "attack_type": atype,
        "source_ip": src,
        "destination_ip": dst,
        "risk_score": score,
        "risk_level": risk_level(score),
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "events": ip_event_counts[src],
        "classification": attacker_classification(src),
        "timeline": ip_timeline[src][-5:]
    }

    if score >= BLOCK_THRESHOLD:
        event["response"] = block_ip(src)
    else:
        event["response"] = "Monitor"

    alerts.append(event)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[{event['risk_level']}] {src} | {event['alert']} | Score: {score}")
    print(f"→ {event['response']}")


def follow():
    while not os.path.exists(SURICATA_LOG):
        time.sleep(1)

    with open(SURICATA_LOG, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                process(line)
            else:
                time.sleep(0.5)


def main():
    ensure_dirs()
    print("🔥 ELITE SOC ENGINE STARTED")
    follow()


if __name__ == "__main__":
    main()
