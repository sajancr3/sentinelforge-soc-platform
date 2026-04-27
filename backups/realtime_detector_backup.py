import time
import json
import os
import yaml
import subprocess
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

# cumulative risk memory per attacker IP
ip_scores = defaultdict(int)
ip_event_counts = defaultdict(int)


def ensure_dirs():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("response", exist_ok=True)


def now():
    return datetime.now().isoformat(timespec="seconds")


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
        return {
            "alert": "Nmap Scan Detected",
            "attack_type": "Network Reconnaissance",
            "severity": "High",
            "base_score": 55,
            "mitre": "T1046 - Network Service Discovery",
            "recommendation": "Review exposed services, validate source IP, and block if unauthorized."
        }

    if "attack_response" in sig or "id check returned root" in sig:
        return {
            "alert": "Suspicious Server Response Detected",
            "attack_type": "Post-Exploitation Indicator",
            "severity": "High",
            "base_score": 70,
            "mitre": "T1005 - Data from Local System",
            "recommendation": "Investigate server response and validate whether command output was exposed."
        }

    if "sql" in sig or "injection" in sig:
        return {
            "alert": "SQL Injection Attempt Detected",
            "attack_type": "Web Application Attack",
            "severity": "Critical",
            "base_score": 85,
            "mitre": "T1190 - Exploit Public-Facing Application",
            "recommendation": "Review web logs, validate input handling, and block malicious source."
        }

    if "trojan" in sig or "reverse shell" in sig or "command and control" in sig:
        return {
            "alert": "Reverse Shell / C2 Behavior Detected",
            "attack_type": "Command and Control",
            "severity": "Critical",
            "base_score": 90,
            "mitre": "T1059 - Command and Scripting Interpreter",
            "recommendation": "Isolate host, block C2 IP, and investigate endpoint activity."
        }

    return {
        "alert": "Generic Suricata Alert",
        "attack_type": "Network Alert",
        "severity": "Medium",
        "base_score": 40,
        "mitre": "T1040 - Network Monitoring",
        "recommendation": "Review Suricata evidence and validate the source."
    }


def risk_level(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def safe_to_block(ip):
    if ip in ALLOWLIST:
        return False, "allowlisted"

    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return False, "private/internal IP"

    private_172 = tuple(f"172.{i}." for i in range(16, 32))
    if ip.startswith(private_172):
        return False, "private/internal IP"

    if ip in ["unknown", "localhost"]:
        return False, "invalid IP"

    return True, "external IP"


def block_ip(ip):
    safe, reason = safe_to_block(ip)

    if not safe:
        return f"[SKIPPED] Not blocking {ip}: {reason}"

    check = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if check.returncode == 0:
        return f"[SKIPPED] Already blocked: {ip}"

    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        return f"[BLOCKED] IP blocked with iptables: {ip}"
    except Exception as e:
        return f"[ERROR] Failed to block {ip}: {e}"


def calculate_cumulative_score(source_ip, base_score):
    ip_event_counts[source_ip] += 1

    # Add base score but use smaller repeated increments after first alert
    if ip_scores[source_ip] == 0:
        ip_scores[source_ip] = base_score
    else:
        ip_scores[source_ip] += 20

    # Correlation boost for repeated suspicious activity
    if ip_event_counts[source_ip] >= 2:
        ip_scores[source_ip] += 10

    if ip_event_counts[source_ip] >= 3:
        ip_scores[source_ip] += 15

    # Cap at 100
    ip_scores[source_ip] = min(ip_scores[source_ip], 100)

    return ip_scores[source_ip]


def response_decision(event):
    ip = event["source_ip"]
    score = event["risk_score"]

    if score >= BLOCK_THRESHOLD:
        if AUTO_BLOCK:
            return block_ip(ip)

        safe, reason = safe_to_block(ip)
        if safe:
            return f"[DRY RUN] Would block external IP: {ip}"
        return f"[DRY RUN SKIPPED] Would not block {ip}: {reason}"

    if score >= 65:
        return "[INVESTIGATE] High risk. Analyst review required."

    if score >= 40:
        return "[MONITOR] Medium risk. Continue monitoring."

    return "[NO ACTION] Low risk."


def save_alerts():
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def write_response_log(event):
    with open(RESPONSE_LOG, "a") as f:
        f.write("\nSMART AUTO RESPONSE\n")
        f.write("-------------------\n")
        f.write(f"Time: {event['timestamp']}\n")
        f.write(f"Alert: {event['alert']}\n")
        f.write(f"Source IP: {event['source_ip']}\n")
        f.write(f"Signature: {event['signature']}\n")
        f.write(f"Base Score: {event['base_score']}/100\n")
        f.write(f"Cumulative Risk Score: {event['risk_score']}/100\n")
        f.write(f"Risk Level: {event['risk_level']}\n")
        f.write(f"Events From IP: {event['events_from_ip']}\n")
        f.write(f"Action: {event['response_action']}\n")


def process_suricata_line(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return

    if data.get("event_type") != "alert":
        return

    signature = data.get("alert", {}).get("signature", "Unknown Signature")
    src_ip = data.get("src_ip", "unknown")
    dest_ip = data.get("dest_ip", "unknown")
    src_port = data.get("src_port", "unknown")
    dest_port = data.get("dest_port", "unknown")
    proto = data.get("proto", "unknown")

    print(f"[DEBUG] Suricata alert found: {signature}")
    print(f"[DEBUG] Source: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

    classification = classify_alert(signature)

    if is_duplicate(classification["alert"], src_ip):
        print(f"[DEDUP] Skipped duplicate: {classification['alert']} from {src_ip}")
        return

    cumulative_score = calculate_cumulative_score(src_ip, classification["base_score"])

    alert_event = {
        "timestamp": now(),
        "alert": classification["alert"],
        "attack_type": classification["attack_type"],
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": proto,
        "signature": signature,
        "severity": classification["severity"],
        "base_score": classification["base_score"],
        "risk_score": cumulative_score,
        "risk_level": risk_level(cumulative_score),
        "events_from_ip": ip_event_counts[src_ip],
        "mitre": classification["mitre"],
        "recommendation": classification["recommendation"],
        "evidence": line.strip()
    }

    alert_event["response_action"] = response_decision(alert_event)

    alerts.append(alert_event)
    save_alerts()
    write_response_log(alert_event)

    print(f"[ALERT] {alert_event['alert']} | {src_ip} -> {dest_ip}")
    print(f"[BASE SCORE] {alert_event['base_score']}/100")
    print(f"[CUMULATIVE RISK] {alert_event['risk_score']}/100 | {alert_event['risk_level']}")
    print(f"[EVENT COUNT] {alert_event['events_from_ip']}")
    print(f"[RESPONSE] {alert_event['response_action']}")


def follow_file(path):
    print(f"[+] Watching Suricata EVE log: {path}")

    while not os.path.exists(path):
        print(f"[!] Waiting for {path}")
        time.sleep(2)

    with open(path, "r", errors="ignore") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            process_suricata_line(line)


def main():
    ensure_dirs()

    print("[+] SentinelForge Cumulative Risk Detector Started")
    print("[+] Processes Suricata alert events")
    print("[+] Cumulative scoring enabled")
    print(f"[+] Suricata log: {SURICATA_LOG}")
    print(f"[+] Output file: {OUTPUT_FILE}")
    print(f"[+] Auto block: {AUTO_BLOCK}")
    print(f"[+] Block threshold: {BLOCK_THRESHOLD}")
    print("[+] Press CTRL+C to stop")

    follow_file(SURICATA_LOG)


if __name__ == "__main__":
    main()
