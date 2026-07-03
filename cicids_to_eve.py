import csv, json, sys, random
from datetime import datetime, timedelta

TACTIC_MAP = {
    "FTP-Patator": ("Brute Force", "T1110.001"),
    "SSH-Patator": ("Brute Force", "T1110.004"),
    "DoS Hulk": ("Impact", "T1499"),
    "DoS GoldenEye": ("Impact", "T1499"),
    "DoS slowloris": ("Impact", "T1499"),
    "DoS Slowhttptest": ("Impact", "T1499"),
    "Heartbleed": ("Credential Access", "T1040"),
    "Infiltration": ("Lateral Movement", "T1210"),
    "Bot": ("Command and Control", "T1071"),
    "DDoS": ("Impact", "T1498"),
    "PortScan": ("Reconnaissance", "T1046"),
    "Web Attack": ("Initial Access", "T1190"),
    "Web Attack - Brute Force": ("Brute Force", "T1110"),
    "Web Attack - XSS": ("Defense Evasion", "T1059"),
    "Web Attack - Sql Injection": ("Initial Access", "T1190"),
}

def convert(csv_path, out_path, max_attacks=3000):
    results = []
    base_time = datetime.now()
    with open(csv_path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if len(results) >= max_attacks:
                break
            label = row.get(" Label", row.get("Label", "BENIGN")).strip()
            if label == "BENIGN":
                continue
            tactic, technique = TACTIC_MAP.get(label, ("Unknown", "T0000"))
            ts = base_time - timedelta(seconds=random.randint(0, 3600))
            risk = 90 if tactic == "Impact" else 75 if tactic in ("Brute Force", "Command and Control") else 60
            src_ip  = row.get(" Source IP",        row.get("Source IP",        "0.0.0.0")).strip()
            dest_ip = row.get(" Destination IP",   row.get("Destination IP",   "0.0.0.0")).strip()
            try: sport = int(float(row.get(" Source Port",      row.get("Source Port",      0)) or 0))
            except: sport = 0
            try: dport = int(float(row.get(" Destination Port", row.get("Destination Port", 0)) or 0))
            except: dport = 0
            proto = row.get(" Protocol", row.get("Protocol", "TCP")).strip()
            event = {
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"),
                "event_type": "alert",
                "src_ip": src_ip, "src_port": sport,
                "dest_ip": dest_ip, "dest_port": dport,
                "proto": proto,
                "alert": {"action": "allowed", "signature": "CICIDS2017 " + label,
                          "category": tactic, "severity": 1 if risk >= 80 else 2},
                "mitre_tactic": tactic, "mitre_technique": technique,
                "risk_score": risk, "severity": "HIGH" if risk >= 80 else "MEDIUM",
                "status": "NEW", "cicids_label": label,
            }
            results.append(json.dumps(event))
    with open(out_path, "w") as f:
        f.write("\n".join(results))
    print("Converted", len(results), "attack events to", out_path)

if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
