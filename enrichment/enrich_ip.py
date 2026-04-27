import json
import requests

API_KEY = "PASTE_YOUR_API_KEY_HERE"

input_file = "logs/alerts.json"
output_file = "logs/enriched_alerts.json"

def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        score = data["data"]["abuseConfidenceScore"]

        if score > 70:
            return "Known Malicious", "Critical"
        elif score > 30:
            return "Suspicious", "High"
        else:
            return "Clean", "Low"

    except:
        return "Unknown", "Medium"

with open(input_file) as f:
    alerts = json.load(f)

enriched = []

for alert in alerts:
    ip = alert["source_ip"]

    reputation, risk = check_ip(ip)

    alert["ioc_reputation"] = reputation
    alert["risk_level"] = risk

    enriched.append(alert)

with open(output_file, "w") as f:
    json.dump(enriched, f, indent=4)

print("Enrichment complete with real threat intel")
