# SentinelForge Real-Time Detection Evidence

SentinelForge was tested in a controlled local lab environment using:

- Debian monitored machine
- Ubuntu/Parrot attacker VM
- Suricata IDS telemetry
- Linux authentication logs
- Python detection engine
- SOC dashboard

## Detected Activity

### 1. Nmap Reconnaissance Scan

**What happened:**  
An attacker VM performed network reconnaissance against the monitored Debian host.

**Detection source:**  
Suricata EVE JSON

**Detection logic:**  
Repeated scan-related IDS alerts from the same source IP were parsed, normalized, and assigned a risk score.

**MITRE ATT&CK mapping:**  
T1046 - Network Service Discovery

---

### 2. SSH Failed Login / Brute-Force Pattern

**What happened:**  
Repeated failed SSH login attempts were generated against the monitored host.

**Detection source:**  
/var/log/auth.log

**Detection logic:**  
Multiple failed login events from the same source IP triggered brute-force suspicion.

**MITRE ATT&CK mapping:**  
T1110 - Brute Force

---

### 3. Repeated Source IP Correlation

**What happened:**  
The same source IP appeared across multiple suspicious events.

**Detection source:**  
Suricata + auth.log

**Detection logic:**  
SentinelForge grouped events by source IP and increased risk when multiple suspicious activities came from the same host.

---

### 4. Safe Response Logic

**What happened:**  
When the risk score crossed the configured threshold, SentinelForge generated a response recommendation.

**Safety control:**  
Private/internal lab IPs were allowlisted to prevent unsafe blocking.

**Response mode:**  
Simulated block / investigate / monitor

---

## Important Note

This project does not claim production monitoring. It demonstrates a realistic SOC workflow in a controlled lab:

Telemetry ingestion → detection → correlation → prioritization → incident reporting.
