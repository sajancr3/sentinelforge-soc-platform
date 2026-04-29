# SentinelForge — Real-Time SOC Detection & Response Platform

SentinelForge is a real-time SOC project that detects network attacks using Suricata, processes alerts with a Python detection engine, maps activity to MITRE ATT&CK, scores risk, and visualizes incidents in a live dashboard.

## Features

- Real-time Suricata alert ingestion
- Nmap scan detection
- Suspicious server response detection
- MITRE ATT&CK mapping
- Risk scoring
- Deduplication
- Response decision engine
- Flask dashboard
- Safe auto-block logic using iptables

## Architecture

Attacker VM → Debian SOC VM → Suricata → SentinelForge Detector → Risk Scoring → Response Engine → Dashboard

## Lab Setup

- SOC VM: Debian
- Attacker VM: Ubuntu
- IDS: Suricata
- Dashboard: Flask
- Response: iptables

## Demo Commands

From Ubuntu attacker VM:

```bash
sudo nmap -sS -sV 192.168.64.6

---

## Real-Time Detection Evidence

SentinelForge was tested in a controlled local SOC lab. The project detected and documented:

- Nmap reconnaissance scans
- SSH failed login / brute-force patterns
- Suricata IDS alerts
- repeated suspicious source IP activity
- MITRE ATT&CK mapping
- cumulative risk scoring
- safe response recommendations

Evidence files:

- `evidence/realtime_detections.md`
- `samples/sample_suricata_eve.json`
- `samples/sample_auth_failed.log`
- `reports/sample_incident_report.md`

The project does not claim production monitoring. It demonstrates a realistic SOC workflow in a controlled lab:

Telemetry ingestion → detection → correlation → prioritization → incident reporting.

