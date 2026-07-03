# SentinelForge — Open-Source SOC Platform

A full-stack Security Operations Center platform built from scratch, combining real-time intrusion detection, threat intelligence enrichment, automated response, and a live SOC dashboard.

Built as a hands-on cybersecurity engineering project to demonstrate end-to-end pipeline design — from raw log ingestion to automated blocking with analyst-facing dashboards.

---

## Live Demo Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTACK SOURCES                              │
│   Parrot OS (Hydra SSH)          CICIDS2017 Dataset (6000 evt) │
└──────────────┬──────────────────────────────┬───────────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────┐        ┌─────────────────────────┐
│   live_monitor.py    │        │      streamer.py         │
│  auth.log tailer     │        │  NDJSON replay engine    │
│  regex detection     │        │  0.3s/event drip rate    │
└──────────┬───────────┘        └────────────┬────────────┘
           │                                 │
           ▼                                 ▼
┌──────────────────────────────────────────────────────────┐
│              NORMALIZE → SQLite alerts table             │
│    src_ip | tactic | technique | risk_score | source     │
└──────────────────────┬───────────────────────────────────┘
                       │
           ┌───────────▼───────────┐
           │   AbuseIPDB Enrich    │
           │  abuse_score 0-100    │
           │  country / ISP / TOR  │
           │  cached per session   │
           └───────────┬───────────┘
                       │
           ┌───────────▼───────────┐
           │    core/event_bus     │
           │  pub/sub threading    │
           │  ALERT_NEW            │
           │  BLOCK_TRIGGERED      │
           │  SCAN_DETECTED        │
           └───────────┬───────────┘
                       │
           ┌───────────▼───────────┐
           │   AUTO-RESPOND        │
           │  iptables DROP        │
           │  after 10 failures    │
           │  response_log table   │
           └───────────┬───────────┘
                       │
           ┌───────────▼───────────┐
           │   Flask Dashboard     │
           │  5s live refresh      │
           │  /api/data            │
           │  /api/timeline        │
           │  /api/analyze (AI)    │
           └───────────────────────┘
```

---

## Features

**Detection**
- Real-time SSH brute force detection via `auth.log` regex parsing
- Detects: Failed Password, Invalid User, Disconnected, SSH Probe (port scan)
- CICIDS2017 dataset replay (8 CSV files → EVE JSON → SQLite) for historical baseline
- Unified view: LIVE alerts mixed with CICIDS replay in single alert queue

**Threat Intelligence**
- AbuseIPDB v2 API enrichment on every live source IP
- Fields stored: `abuse_score`, `country`, `isp`, `is_tor`
- Risk score boosting: +20 if score ≥ 75 (→ CRITICAL), +10 if score ≥ 50
- Per-IP caching prevents rate limiting during high-volume attacks
- Private IPs correctly labelled "Internal" (not "checking...")

**Automated Response**
- `iptables DROP` after configurable failure threshold (default: 10)
- All response actions logged to `response_log` DB table
- Dashboard response panel reads from DB in real time

**Event Bus** (`core/event_bus.py`)
- Thread-safe `threading.Queue`-based pub/sub
- Publishers: `live_monitor.py` (alert.new, block.triggered, scan.detected)
- Wildcard subscriber support (`bus.subscribe('*', callback)`)
- Decouples detection from enrichment, response, and AI modules

**Attack Timeline** (`core/timeline.py`)
- Groups alerts into discrete attack sessions
- Gap detection: 5-minute silence = new session
- Per-session: start/end, duration, peak risk, MITRE URL
- Exposed via `/api/timeline`

**AI Analyst** (`ai_analyst/`)
- Ollama-backed local LLM threat analysis (llama3/mistral/phi3)
- `analyse_recent(hours)`: summarises alert activity, identifies top threats
- `hunt_ip(ip)`: threat hunts a specific attacker IP across the DB
- `analyse_incident(id)`: full incident breakdown with recommended action
- 120s result cache to survive dashboard refresh interval
- Dashboard panel with ANALYSE button, live status indicator

**SOC Dashboard**
- Dark-theme Flask dashboard, auto-refreshes every 5 seconds
- Metric cards: Total Alerts, Active Incidents, Avg Risk, Live Attacks
- Alert queue with source badge (LIVE pulsing red / CICIDS grey)
- TI Score column: coloured by severity, TOR flag, country badge
- MITRE ATT&CK tactic breakdown (Chart.js horizontal bar)
- Attack timeline panel (session-level view)
- Automated response log panel

---

## MITRE ATT&CK Coverage

| Technique | ID | Source |
|---|---|---|
| SSH Brute Force | T1110.004 | Hydra / CICIDS SSH-Patator |
| FTP Brute Force | T1110.004 | CICIDS FTP-Patator |
| Port Scan | T1046 | Nmap / CICIDS PortScan |
| DDoS | T1499 | CICIDS Friday DDoS |
| C2 Communication | T1071 | CICIDS Bot traffic |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Detection | Python, regex, auth.log |
| Dataset | CICIDS2017 (UNB), EVE JSON (Suricata format) |
| Storage | SQLite |
| Threat Intel | AbuseIPDB v2 API |
| Response | iptables, subprocess |
| Event Bus | Python threading.Queue |
| AI Analyst | Ollama (llama3), local inference |
| Dashboard | Flask, Chart.js |
| Attack Lab | Parrot OS, Hydra, Nmap |

---

## Project Structure

```
sentinelforge/
├── dashboard.py          # Flask SOC dashboard + all API routes
├── live_monitor.py       # Real-time auth.log detection + enrichment + auto-block
├── streamer.py           # CICIDS2017 replay engine (drip rate configurable)
├── cicids_to_eve.py      # CICIDS2017 CSV → Suricata EVE JSON converter
├── launch.sh             # One-command launcher for all three processes
├── core/
│   ├── event_bus.py      # Thread-safe pub/sub event bus
│   └── timeline.py       # Attack session grouper + gap detection
├── ai_analyst/
│   ├── analyst.py        # analyse_recent / hunt_ip / analyse_incident
│   ├── ollama_client.py  # Ollama HTTP API wrapper
│   └── prompts.py        # SOC analyst prompt templates
├── enrichment/
│   └── enrich_ip.py      # AbuseIPDB v2 enrichment with caching
├── response/
│   └── auto_block.py     # iptables blocking module
├── samples/              # EVE JSON samples (gitignored, large)
└── config.yaml.example   # API key config template
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/sajancr3/sentinelforge-soc-platform.git
cd sentinelforge-soc-platform

# 2. Install dependencies
pip install flask requests pyyaml

# 3. Configure AbuseIPDB
cp config.yaml.example config.yaml
# Edit config.yaml and add your AbuseIPDB API key (free at abuseipdb.com)

# 4. (Optional) AI Analyst — requires Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3

# 5. Launch
chmod +x launch.sh
sudo ./launch.sh

# Dashboard: http://localhost:5001
```

**Simulate attacks (from a second machine):**
```bash
# SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP -t 4

# Port scan
nmap -sS -p 22,80,443 TARGET_IP
```

---

## Dataset

Uses the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) from the Canadian Institute for Cybersecurity.

- Tuesday: SSH-Patator + FTP-Patator brute force attacks
- Friday: PortScan + DDoS attacks

The `cicids_to_eve.py` converter transforms the raw CSV files into Suricata EVE JSON format for replay via `streamer.py`.

---

## What I Built vs. What I Learned

**Built:** A 7-stage security pipeline: Sources → Ingest → Normalize → Enrich → Detect → Respond → Present

**Engineering:** EVE JSON normalization schema, SQLite as lightweight SIEM backend, thread-safe pub/sub event bus, AbuseIPDB enrichment with per-session caching, iptables automation via subprocess, multi-source log ingestion into unified alert queue, Flask REST API with 5s polling frontend.

**SOC Analyst:** CICIDS2017 attack taxonomy, MITRE ATT&CK mapping for SSH/FTP/PortScan/DDoS, threat intel triage workflow (score → country → ISP → TOR), alert vs. incident distinction, why auth.log misses network-layer attacks (SYN probes need Suricata/iptables LOG).

---

*Built by Sajan Raju | [LinkedIn](https://linkedin.com/in/sajanraju) | Cybersecurity Engineering Portfolio*
