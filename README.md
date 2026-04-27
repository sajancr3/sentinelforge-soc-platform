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
