"""
SentinelForge - AbuseIPDB Enrichment
======================================
Queries AbuseIPDB v2 API for threat intel on a source IP.

Usage:
    from enrichment.enrich_ip import enrich_ip
    result = enrich_ip("8.8.8.8")

Returns dict:
    {
        "ip":           str,
        "abuse_score":  int,   # 0-100 (0 = clean / private / not in DB)
        "country":      str,   # 2-letter country code
        "isp":          str,
        "is_tor":       bool,
        "total_reports": int,
        "known_malicious": bool,  # True if score >= 75
    }

Config: reads API key from config.yaml (key: abuseipdb.api_key) or
        the ABUSEIPDB_KEY environment variable.
"""

import os
import yaml
import requests

_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG  = os.path.join(_ROOT, 'config.yaml')
_API_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT  = 10


def _load_api_key() -> str:
    # 1. Environment variable (highest priority)
    key = os.getenv("ABUSEIPDB_KEY", "").strip()
    if key:
        return key
    # 2. config.yaml
    try:
        with open(_CONFIG) as f:
            cfg = yaml.safe_load(f)
        key = cfg.get("abuseipdb", {}).get("api_key", "")
        if key and not key.startswith("YOUR_"):
            return key
    except Exception:
        pass
    return ""


def enrich_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for threat intel on `ip`.
    Returns a dict with enrichment fields (see module docstring).
    Private/loopback IPs return score=0 without an API call.
    """
    import ipaddress as _ipa
    empty = {"ip": ip, "abuse_score": 0, "country": "??",
             "isp": "", "is_tor": False, "total_reports": 0, "known_malicious": False}

    # Skip private IPs (AbuseIPDB won't have them)
    try:
        if _ipa.ip_address(ip).is_private:
            empty["country"] = "Private"
            return empty
    except ValueError:
        return empty

    api_key = _load_api_key()
    if not api_key:
        empty["error"] = "No AbuseIPDB API key configured (see config.yaml.example)"
        return empty

    try:
        r = requests.get(
            _API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        if not data:
            empty["error"] = "No data returned"
            return empty
        score = int(data.get("abuseConfidenceScore", 0))
        return {
            "ip":            ip,
            "abuse_score":   score,
            "country":       data.get("countryCode", "??"),
            "isp":           data.get("isp", ""),
            "is_tor":        bool(data.get("isTor", False)),
            "total_reports": int(data.get("totalReports", 0)),
            "known_malicious": score >= 75,
        }
    except requests.exceptions.HTTPError as e:
        return {**empty, "error": f"HTTP {r.status_code}: {e}"}
    except Exception as e:
        return {**empty, "error": str(e)}


if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    result = enrich_ip(ip)
    print(f"\nAbuseIPDB result for {ip}:")
    for k, v in result.items():
        print(f"  {k:16}: {v}")
