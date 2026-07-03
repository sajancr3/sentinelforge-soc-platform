"""
SentinelForge - AI Analyst
===========================
Local LLM-powered threat analysis using Ollama.

Public API:
    analyse_recent(hours=1)       -> dict   # summarise recent alert activity
    analyse_incident(incident_id) -> dict   # analyse a specific incident
    hunt_ip(ip)                   -> dict   # threat hunt a specific attacker IP

All functions return a dict with at least:
    {
        "available": bool,      # False if Ollama is not running
        "analysis":  str,       # LLM output (or error message)
        "generated_at": str,    # ISO timestamp
    }

Results are cached for CACHE_TTL seconds to avoid hammering Ollama during
dashboard refreshes (5s interval).
"""

import sqlite3
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from collections import Counter

# ── Path fix: allow running from project root ─────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ai_analyst.ollama_client import generate, is_available
from ai_analyst.prompts import (
    SYSTEM_PROMPT,
    HUNT_SYSTEM_PROMPT,
    alert_summary_prompt,
    incident_analysis_prompt,
    threat_hunt_prompt,
)

DB         = os.path.join(_ROOT, 'sentinelforge.db')
CACHE_TTL  = 120   # seconds before re-querying Ollama for same key

# ── In-process result cache ───────────────────────────────────────────────────
_cache: dict = {}   # key -> (timestamp_float, result_dict)


def _get_cache(key: str):
    if key in _cache:
        ts, val = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return val
    return None


def _set_cache(key: str, val: dict):
    _cache[key] = (time.time(), val)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unavailable(reason: str = "Ollama not running. Start with: ollama serve") -> dict:
    return {"available": False, "analysis": reason, "generated_at": _now()}


# ── DB helpers ────────────────────────────────────────────────────────────────

def _fetch_alerts(hours: int = 1, source: str = None, limit: int = 200) -> list:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    where, params = "WHERE timestamp >= ?", [cutoff]
    if source:
        where  += " AND source = ?"
        params.append(source)
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _fetch_incident(incident_id: str):
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", [incident_id]).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def _fetch_ip_alerts(ip: str, limit: int = 100) -> list:
    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT tactic, technique, risk_score, source,
                      COALESCE(abuse_score, 0) AS abuse_score,
                      COALESCE(country, '??')  AS country,
                      COALESCE(isp, '')        AS isp,
                      COALESCE(is_tor, 0)      AS is_tor
               FROM alerts WHERE src_ip = ?
               ORDER BY timestamp DESC LIMIT ?""",
            [ip, limit]
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ── Public functions ──────────────────────────────────────────────────────────

def analyse_recent(hours: int = 1) -> dict:
    """Summarise alert activity for the last `hours` and return AI assessment."""
    key    = f"recent_{hours}"
    cached = _get_cache(key)
    if cached:
        return cached

    if not is_available():
        return _unavailable()

    alerts      = _fetch_alerts(hours=hours)
    live_count  = sum(1 for a in alerts if a.get("source") == "LIVE")
    cicids_count = len(alerts) - live_count

    if not alerts:
        result = {
            "available": True,
            "analysis":  "No alerts in the selected time window. System appears quiet.",
            "alert_count": 0,
            "generated_at": _now(),
            "hours": hours,
        }
        _set_cache(key, result)
        return result

    prompt = alert_summary_prompt(alerts, live_count, cicids_count, hours)
    try:
        analysis = generate(prompt, system=SYSTEM_PROMPT)
    except RuntimeError as e:
        return _unavailable(str(e))

    result = {
        "available":    True,
        "analysis":     analysis,
        "alert_count":  len(alerts),
        "live_count":   live_count,
        "cicids_count": cicids_count,
        "generated_at": _now(),
        "hours":        hours,
    }
    _set_cache(key, result)
    return result


def analyse_incident(incident_id: str) -> dict:
    """Analyse a specific incident by its ID."""
    key    = f"incident_{incident_id}"
    cached = _get_cache(key)
    if cached:
        return cached

    if not is_available():
        return _unavailable()

    incident = _fetch_incident(incident_id)
    if not incident:
        return _unavailable(f"Incident {incident_id} not found in database.")

    alerts = _fetch_ip_alerts(incident.get("src_ip", ""), limit=50)
    prompt = incident_analysis_prompt(incident, alerts)

    try:
        analysis = generate(prompt, system=SYSTEM_PROMPT)
    except RuntimeError as e:
        return _unavailable(str(e))

    result = {
        "available":    True,
        "analysis":     analysis,
        "incident_id":  incident_id,
        "generated_at": _now(),
    }
    _set_cache(key, result)
    return result


def hunt_ip(ip: str) -> dict:
    """Threat hunt a specific IP across the alert database."""
    key    = f"hunt_{ip}"
    cached = _get_cache(key)
    if cached:
        return cached

    if not is_available():
        return _unavailable()

    rows = _fetch_ip_alerts(ip)
    if not rows:
        return {
            "available":    True,
            "analysis":     f"No alerts found for {ip}. IP is not in the alert database.",
            "ip":           ip,
            "generated_at": _now(),
        }

    tactics    = list(Counter(r["tactic"] for r in rows if r.get("tactic")).keys())
    last       = rows[0]
    peak_risk  = max((r.get("risk_score") or 0) for r in rows)

    prompt = threat_hunt_prompt(
        src_ip      = ip,
        abuse_score = last.get("abuse_score", 0),
        country     = last.get("country", "??"),
        isp         = last.get("isp", ""),
        is_tor      = bool(last.get("is_tor")),
        alert_count = len(rows),
        tactics     = tactics,
        peak_risk   = peak_risk,
    )

    try:
        analysis = generate(prompt, system=HUNT_SYSTEM_PROMPT)
    except RuntimeError as e:
        return _unavailable(str(e))

    result = {
        "available":   True,
        "analysis":    analysis,
        "ip":          ip,
        "alert_count": len(rows),
        "tactics":     tactics,
        "abuse_score": last.get("abuse_score", 0),
        "country":     last.get("country", "??"),
        "peak_risk":   peak_risk,
        "generated_at": _now(),
    }
    _set_cache(key, result)
    return result


# ── CLI self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== SentinelForge AI Analyst ===")
    avail = is_available()
    print(f"Ollama available: {avail}")
    if not avail:
        print("Run: ollama serve && ollama pull llama3")
    else:
        print("\nAnalysing last 1 hour of alerts...")
        r = analyse_recent(hours=1)
        print(f"Alerts analysed: {r.get('alert_count', 0)}")
        print(f"Live count     : {r.get('live_count', 0)}")
        print(f"\nAI Analysis:\n{r.get('analysis')}")
