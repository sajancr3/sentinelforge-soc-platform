"""
SentinelForge Attack Timeline
==============================
Groups alerts from the DB into discrete attack sessions.

A "session" = consecutive alerts from the same (src_ip, tactic, source) combo
where consecutive alerts are no more than SESSION_GAP_MINUTES apart.

Usage:
    from core.timeline import get_timeline
    sessions = get_timeline(hours=24)

Returns a list of session dicts sorted by start time:
    {
        start, end, duration_s,
        src_ip, tactic, technique, alert_count, peak_risk,
        source,                              # LIVE or CICIDS
        enrichment: {abuse_score, country},
        mitre_url,                           # link to technique page
    }
"""

import sqlite3
import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sentinelforge.db')

SESSION_GAP_MINUTES = 5    # gap in minutes that signals a new attack session
MITRE_BASE = "https://attack.mitre.org/techniques"


def _mitre_url(technique: str) -> str:
    """Convert 'T1110.004' -> 'https://attack.mitre.org/techniques/T1110/004/'"""
    if not technique or not technique.startswith('T'):
        return ""
    parts = technique.split('.')
    base  = parts[0]
    sub   = f"/{parts[1]}" if len(parts) > 1 else ""
    return f"{MITRE_BASE}/{base}{sub.replace('.', '/')}/"


def get_timeline(hours: int = 24, source: str = None, src_ip: str = None) -> list:
    """
    Return attack sessions over the last `hours`.

    Args:
        hours:   look-back window (default 24)
        source:  filter by 'LIVE' or 'CICIDS' (default: both)
        src_ip:  filter to a specific attacker IP (default: all)

    Returns:
        List of session dicts, sorted by start time ascending.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")

    where   = "WHERE timestamp >= ?"
    params  = [cutoff]
    if source:
        where  += " AND source = ?"
        params.append(source)
    if src_ip:
        where  += " AND src_ip = ?"
        params.append(src_ip)

    try:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""SELECT timestamp, src_ip, tactic, technique, risk_score, source,
                       COALESCE(abuse_score, 0)  AS abuse_score,
                       COALESCE(country, '??')   AS country
                FROM alerts
                {where}
                ORDER BY timestamp ASC""",
            params
        ).fetchall()
        conn.close()
    except Exception as e:
        return []

    if not rows:
        return []

    # Group by (src_ip, tactic, source)
    groups = defaultdict(list)
    for r in rows:
        key = (r['src_ip'], r['tactic'] or 'Unknown', r['source'] or 'CICIDS')
        groups[key].append(dict(r))

    sessions = []
    for (src_ip_, tactic, src), alerts in groups.items():
        # Split into sessions wherever gap > SESSION_GAP_MINUTES
        session_alerts = [alerts[0]]
        for alert in alerts[1:]:
            try:
                prev = datetime.fromisoformat(session_alerts[-1]['timestamp'])
                curr = datetime.fromisoformat(alert['timestamp'])
                gap  = (curr - prev).total_seconds()
            except Exception:
                gap  = 0
            if gap > SESSION_GAP_MINUTES * 60:
                sessions.append(_build_session(session_alerts, src_ip_, tactic, src))
                session_alerts = [alert]
            else:
                session_alerts.append(alert)
        sessions.append(_build_session(session_alerts, src_ip_, tactic, src))

    sessions.sort(key=lambda s: s['start'])
    return sessions


def get_summary(hours: int = 24) -> dict:
    """High-level summary for the /api/timeline endpoint."""
    sessions = get_timeline(hours=hours)
    live_sessions   = [s for s in sessions if s['source'] == 'LIVE']
    cicids_sessions = [s for s in sessions if s['source'] == 'CICIDS']
    top_attackers   = {}
    for s in sessions:
        ip = s['src_ip']
        top_attackers[ip] = top_attackers.get(ip, 0) + s['alert_count']

    return {
        'total_sessions':   len(sessions),
        'live_sessions':    len(live_sessions),
        'cicids_sessions':  len(cicids_sessions),
        'hours':            hours,
        'top_attackers':    sorted(top_attackers.items(), key=lambda x: -x[1])[:5],
        'sessions':         sessions,
    }


def _build_session(alerts: list, src_ip: str, tactic: str, source: str) -> dict:
    start = alerts[0]['timestamp']
    end   = alerts[-1]['timestamp']
    try:
        dur = int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except Exception:
        dur = 0
    technique = alerts[0].get('technique') or ''
    last      = alerts[-1]
    return {
        'start':       start,
        'end':         end,
        'duration_s':  dur,
        'duration_fmt': _fmt_duration(dur),
        'src_ip':      src_ip,
        'tactic':      tactic,
        'technique':   technique,
        'alert_count': len(alerts),
        'peak_risk':   max(a['risk_score'] or 0 for a in alerts),
        'source':      source,
        'enrichment': {
            'abuse_score': last.get('abuse_score', 0),
            'country':     last.get('country', '??'),
        },
        'mitre_url':   _mitre_url(technique),
    }


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


if __name__ == '__main__':
    summary = get_summary(hours=48)
    print(f"Attack Timeline — last 48h")
    print(f"  Total sessions : {summary['total_sessions']}")
    print(f"  LIVE sessions  : {summary['live_sessions']}")
    print(f"  CICIDS sessions: {summary['cicids_sessions']}")
    print()
    for s in summary['sessions'][:10]:
        abuse = s['enrichment']['abuse_score']
        ti    = f" [TI:{abuse}]" if abuse else ""
        print(f"  {s['start'][:16]}  {s['src_ip']:15}  {s['tactic']:22}"
              f"  {s['alert_count']:4} alerts  peak:{s['peak_risk']:3}"
              f"  {s['duration_fmt']:8}  {s['source']}{ti}")
