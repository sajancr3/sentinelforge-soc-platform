"""
SentinelForge - AI Analyst Prompt Templates
============================================
Structured prompts for Ollama-based threat analysis.
All prompts are designed to produce concise, actionable SOC output.
"""

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are a concise SOC (Security Operations Center) analyst AI. "
    "Analyze security alerts and produce brief, actionable intelligence. "
    "Always respond in 3-5 sentences maximum. Be specific about IPs, tactics, and risk. "
    "Never invent facts not present in the data. "
    "Format: plain text, no markdown, no bullet points."
)

HUNT_SYSTEM_PROMPT = (
    "You are a threat hunter AI assistant embedded in a SIEM. "
    "Given alert data about a specific IP, assess whether it is an active threat, "
    "a scanner/bot, or benign. Recommend a specific defensive action. "
    "Be direct and specific. 3 sentences maximum."
)


# ── Prompt builders ───────────────────────────────────────────────────────────

def alert_summary_prompt(alerts: list, live_count: int, cicids_count: int, hours: int = 1) -> str:
    """Prompt for summarising recent alert activity across the SOC."""
    tactic_counts: dict = {}
    ip_counts: dict     = {}
    high_risk           = [a for a in alerts if (a.get("risk_score") or 0) >= 75]

    for a in alerts:
        t = a.get("tactic") or "Unknown"
        tactic_counts[t] = tactic_counts.get(t, 0) + 1
        ip = a.get("src_ip") or "?"
        ip_counts[ip]    = ip_counts.get(ip, 0) + 1

    top_tactics   = sorted(tactic_counts.items(), key=lambda x: -x[1])[:3]
    top_attackers = sorted(ip_counts.items(),     key=lambda x: -x[1])[:3]

    return (
        f"Analyze this SOC alert summary for the past {hours} hour(s) and give a threat assessment.\n\n"
        f"STATISTICS:\n"
        f"  Total alerts : {len(alerts)}\n"
        f"  Live attacks : {live_count} (real-time detections)\n"
        f"  CICIDS replay: {cicids_count} (dataset simulation)\n"
        f"  High-risk    : {len(high_risk)} alerts with risk >= 75\n"
        f"  Top tactics  : {', '.join(f'{t} ({c})' for t,c in top_tactics)}\n"
        f"  Top attackers: {', '.join(f'{ip} ({c} alerts)' for ip,c in top_attackers)}\n\n"
        f"Is there active attack activity? What is the current threat posture? "
        f"What should the analyst investigate first?"
    )


def incident_analysis_prompt(incident: dict, alerts: list) -> str:
    """Prompt for analysing a specific incident."""
    sigs = list({a.get("signature") or "" for a in alerts[:10] if a.get("signature")})
    techs = list({a.get("technique") or "" for a in alerts if a.get("technique")})
    return (
        f"Analyze this security incident:\n\n"
        f"  Title     : {incident.get('title', 'Unknown')}\n"
        f"  Source IP : {incident.get('src_ip', '?')}\n"
        f"  Tactic    : {incident.get('tactic', '?')}\n"
        f"  Risk Score: {incident.get('risk_score', 0)}/100\n"
        f"  Alerts    : {incident.get('alert_count', 0)}\n"
        f"  First seen: {incident.get('timestamp', '?')}\n"
        f"  Status    : {incident.get('status', '?')}\n"
        f"  Techniques: {', '.join(techs[:4])}\n"
        f"  Signatures: {', '.join(sigs[:5])}\n\n"
        f"Provide: (1) what the attacker was doing, "
        f"(2) confidence level in this assessment, "
        f"(3) recommended next action for the analyst."
    )


def threat_hunt_prompt(
    src_ip: str,
    abuse_score: int,
    country: str,
    isp: str,
    is_tor: bool,
    alert_count: int,
    tactics: list,
    peak_risk: int,
) -> str:
    """Prompt for threat hunting on a specific IP."""
    tor_note = " — TOR EXIT NODE" if is_tor else ""
    return (
        f"Threat hunt assessment:\n\n"
        f"  IP         : {src_ip}\n"
        f"  AbuseIPDB  : {abuse_score}/100{tor_note}\n"
        f"  Country    : {country}\n"
        f"  ISP        : {isp or 'Unknown'}\n"
        f"  Alerts     : {alert_count} in last 24h\n"
        f"  Peak risk  : {peak_risk}/100\n"
        f"  Tactics    : {', '.join(tactics) or 'Unknown'}\n\n"
        f"Is this IP a credible threat, a scanner/bot, or likely benign? "
        f"What specific defensive action is recommended?"
    )


def enrichment_classify_prompt(abuse_score: int, country: str, isp: str, is_tor: bool) -> str:
    """One-sentence classification of a threat intel enrichment result."""
    tor = " (TOR exit node)" if is_tor else ""
    return (
        f"In one sentence, characterize the threat level of a source with "
        f"AbuseIPDB score {abuse_score}/100, origin {country}{tor}, ISP: {isp or 'Unknown'}."
    )
