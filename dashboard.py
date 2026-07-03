"""
SentinelForge SOC Dashboard
============================
Run: python3 dashboard.py
URL: http://localhost:5001

Features:
  - Unified alert queue: CICIDS replay + LIVE real-time detections
  - AbuseIPDB threat intel scores on LIVE alerts
  - AI Analyst panel powered by local Ollama (llama3)
  - Attack timeline via /api/timeline
  - Automated response log (iptables blocks)
  - MITRE ATT&CK tactic breakdown chart
  - 5-second auto-refresh
"""

from flask import Flask, jsonify, render_template_string, request
import sqlite3, json, os, glob
from datetime import datetime, timezone

app = Flask(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_ROOT        = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(_ROOT, 'sentinelforge.db')
REPORTS_DIR  = os.path.join(_ROOT, 'reports')
RESPONSE_LOG = os.path.join(_ROOT, 'response', 'response_log.json')

# ── Private IP ranges (AbuseIPDB returns 0 for these, not a query failure) ───
import ipaddress as _ip

def _is_private(ip_str: str) -> bool:
    try:
        return _ip.ip_address(ip_str).is_private
    except Exception:
        return False


# ── Data helpers ───────────────────────────────────────────────────────────────

def get_alerts(limit: int = 60):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT timestamp, src_ip, dest_ip, tactic, technique,
                   risk_score, severity, status,
                   COALESCE(source, 'CICIDS')    AS source,
                   COALESCE(abuse_score, 0)      AS abuse_score,
                   COALESCE(country, '??')        AS country,
                   COALESCE(is_tor, 0)           AS is_tor
            FROM alerts ORDER BY id DESC LIMIT ?
        """, [limit]).fetchall()
        conn.close()
        alerts = [dict(r) for r in rows]
        # Tag private IPs so the JS can display "Internal" instead of "checking..."
        for a in alerts:
            a['is_private_ip'] = _is_private(a.get('src_ip') or '')
        return alerts if alerts else _demo_alerts()
    except Exception:
        return _demo_alerts()


def _demo_alerts():
    import random
    tactics = ['Reconnaissance','Brute Force','Lateral Movement','Data Exfiltration','Command and Control']
    sevs    = ['CRITICAL','HIGH','MEDIUM','LOW']
    demo    = []
    for i in range(15):
        risk = random.randint(15, 95)
        sev  = 'CRITICAL' if risk>80 else 'HIGH' if risk>60 else 'MEDIUM' if risk>35 else 'LOW'
        demo.append({
            'timestamp': f"2026-07-03T00:{str(i).zfill(2)}:00",
            'src_ip':    f"192.168.{random.randint(1,5)}.{random.randint(2,254)}",
            'dest_ip':   '192.168.64.6',
            'tactic':    random.choice(tactics),
            'technique': f"T{random.randint(1000,1599)}",
            'risk_score': risk,
            'severity':  sev,
            'status':    'NEW',
            'source':    'CICIDS',
            'abuse_score': 0,
            'country':   '??',
            'is_tor':    0,
            'is_private_ip': True,
        })
    return demo


def get_incidents():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, title, risk_score, status, tactic, src_ip, timestamp, alert_count
            FROM incidents ORDER BY risk_score DESC LIMIT 10
        """).fetchall()
        conn.close()
        if rows:
            return [dict(r) for r in rows]
    except Exception:
        pass
    try:
        files = sorted(glob.glob(os.path.join(REPORTS_DIR, '*.json')), reverse=True)
        if files:
            with open(files[0]) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data[:10]
            if isinstance(data, dict) and 'incidents' in data:
                return data['incidents'][:10]
    except Exception:
        pass
    return [{'id': 'INC-001', 'title': 'Brute Force Campaign', 'risk_score': 72,
             'status': 'ACTIVE', 'tactic': 'Brute Force', 'src_ip': '—',
             'timestamp': '—', 'alert_count': 0}]


def get_response_log():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT time, action, target, result, rule FROM response_log ORDER BY id DESC LIMIT 12"
        ).fetchall()
        conn.close()
        if rows:
            return [dict(r) for r in rows]
    except Exception:
        pass
    try:
        with open(RESPONSE_LOG) as f:
            return json.load(f)[-12:]
    except Exception:
        pass
    return [{'time': '--:--', 'action': 'INIT', 'target': 'system',
             'result': 'SUCCESS', 'rule': 'Awaiting attacks...'}]


def build_stats(alerts, incidents):
    total_alerts  = len(alerts)
    active_inc    = sum(1 for i in incidents if i.get('status') not in ('CLOSED','RESOLVED'))
    avg_risk      = round(sum(a.get('risk_score',0) for a in alerts) / max(total_alerts, 1))
    tactic_counts = {}
    for a in alerts:
        t = a.get('tactic') or 'Unknown'
        tactic_counts[t] = tactic_counts.get(t, 0) + 1
    try:
        conn     = sqlite3.connect(DB_PATH)
        total_db = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        live_db  = conn.execute("SELECT COUNT(*) FROM alerts WHERE source='LIVE'").fetchone()[0]
        conn.close()
    except Exception:
        total_db = total_alerts
        live_db  = sum(1 for a in alerts if a.get('source') == 'LIVE')
    return {
        'total_alerts':  total_db,
        'live_count':    live_db,
        'active_inc':    active_inc,
        'avg_risk':      avg_risk,
        'tactic_counts': tactic_counts,
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/api/data')
def api_data():
    alerts    = get_alerts()
    incidents = get_incidents()
    response  = get_response_log()
    stats     = build_stats(alerts, incidents)
    return jsonify({
        'alerts':    alerts[:30],
        'incidents': incidents,
        'response':  response,
        'stats':     stats,
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
    })


@app.route('/api/analyze')
def api_analyze():
    """AI Analyst: summarise recent alert activity."""
    hours = int(request.args.get('hours', 1))
    try:
        from ai_analyst.analyst import analyse_recent
        result = analyse_recent(hours=hours)
    except Exception as e:
        result = {"available": False, "analysis": f"AI Analyst error: {e}",
                  "generated_at": datetime.now(timezone.utc).isoformat()}
    return jsonify(result)


@app.route('/api/hunt')
def api_hunt():
    """AI Analyst: threat hunt a specific IP."""
    ip = request.args.get('ip', '')
    if not ip:
        return jsonify({"available": False, "analysis": "No IP provided."}), 400
    try:
        from ai_analyst.analyst import hunt_ip
        result = hunt_ip(ip)
    except Exception as e:
        result = {"available": False, "analysis": f"Hunt error: {e}",
                  "generated_at": datetime.now(timezone.utc).isoformat()}
    return jsonify(result)


@app.route('/api/timeline')
def api_timeline():
    """Attack session timeline."""
    hours  = int(request.args.get('hours', 24))
    source = request.args.get('source')
    try:
        from core.timeline import get_summary
        result = get_summary(hours=hours)
    except Exception as e:
        result = {"error": str(e), "sessions": []}
    return jsonify(result)


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


# ── HTML Template ──────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SentinelForge SOC Operations</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg:     #060D1A; --panel:  #0D1B2E; --border: #1E3A5F;
    --blue:   #3B82F6; --cyan:   #06B6D4; --red:    #EF4444;
    --orange: #F97316; --yellow: #EAB308; --green:  #10B981;
    --purple: #A855F7; --muted:  #64748B; --text:   #E2E8F0; --dim: #94A3B8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 13px; }

  /* TOP BAR */
  .topbar { display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:52px;
    background:var(--panel);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100; }
  .logo { display:flex;align-items:center;gap:10px; }
  .logo-icon { width:28px;height:28px;background:var(--blue);border-radius:6px;
    display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#fff; }
  .logo-text { font-size:16px;font-weight:700;color:#fff;letter-spacing:1px; }
  .logo-sub  { font-size:10px;color:var(--muted);letter-spacing:2px;margin-top:1px; }
  .live-badge { display:flex;align-items:center;gap:7px;background:rgba(16,185,129,.1);
    border:1px solid rgba(16,185,129,.3);color:var(--green);padding:4px 12px;
    border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px; }
  .pulse { width:7px;height:7px;border-radius:50%;background:var(--green);
    animation:pulse 1.4s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.8)} }
  .clock { color:var(--muted);font-size:12px; }

  /* LAYOUT */
  .main { padding:20px 24px;display:grid;grid-template-rows:auto auto 1fr;gap:16px; }
  .metrics { display:grid;grid-template-columns:repeat(4,1fr);gap:12px; }
  .metric-card { background:var(--panel);border:1px solid var(--border);border-radius:10px;
    padding:18px 20px;position:relative;overflow:hidden; }
  .metric-card::before { content:'';position:absolute;top:0;left:0;right:0;height:3px;
    background:var(--card-accent,var(--blue)); }
  .metric-card.blue   { --card-accent:var(--blue); }
  .metric-card.red    { --card-accent:var(--red); }
  .metric-card.orange { --card-accent:var(--orange); }
  .metric-card.purple { --card-accent:var(--purple); }
  .metric-label { font-size:10px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:10px; }
  .metric-value { font-size:36px;font-weight:900;line-height:1;margin-bottom:6px; }
  .metric-card.blue   .metric-value { color:var(--blue); }
  .metric-card.red    .metric-value { color:var(--red); }
  .metric-card.orange .metric-value { color:var(--orange); }
  .metric-card.purple .metric-value { color:var(--purple); }
  .metric-sub { font-size:11px;color:var(--dim); }

  /* PANELS */
  .panels { display:grid;grid-template-columns:1fr 360px;gap:16px; }
  .left-col { display:flex;flex-direction:column;gap:16px; }
  .right-col { display:flex;flex-direction:column;gap:16px; }
  .panel { background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden; }
  .panel-header { display:flex;align-items:center;justify-content:space-between;
    padding:12px 18px;border-bottom:1px solid var(--border);background:rgba(30,58,95,.2); }
  .panel-title { font-size:11px;font-weight:700;letter-spacing:2px;color:var(--blue);text-transform:uppercase; }
  .panel-badge { font-size:10px;background:rgba(59,130,246,.15);color:var(--blue);
    padding:2px 8px;border-radius:10px;border:1px solid rgba(59,130,246,.3); }

  /* ALERT TABLE */
  .alert-table { width:100%;border-collapse:collapse; }
  .alert-table th { padding:8px 14px;text-align:left;font-size:10px;letter-spacing:1.5px;
    color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--border);
    background:rgba(13,27,46,.6);font-weight:600; }
  .alert-table td { padding:9px 14px;border-bottom:1px solid rgba(30,58,95,.4);vertical-align:middle; }
  .alert-table tr:hover td { background:rgba(59,130,246,.04); }
  .alert-table tr:last-child td { border-bottom:none; }
  .sev { display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px; }
  .sev-CRITICAL { background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3); }
  .sev-HIGH     { background:rgba(249,115,22,.15);color:var(--orange);border:1px solid rgba(249,115,22,.3); }
  .sev-MEDIUM   { background:rgba(234,179,8,.15);color:var(--yellow);border:1px solid rgba(234,179,8,.3); }
  .sev-LOW      { background:rgba(100,116,139,.15);color:var(--muted);border:1px solid rgba(100,116,139,.3); }
  .ip { color:var(--cyan);font-family:'Courier New',monospace;font-size:12px; }
  .tactic-tag { color:var(--dim);font-size:11px; }
  .risk-bar-wrap { display:flex;align-items:center;gap:8px; }
  .risk-bar { height:4px;border-radius:2px;background:var(--border);width:60px;overflow:hidden; }
  .risk-fill { height:100%;border-radius:2px; }
  .risk-num { font-size:12px;font-weight:700;min-width:24px; }

  /* BADGES */
  .src-live { display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,.15);
    color:#EF4444;border:1px solid rgba(239,68,68,.4);font-size:9px;font-weight:900;
    padding:2px 6px;border-radius:3px;letter-spacing:1px; }
  .src-live .src-dot { width:5px;height:5px;border-radius:50%;background:#EF4444;animation:pulse 1s infinite; }
  .src-cicids { display:inline-block;background:rgba(100,116,139,.1);color:#64748B;
    border:1px solid rgba(100,116,139,.25);font-size:9px;font-weight:700;
    padding:2px 6px;border-radius:3px;letter-spacing:1px; }

  /* INCIDENTS */
  .incident-list { padding:12px;display:flex;flex-direction:column;gap:8px; }
  .inc-card { background:rgba(13,27,46,.8);border:1px solid var(--border);border-radius:8px;
    padding:12px 14px;border-left:3px solid var(--orange); }
  .inc-card.contained { border-left-color:var(--green); }
  .inc-card.closed    { border-left-color:var(--muted); }
  .inc-title { font-size:12px;font-weight:700;color:var(--text);margin-bottom:6px; }
  .inc-meta  { display:flex;gap:12px;font-size:11px;color:var(--muted);flex-wrap:wrap; }
  .inc-risk  { color:var(--red);font-weight:700; }

  /* CHART */
  .chart-wrap { padding:16px;height:220px;position:relative; }

  /* RESPONSE LOG */
  .response-list { padding:10px 14px;display:flex;flex-direction:column;gap:6px;max-height:220px;overflow-y:auto; }
  .resp-item { display:flex;align-items:center;gap:10px;padding:8px 10px;
    background:rgba(13,27,46,.6);border-radius:6px;border:1px solid var(--border); }
  .resp-time   { color:var(--muted);font-size:11px;min-width:52px; }
  .resp-action { font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;min-width:74px;text-align:center; }
  .action-BLOCK     { background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3); }
  .action-ALERT     { background:rgba(234,179,8,.15);color:var(--yellow);border:1px solid rgba(234,179,8,.3); }
  .action-CORRELATE { background:rgba(59,130,246,.15);color:var(--blue);border:1px solid rgba(59,130,246,.3); }
  .action-INIT      { background:rgba(16,185,129,.1);color:var(--green);border:1px solid rgba(16,185,129,.3); }
  .resp-target { color:var(--cyan);font-size:12px;flex:1; }
  .resp-ok  { color:var(--green);font-size:11px;font-weight:700; }
  .resp-err { color:var(--red);font-size:11px;font-weight:700; }

  /* AI ANALYST PANEL */
  .ai-panel-body { padding:14px 16px;display:flex;flex-direction:column;gap:12px; }
  .ai-status { display:flex;align-items:center;gap:8px;font-size:11px; }
  .ai-dot-ok   { width:7px;height:7px;border-radius:50%;background:var(--green); }
  .ai-dot-off  { width:7px;height:7px;border-radius:50%;background:var(--muted); }
  .ai-dot-spin { width:7px;height:7px;border-radius:50%;background:var(--purple);
    animation:pulse 0.8s ease-in-out infinite; }
  .ai-text { font-size:12px;line-height:1.6;color:var(--dim);font-style:italic; }
  .ai-text.loaded { color:var(--text);font-style:normal; }
  .ai-meta { font-size:10px;color:var(--muted);letter-spacing:1px; }
  .ai-btn { background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.3);color:var(--purple);
    padding:5px 12px;border-radius:6px;font-family:'Courier New',monospace;font-size:11px;
    cursor:pointer;letter-spacing:1px;transition:background .2s; }
  .ai-btn:hover { background:rgba(168,85,247,.2); }
  .ai-btn:disabled { opacity:.4;cursor:not-allowed; }

  /* TIMELINE */
  .timeline-body { padding:10px 14px;max-height:280px;overflow-y:auto;display:flex;flex-direction:column;gap:6px; }
  .tl-item { display:flex;align-items:center;gap:10px;padding:8px 10px;
    background:rgba(13,27,46,.6);border-radius:6px;border:1px solid var(--border);
    border-left:3px solid var(--border); }
  .tl-item.live   { border-left-color:var(--red); }
  .tl-item.cicids { border-left-color:var(--blue); }
  .tl-time  { color:var(--muted);font-size:10px;min-width:42px; }
  .tl-ip    { color:var(--cyan);font-size:11px;min-width:100px; }
  .tl-tactic { color:var(--dim);font-size:11px;flex:1; }
  .tl-count { color:var(--text);font-size:11px;font-weight:700;min-width:32px; }
  .tl-dur   { color:var(--muted);font-size:10px;min-width:40px; }

  /* MISC */
  ::-webkit-scrollbar { width:4px;height:4px; }
  ::-webkit-scrollbar-track { background:var(--bg); }
  ::-webkit-scrollbar-thumb { background:var(--border);border-radius:2px; }
  .loading { color:var(--muted);padding:24px;text-align:center;letter-spacing:2px;font-size:11px; }
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <div class="logo">
    <div class="logo-icon">SF</div>
    <div>
      <div class="logo-text">SENTINELFORGE</div>
      <div class="logo-sub">SOC OPERATIONS CENTER</div>
    </div>
  </div>
  <div class="live-badge"><span class="pulse"></span>LIVE</div>
  <div class="clock" id="clock">--</div>
</div>

<!-- MAIN -->
<div class="main">

  <!-- METRIC CARDS -->
  <div class="metrics">
    <div class="metric-card blue">
      <div class="metric-label">Total Alerts</div>
      <div class="metric-value" id="m-alerts">—</div>
      <div class="metric-sub">ingested this session</div>
    </div>
    <div class="metric-card red">
      <div class="metric-label">Active Incidents</div>
      <div class="metric-value" id="m-incidents">—</div>
      <div class="metric-sub">requiring investigation</div>
    </div>
    <div class="metric-card orange">
      <div class="metric-label">Avg Risk Score</div>
      <div class="metric-value" id="m-risk">—</div>
      <div class="metric-sub">across all alerts</div>
    </div>
    <div class="metric-card red">
      <div class="metric-label">Live Attacks</div>
      <div class="metric-value" id="m-live">—</div>
      <div class="metric-sub" style="display:flex;align-items:center;gap:6px">
        <span class="pulse" style="background:#EF4444;width:6px;height:6px;border-radius:50%;animation:pulse 1s infinite"></span>real-time detections
      </div>
    </div>
  </div>

  <!-- PANELS -->
  <div class="panels">

    <!-- LEFT -->
    <div class="left-col">

      <!-- ALERT QUEUE -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Alert Queue</span>
          <span class="panel-badge" id="alert-count-badge">0 alerts</span>
        </div>
        <div style="overflow-x:auto;max-height:340px;overflow-y:auto">
          <table class="alert-table">
            <thead>
              <tr>
                <th>Src</th><th>Time</th><th>Source IP</th>
                <th>Tactic</th><th>Risk</th><th>Severity</th><th>TI Score</th>
              </tr>
            </thead>
            <tbody id="alert-tbody">
              <tr><td colspan="7" class="loading">LOADING ALERTS...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- INCIDENTS -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Incident Register</span>
          <span class="panel-badge" id="inc-count-badge">0 incidents</span>
        </div>
        <div class="incident-list" id="incident-list">
          <div class="loading">LOADING INCIDENTS...</div>
        </div>
      </div>

      <!-- ATTACK TIMELINE -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Attack Timeline</span>
          <span class="panel-badge" id="tl-badge">loading...</span>
        </div>
        <div class="timeline-body" id="timeline-body">
          <div class="loading">LOADING TIMELINE...</div>
        </div>
      </div>

    </div>

    <!-- RIGHT -->
    <div class="right-col">

      <!-- AI ANALYST -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title" style="color:var(--purple)">AI Analyst</span>
          <button class="ai-btn" id="ai-btn" onclick="runAnalysis()">ANALYSE</button>
        </div>
        <div class="ai-panel-body">
          <div class="ai-status">
            <span class="ai-dot-off" id="ai-dot"></span>
            <span id="ai-status-text" style="color:var(--muted)">Ollama — idle</span>
          </div>
          <div class="ai-text" id="ai-text">
            Click ANALYSE to run local LLM threat assessment on current alerts.
          </div>
          <div class="ai-meta" id="ai-meta"></div>
        </div>
      </div>

      <!-- TACTIC CHART -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">MITRE ATT&CK Breakdown</span>
        </div>
        <div class="chart-wrap">
          <canvas id="tacticChart"></canvas>
        </div>
      </div>

      <!-- RESPONSE LOG -->
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Automated Response Log</span>
          <span class="panel-badge">iptables / SOAR</span>
        </div>
        <div class="response-list" id="response-list">
          <div class="loading">LOADING...</div>
        </div>
      </div>

    </div>
  </div>

</div>

<script>
let tacticChart = null;

function riskColor(score) {
  if (score >= 80) return '#EF4444';
  if (score >= 60) return '#F97316';
  if (score >= 35) return '#EAB308';
  return '#64748B';
}

function renderAlerts(alerts) {
  const tbody = document.getElementById('alert-tbody');
  document.getElementById('alert-count-badge').textContent = alerts.length + ' shown';
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading">NO ALERTS</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a => {
    const sev        = a.severity || 'LOW';
    const score      = a.risk_score || 0;
    const ts         = (a.timestamp || '').replace('T',' ').slice(11,19) || '—';
    const isLive     = (a.source || 'CICIDS') === 'LIVE';
    const abuseScore = a.abuse_score || 0;
    const country    = a.country || '??';
    const isPrivate  = !!a.is_private_ip;
    const isTor      = !!a.is_tor;

    const srcBadge = isLive
      ? `<span class="src-live"><span class="src-dot"></span>LIVE</span>`
      : `<span class="src-cicids">CICIDS</span>`;

    const rowStyle = isLive ? 'background:rgba(239,68,68,.04);' : '';

    // TI badge logic
    // LIVE + private IP  -> "Internal" (no AbuseIPDB entry, but that's fine)
    // LIVE + score >0    -> show score + country
    // LIVE + score 0 + not private -> "Clean / No Reports"
    // CICIDS             -> dash (no enrichment for replay data)
    let tiBadge = '<span style="color:var(--muted);font-size:10px">—</span>';
    if (isLive) {
      if (abuseScore > 0) {
        const tiColor = abuseScore >= 75 ? '#EF4444' : abuseScore >= 50 ? '#F97316' : '#EAB308';
        const torNote = isTor ? ' <span style="color:var(--red);font-size:9px">TOR</span>' : '';
        tiBadge = `<span style="color:${tiColor};font-weight:700;font-size:11px">${abuseScore}</span>` +
                  `<span style="color:var(--muted);font-size:10px"> ${country}</span>${torNote}`;
      } else if (isPrivate) {
        tiBadge = `<span style="color:var(--muted);font-size:10px">Internal</span>`;
      } else {
        tiBadge = `<span style="color:var(--green);font-size:10px">Clean</span>`;
      }
    }

    return `<tr style="${rowStyle}">
      <td>${srcBadge}</td>
      <td style="color:var(--dim);font-size:11px">${ts}</td>
      <td><span class="ip">${a.src_ip || '—'}</span></td>
      <td><span class="tactic-tag">${a.tactic || '—'}</span></td>
      <td>
        <div class="risk-bar-wrap">
          <div class="risk-bar"><div class="risk-fill" style="width:${score}%;background:${riskColor(score)}"></div></div>
          <span class="risk-num" style="color:${riskColor(score)}">${score}</span>
        </div>
      </td>
      <td><span class="sev sev-${sev}">${sev}</span></td>
      <td>${tiBadge}</td>
    </tr>`;
  }).join('');
}

function renderIncidents(incidents) {
  const el = document.getElementById('incident-list');
  document.getElementById('inc-count-badge').textContent = incidents.length + ' incidents';
  if (!incidents.length) { el.innerHTML = '<div class="loading">NO INCIDENTS</div>'; return; }
  el.innerHTML = incidents.map(i => {
    const st  = (i.status || 'ACTIVE').toUpperCase();
    const cls = (st === 'CONTAINED' || st === 'RESOLVED') ? 'contained' : st === 'CLOSED' ? 'closed' : '';
    return `<div class="inc-card ${cls}">
      <div class="inc-title">${i.title || i.id || 'Incident'}</div>
      <div class="inc-meta">
        <span>ID: <strong style="color:var(--text)">${i.id || '—'}</strong></span>
        <span>Risk: <span class="inc-risk">${i.risk_score || '—'}</span></span>
        <span>Status: <strong>${st}</strong></span>
        <span>Alerts: <strong style="color:var(--text)">${i.alert_count || '—'}</strong></span>
        ${i.src_ip ? `<span>Src: <span class="ip">${i.src_ip}</span></span>` : ''}
      </div>
    </div>`;
  }).join('');
}

function renderTactics(counts) {
  const labels = Object.keys(counts);
  const values = Object.values(counts);
  const colors = ['#3B82F6','#EF4444','#10B981','#F97316','#A855F7','#06B6D4','#EAB308','#EC4899'];
  const ctx = document.getElementById('tacticChart').getContext('2d');
  if (tacticChart) tacticChart.destroy();
  tacticChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ data: values, backgroundColor: colors.slice(0, labels.length),
      borderRadius: 4, borderSkipped: false }] },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(30,58,95,.4)' }, ticks: { color: '#64748B', font: { size: 10 } } },
        y: { grid: { display: false }, ticks: { color: '#94A3B8', font: { size: 10, family: 'Courier New' } } }
      }
    }
  });
}

function renderResponse(log) {
  const el = document.getElementById('response-list');
  if (!log.length) { el.innerHTML = '<div class="loading">NO ACTIONS YET</div>'; return; }
  el.innerHTML = log.map(r => {
    const ok = (r.result || '').toUpperCase() === 'SUCCESS';
    const act = (r.action || 'ACTION').toUpperCase();
    return `<div class="resp-item">
      <span class="resp-time">${r.time || '—'}</span>
      <span class="resp-action action-${act}">${act}</span>
      <span class="resp-target">${r.target || '—'}</span>
      <span class="${ok ? 'resp-ok' : 'resp-err'}">${ok ? '✓' : '✗'}</span>
    </div>`;
  }).join('');
}

function renderTimeline(summary) {
  const sessions = summary.sessions || [];
  const badge    = document.getElementById('tl-badge');
  const body     = document.getElementById('timeline-body');
  badge.textContent = `${sessions.length} sessions / ${summary.hours}h`;
  if (!sessions.length) { body.innerHTML = '<div class="loading">NO SESSIONS</div>'; return; }
  body.innerHTML = sessions.slice(-20).reverse().map(s => {
    const ts  = (s.start || '').replace('T',' ').slice(11,16);
    const cls = s.source === 'LIVE' ? 'live' : 'cicids';
    const abuse = s.enrichment && s.enrichment.abuse_score > 0
      ? `<span style="color:var(--red);font-size:10px"> [TI:${s.enrichment.abuse_score}]</span>` : '';
    return `<div class="tl-item ${cls}">
      <span class="tl-time">${ts}</span>
      <span class="tl-ip">${s.src_ip || '?'}</span>
      <span class="tl-tactic">${s.tactic || '?'}${abuse}</span>
      <span class="tl-count">${s.alert_count}</span>
      <span class="tl-dur">${s.duration_fmt || ''}</span>
    </div>`;
  }).join('');
}

function renderStats(stats) {
  document.getElementById('m-alerts').textContent    = stats.total_alerts ?? '—';
  document.getElementById('m-incidents').textContent = stats.active_inc   ?? '—';
  document.getElementById('m-risk').textContent      = stats.avg_risk     ?? '—';
  document.getElementById('m-live').textContent      = stats.live_count   ?? '0';
}

/* AI Analyst */
let aiRunning = false;
async function runAnalysis() {
  if (aiRunning) return;
  aiRunning = true;
  const btn  = document.getElementById('ai-btn');
  const dot  = document.getElementById('ai-dot');
  const text = document.getElementById('ai-text');
  const meta = document.getElementById('ai-meta');
  const stat = document.getElementById('ai-status-text');
  btn.disabled = true;
  dot.className  = 'ai-dot-spin';
  stat.textContent = 'Ollama — generating...';
  stat.style.color = 'var(--purple)';
  text.className   = 'ai-text';
  text.textContent = 'Running threat assessment...';
  meta.textContent = '';
  try {
    const r    = await fetch('/api/analyze?hours=1');
    const data = await r.json();
    dot.className = data.available ? 'ai-dot-ok' : 'ai-dot-off';
    stat.style.color = data.available ? 'var(--green)' : 'var(--muted)';
    stat.textContent = data.available ? 'Ollama — ready' : 'Ollama — offline';
    text.className   = 'ai-text loaded';
    text.textContent = data.analysis || 'No analysis returned.';
    if (data.generated_at) {
      const t = data.generated_at.slice(11,19);
      meta.textContent = `Generated at ${t} UTC | ${data.alert_count || 0} alerts analysed`;
    }
  } catch(e) {
    dot.className  = 'ai-dot-off';
    stat.textContent = 'Ollama — error';
    stat.style.color = 'var(--red)';
    text.textContent = 'Request failed. Is Ollama running?';
  }
  btn.disabled = false;
  aiRunning    = false;
}

function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toISOString().replace('T',' ').slice(0,19) + ' UTC';
}

async function refresh() {
  try {
    const res  = await fetch('/api/data');
    const data = await res.json();
    renderStats(data.stats);
    renderAlerts(data.alerts);
    renderIncidents(data.incidents);
    renderTactics(data.stats.tactic_counts || {});
    renderResponse(data.response);
  } catch(e) { console.error('Refresh failed:', e); }
}

async function refreshTimeline() {
  try {
    const res  = await fetch('/api/timeline?hours=24');
    const data = await res.json();
    renderTimeline(data);
  } catch(e) { console.error('Timeline refresh failed:', e); }
}

// Init
updateClock();
setInterval(updateClock, 1000);
refresh();
refreshTimeline();
setInterval(refresh, 5000);
setInterval(refreshTimeline, 30000);   // timeline is heavier, refresh every 30s
</script>
</body>
</html>"""


if __name__ == '__main__':
    print("\n  SentinelForge SOC Dashboard")
    print(f"  DB: {DB_PATH}")
    print("  URL: http://localhost:5001\n")
    app.run(host='0.0.0.0', port=5001, debug=False)
