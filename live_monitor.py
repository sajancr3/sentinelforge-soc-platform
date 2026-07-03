"""
SentinelForge - Live Attack Monitor
=====================================
Watches /var/log/auth.log for real-time SSH attacks.
Enriches source IPs via AbuseIPDB.
Auto-blocks after threshold failures via iptables.
Publishes events to the EventBus for downstream subscribers (AI Analyst, etc.)

Run with: sudo python3 live_monitor.py
"""

import sqlite3, os, re, time, subprocess, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enrichment.enrich_ip import enrich_ip
from core.event_bus import bus, ALERT_NEW, ALERT_ENRICHED, BLOCK_TRIGGERED, SCAN_DETECTED

DB       = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sentinelforge.db')
AUTH_LOG = '/var/log/auth.log'

SSH_FAIL = re.compile(r'Failed password for \S+ from ([\d.]+) port (\d+)')
SSH_SCAN = re.compile(r'Did not receive identification string from ([\d.]+)')
INVALID  = re.compile(r'Invalid user \S+ from ([\d.]+) port (\d+)')
DISC     = re.compile(r'Disconnected from authenticating user \S+ ([\d.]+) port (\d+)')

# ── State ──────────────────────────────────────────────────────────────────────
enrichment_cache = {}   # ip -> AbuseIPDB result
fail_counts      = {}   # ip -> failure count
blocked_ips      = set()
seen_scan_ips    = set()
AUTO_BLOCK_THRESHOLD = 10


# ── DB setup ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src_ip TEXT, dest_ip TEXT,
        src_port INTEGER, dest_port INTEGER, proto TEXT,
        tactic TEXT, technique TEXT, risk_score INTEGER,
        severity TEXT, status TEXT, signature TEXT, source TEXT DEFAULT 'CICIDS',
        abuse_score INTEGER DEFAULT 0, country TEXT DEFAULT '??',
        isp TEXT DEFAULT '', is_tor INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS response_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT, action TEXT, target TEXT, result TEXT, rule TEXT
    )""")
    for col, typ in [
        ('abuse_score', 'INTEGER DEFAULT 0'),
        ('country',     "TEXT DEFAULT '??'"),
        ('isp',         "TEXT DEFAULT ''"),
        ('is_tor',      'INTEGER DEFAULT 0'),
    ]:
        try:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {typ}")
        except Exception:
            pass
    conn.commit()
    conn.close()


# ── Enrichment (cached per session) ───────────────────────────────────────────
def get_enrichment(ip):
    if ip in enrichment_cache:
        return enrichment_cache[ip]
    print(f"[ENRICH] Querying AbuseIPDB for {ip}...")
    try:
        result = enrich_ip(ip)
    except Exception as e:
        result = {"ip": ip, "error": str(e), "abuse_score": 0, "country": "??"}
    enrichment_cache[ip] = result
    score   = result.get('abuse_score', 0)
    country = result.get('country', '??')
    tag     = " *** KNOWN MALICIOUS ***" if score >= 75 else ""
    print(f"[ENRICH] {ip} -> AbuseIPDB: {score}/100 | {country}{tag}")
    # Publish enrichment event
    bus.publish(ALERT_ENRICHED, {
        'ip':          ip,
        'abuse_score': score,
        'country':     country,
        'isp':         result.get('isp', ''),
        'is_tor':      result.get('is_tor', False),
    })
    return result


# ── Auto-block ─────────────────────────────────────────────────────────────────
def do_block(ip):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    ts = datetime.now().strftime("%H:%M:%S")
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"[BLOCK {ts}] iptables DROP -> {ip}")
        result = 'SUCCESS'
    except Exception as e:
        print(f"[BLOCK {ts}] FAILED: {e}")
        result = f'FAIL: {e}'
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO response_log (time, action, target, result, rule) VALUES (?,?,?,?,?)",
        (ts, 'BLOCK', ip, result, f'Auto-block >= {AUTO_BLOCK_THRESHOLD} failures')
    )
    conn.commit()
    conn.close()
    # Publish block event
    bus.publish(BLOCK_TRIGGERED, {'ip': ip, 'result': result, 'time': ts})


# ── Log response action ────────────────────────────────────────────────────────
def log_response(action, target, result, rule):
    ts = datetime.now().strftime("%H:%M:%S")
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO response_log (time, action, target, result, rule) VALUES (?,?,?,?,?)",
        (ts, action, target, result, rule)
    )
    conn.commit()
    conn.close()


# ── Insert alert ───────────────────────────────────────────────────────────────
def insert_alert(tactic, technique, risk, severity, src_ip, dest_ip,
                 sport, dport, sig, enrichment=None):
    e           = enrichment or {}
    abuse_score = e.get('abuse_score', 0)
    country     = e.get('country', '??')
    isp         = e.get('isp', '')
    is_tor      = 1 if e.get('is_tor', False) else 0

    # Risk boost from threat intel
    if abuse_score >= 75:
        risk     = min(100, risk + 20)
        severity = 'CRITICAL'
    elif abuse_score >= 50:
        risk     = min(100, risk + 10)

    ts   = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    conn = sqlite3.connect(DB)
    conn.execute("""INSERT INTO alerts
        (timestamp, src_ip, dest_ip, src_port, dest_port, proto,
         tactic, technique, risk_score, severity, status, signature, source,
         abuse_score, country, isp, is_tor)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        ts, src_ip, dest_ip, sport, dport, 'TCP',
        tactic, technique, risk, severity, 'NEW', sig, 'LIVE',
        abuse_score, country, isp, is_tor,
    ))
    conn.commit()
    conn.close()

    ti_tag = f" [TI:{abuse_score}/100 {country}]" if abuse_score > 0 else " [TI:querying]"
    print(f"[LIVE {ts[11:]}] *** {severity} *** {sig} from {src_ip}{ti_tag}")

    # Publish to event bus
    bus.publish(ALERT_NEW, {
        'timestamp':   ts,
        'src_ip':      src_ip,
        'dest_ip':     dest_ip,
        'tactic':      tactic,
        'technique':   technique,
        'risk_score':  risk,
        'severity':    severity,
        'signature':   sig,
        'source':      'LIVE',
        'abuse_score': abuse_score,
        'country':     country,
    })


# ── Main ───────────────────────────────────────────────────────────────────────
init_db()
bus.start()   # start EventBus dispatch thread

try:
    my_ip = subprocess.getoutput("hostname -I").split()[0]
except Exception:
    my_ip = "192.168.64.6"

print(f"[LIVE MONITOR] Watching {AUTH_LOG}")
print(f"[LIVE MONITOR] AbuseIPDB enrichment: ENABLED (cached per IP)")
print(f"[LIVE MONITOR] Auto-block after {AUTO_BLOCK_THRESHOLD} failures from same IP")
print(f"[LIVE MONITOR] EventBus: STARTED")
print(f"[LIVE MONITOR] Protecting: {my_ip}\n")

log_response('INIT', my_ip, 'SUCCESS', 'Live monitor started')

with open(AUTH_LOG, 'r') as f:
    f.seek(0, 2)   # seek to end of file
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue

        m = SSH_FAIL.search(line)
        if m:
            src, port = m.group(1), int(m.group(2))
            enrichment = get_enrichment(src)
            insert_alert('Brute Force', 'T1110.004', 75, 'HIGH',
                         src, my_ip, port, 22,
                         'SSH Brute Force - Failed Password', enrichment)
            fail_counts[src] = fail_counts.get(src, 0) + 1
            if fail_counts[src] == AUTO_BLOCK_THRESHOLD:
                log_response('ALERT', f'INC-{src.replace(".","_")}',
                             'SUCCESS', f'Threshold hit: {AUTO_BLOCK_THRESHOLD} failures')
            if fail_counts[src] >= AUTO_BLOCK_THRESHOLD:
                do_block(src)
            continue

        m = INVALID.search(line)
        if m:
            src, port = m.group(1), int(m.group(2))
            enrichment = get_enrichment(src)
            insert_alert('Brute Force', 'T1110.004', 70, 'HIGH',
                         src, my_ip, port, 22,
                         'SSH Brute Force - Invalid User', enrichment)
            fail_counts[src] = fail_counts.get(src, 0) + 1
            if fail_counts[src] >= AUTO_BLOCK_THRESHOLD:
                do_block(src)
            continue

        m = SSH_SCAN.search(line)
        if m:
            src = m.group(1)
            if src not in seen_scan_ips:
                seen_scan_ips.add(src)
                enrichment = get_enrichment(src)
                insert_alert('Reconnaissance', 'T1046', 60, 'MEDIUM',
                             src, my_ip, 0, 22,
                             'Port Scan - SSH Probe', enrichment)
                bus.publish(SCAN_DETECTED, {'src_ip': src, 'port': 22})
            continue

        m = DISC.search(line)
        if m:
            src, port = m.group(1), int(m.group(2))
            enrichment = enrichment_cache.get(src, {})
            insert_alert('Brute Force', 'T1110.004', 65, 'HIGH',
                         src, my_ip, port, 22,
                         'SSH Auth Failure - Disconnected', enrichment)
