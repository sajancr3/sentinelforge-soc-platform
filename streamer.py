import json, sqlite3, os, time, sys

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sentinelforge.db')
SAMPLES = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'tuesday_alerts.json'),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'friday_alerts.json'),
]
RATE = float(sys.argv[1]) if len(sys.argv) > 1 else 0.3

conn = sqlite3.connect(DB)
conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, src_ip TEXT, dest_ip TEXT,
    src_port INTEGER, dest_port INTEGER, proto TEXT,
    tactic TEXT, technique TEXT, risk_score INTEGER,
    severity TEXT, status TEXT, signature TEXT, source TEXT DEFAULT 'CICIDS'
)""")
conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, title TEXT, risk_score INTEGER,
    status TEXT, tactic TEXT, src_ip TEXT, timestamp TEXT, alert_count INTEGER
)""")
conn.commit()

all_events = []
for path in SAMPLES:
    if not os.path.exists(path):
        print(f"[STREAMER] Missing: {path}")
        continue
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                all_events.append(json.loads(line))

print(f"[STREAMER] {len(all_events)} CICIDS events queued at 1/{RATE}s")
print(f"[STREAMER] Est. time: {len(all_events)*RATE/60:.1f} min")
print(f"[STREAMER] Start Parrot attacks anytime — live_monitor catches them live.\n")

count = 0
for e in all_events:
    a = e.get('alert', {})
    conn.execute("""INSERT INTO alerts
        (timestamp, src_ip, dest_ip, src_port, dest_port, proto,
         tactic, technique, risk_score, severity, status, signature, source)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        e.get('timestamp'), e.get('src_ip'), e.get('dest_ip'),
        e.get('src_port', 0), e.get('dest_port', 0), e.get('proto', 'TCP'),
        e.get('mitre_tactic'), e.get('mitre_technique'),
        e.get('risk_score'), e.get('severity'), 'NEW',
        a.get('signature', ''), 'CICIDS',
    ))
    conn.commit()
    count += 1
    if count % 100 == 0:
        print(f"[STREAMER] {count}/{len(all_events)} CICIDS events loaded...")
    time.sleep(RATE)

print(f"[STREAMER] Done. {count} CICIDS events in DB.")
conn.close()
