import json, sqlite3, os

DB = os.path.join(os.path.dirname(__file__), 'sentinelforge.db')
SAMPLES = [
    os.path.join(os.path.dirname(__file__), 'samples', 'tuesday_alerts.json'),
    os.path.join(os.path.dirname(__file__), 'samples', 'friday_alerts.json'),
]

conn = sqlite3.connect(DB)
cur  = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src_ip TEXT, dest_ip TEXT,
        src_port INTEGER, dest_port INTEGER, proto TEXT,
        tactic TEXT, technique TEXT, risk_score INTEGER,
        severity TEXT, status TEXT, signature TEXT
    )
""")

cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY, title TEXT, risk_score INTEGER,
        status TEXT, tactic TEXT, src_ip TEXT,
        timestamp TEXT, alert_count INTEGER
    )
""")

total = 0
for path in SAMPLES:
    if not os.path.exists(path):
        print("Missing:", path)
        continue
    with open(path) as f:
        lines = [l.strip() for l in f if l.strip()]
    for line in lines:
        e = json.loads(line)
        a = e.get('alert', {})
        cur.execute("""
            INSERT INTO alerts
            (timestamp, src_ip, dest_ip, src_port, dest_port, proto,
             tactic, technique, risk_score, severity, status, signature)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            e.get('timestamp'), e.get('src_ip'), e.get('dest_ip'),
            e.get('src_port'), e.get('dest_port'), e.get('proto'),
            e.get('mitre_tactic'), e.get('mitre_technique'),
            e.get('risk_score'), e.get('severity'), e.get('status','NEW'),
            a.get('signature',''),
        ))
        total += 1
    print(f"Loaded {len(lines)} alerts from {os.path.basename(path)}")

# Seed two incidents from the data
cur.execute("DELETE FROM incidents")
cur.execute("""
    INSERT OR REPLACE INTO incidents VALUES
    ('INC-001','SSH Brute Force Campaign - 3000 events',75,'INVESTIGATING',
     'Brute Force','205.174.165.73','2026-07-03 09:00:00',3000)
""")
cur.execute("""
    INSERT OR REPLACE INTO incidents VALUES
    ('INC-002','PortScan Sweep - Internal Reconnaissance',60,'NEW',
     'Reconnaissance','192.168.10.50','2026-07-03 14:00:00',3000)
""")

conn.commit()
conn.close()
print(f"\nDone. {total} total alerts in DB. 2 incidents seeded.")
