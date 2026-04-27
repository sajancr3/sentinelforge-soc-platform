from flask import Flask, render_template_string, jsonify
import json
import os

app = Flask(__name__)

LOG_FILE = "logs/enriched_alerts.json"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SentinelForge SOC Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            background: #0d1117;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
        }

        header {
            background: #010409;
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #30363d;
        }

        h1 {
            color: #58a6ff;
            margin: 0;
        }

        .subtitle {
            color: #8b949e;
            margin-top: 8px;
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            padding: 16px;
        }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 16px;
        }

        .metric {
            font-size: 30px;
            color: #58a6ff;
            font-weight: bold;
        }

        .alerts {
            padding: 16px;
        }

        .alert {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 14px;
            margin-bottom: 12px;
        }

        .Critical {
            border-left: 6px solid #ff4d4d;
        }

        .High {
            border-left: 6px solid #ff9800;
        }

        .Medium {
            border-left: 6px solid #f2cc60;
        }

        .Low {
            border-left: 6px solid #3fb950;
        }

        code {
            color: #79c0ff;
        }

        .small {
            color: #8b949e;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ SentinelForge SOC Dashboard</h1>
        <div class="subtitle">Real-Time Detection • Suricata • Risk Scoring • Response Engine</div>
    </header>

    <section class="metrics">
        <div class="card">
            <div>Total Alerts</div>
            <div class="metric">{{ total_alerts }}</div>
        </div>

        <div class="card">
            <div>Unique Attackers</div>
            <div class="metric">{{ unique_attackers }}</div>
        </div>

        <div class="card">
            <div>Max Risk</div>
            <div class="metric">{{ max_risk }}</div>
        </div>

        <div class="card">
            <div>High/Critical</div>
            <div class="metric">{{ high_alerts }}</div>
        </div>
    </section>

    <section class="alerts">
        <h2>Recent Alerts</h2>

        {% if alerts|length == 0 %}
            <div class="alert Medium">No alerts yet. Run Nmap or trigger Suricata.</div>
        {% endif %}

        {% for alert in alerts|reverse %}
        <div class="alert {{ alert.get('risk_level', 'Medium') }}">
            <b>{{ alert.get('alert', 'Unknown Alert') }}</b>
            <div class="small">{{ alert.get('timestamp', 'N/A') }}</div>
            <br>

            <b>Source IP:</b> {{ alert.get('source_ip', 'unknown') }} |
            <b>Destination:</b> {{ alert.get('destination_ip', 'unknown') }}
            <br>

            <b>Protocol:</b> {{ alert.get('protocol', 'unknown') }} |
            <b>Signature:</b> {{ alert.get('signature', 'N/A') }}
            <br>

            <b>Attack Type:</b> {{ alert.get('attack_type', 'Unknown') }} |
            <b>MITRE:</b> {{ alert.get('mitre', 'N/A') }}
            <br>

            <b>Risk:</b> {{ alert.get('risk_level', 'Unknown') }}
            ({{ alert.get('risk_score', 0) }}/100)
            <br>

            <b>Recommendation:</b> {{ alert.get('recommendation', 'N/A') }}
            <br>

            <b>Response:</b>
            <code>{{ alert.get('response_action', 'No response action') }}</code>
        </div>
        {% endfor %}
    </section>
</body>
</html>
"""


def load_alerts():
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception as e:
        print(f"[DASHBOARD ERROR] Failed to read alerts: {e}")
        return []


@app.route("/")
def home():
    alerts = load_alerts()
    recent = alerts[-30:]

    total_alerts = len(alerts)
    unique_attackers = len(set(a.get("source_ip", "unknown") for a in alerts))
    max_risk = max([a.get("risk_score", 0) for a in alerts], default=0)
    high_alerts = sum(1 for a in alerts if a.get("risk_level") in ["High", "Critical"])

    return render_template_string(
        HTML,
        alerts=recent,
        total_alerts=total_alerts,
        unique_attackers=unique_attackers,
        max_risk=max_risk,
        high_alerts=high_alerts
    )


@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
