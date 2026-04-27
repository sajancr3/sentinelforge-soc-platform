from flask import Flask, render_template_string, jsonify
import json
import os
from collections import Counter

app = Flask(__name__)

LOG_FILE = "logs/enriched_alerts.json"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SentinelForge Elite SOC Dashboard</title>
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
            padding: 22px;
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
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            padding: 16px;
        }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 16px;
        }

        .metric {
            font-size: 30px;
            color: #58a6ff;
            font-weight: bold;
        }

        .section {
            padding: 16px;
        }

        .alert {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
        }

        .Critical {
            border-left: 7px solid #ff4d4d;
        }

        .High {
            border-left: 7px solid #ff9800;
        }

        .Medium {
            border-left: 7px solid #f2cc60;
        }

        .Low {
            border-left: 7px solid #3fb950;
        }

        code {
            color: #79c0ff;
            word-break: break-word;
        }

        .small {
            color: #8b949e;
            font-size: 13px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            overflow: hidden;
        }

        th, td {
            padding: 10px;
            border-bottom: 1px solid #30363d;
            text-align: left;
        }

        th {
            color: #58a6ff;
            background: #010409;
        }

        .badge {
            padding: 4px 8px;
            border-radius: 999px;
            background: #30363d;
            color: white;
            font-size: 12px;
        }

        .timeline {
            margin-top: 8px;
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ SentinelForge Elite SOC Dashboard</h1>
        <div class="subtitle">Detection • Correlation • Risk Scoring • GeoIP • Automated Response</div>
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
            <div>Critical Alerts</div>
            <div class="metric">{{ critical_alerts }}</div>
        </div>

        <div class="card">
            <div>Block Decisions</div>
            <div class="metric">{{ block_decisions }}</div>
        </div>
    </section>

    <section class="section">
        <h2>Top Attacker IPs</h2>
        <table>
            <tr>
                <th>Source IP</th>
                <th>Events</th>
            </tr>
            {% for ip, count in top_attackers %}
            <tr>
                <td>{{ ip }}</td>
                <td>{{ count }}</td>
            </tr>
            {% endfor %}
        </table>
    </section>

    <section class="section">
        <h2>Attack Types Observed</h2>
        <table>
            <tr>
                <th>Attack Type</th>
                <th>Count</th>
            </tr>
            {% for attack_type, count in attack_counts %}
            <tr>
                <td>{{ attack_type }}</td>
                <td>{{ count }}</td>
            </tr>
            {% endfor %}
        </table>
    </section>

    <section class="section">
        <h2>Recent Alerts</h2>

        {% if alerts|length == 0 %}
            <div class="alert Medium">No alerts yet. Run an approved lab scan from the attacker VM.</div>
        {% endif %}

        {% for alert in alerts|reverse %}
        <div class="alert {{ alert.get('risk_level', 'Medium') }}">
            <b>{{ alert.get('alert', 'Unknown Alert') }}</b>
            <span class="badge">{{ alert.get('risk_level', 'Unknown') }}</span>
            <div class="small">{{ alert.get('timestamp', 'N/A') }}</div>
            <br><br>

            <b>Source IP:</b> {{ alert.get('source_ip', 'unknown') }}
            →
            <b>Destination IP:</b> {{ alert.get('destination_ip', 'unknown') }}
            <br>

            <b>Location:</b> {{ alert.get('country', 'Unknown') }}, {{ alert.get('city', 'Unknown') }}
            <br>

            <b>ISP:</b> {{ alert.get('isp', 'Unknown') }}
            <br>

            <b>Attack Type:</b> {{ alert.get('attack_type', 'Unknown') }}
            <br>

            <b>Classification:</b> {{ alert.get('classification', alert.get('attacker_classification', 'Unknown')) }}
            <br>

            <b>Risk Score:</b> {{ alert.get('risk_score', 0) }}/100
            <br>

            <b>Events From IP:</b> {{ alert.get('events', alert.get('events_from_ip', 0)) }}
            <br>

            <b>MITRE:</b> {{ alert.get('mitre', 'N/A') }}
            <br>

            <b>Signature:</b>
            <code>{{ alert.get('signature', 'N/A') }}</code>
            <br>

            <b>Recommendation:</b> {{ alert.get('recommendation', 'N/A') }}
            <br>

            <b>Response:</b>
            <code>{{ alert.get('response', alert.get('response_action', 'No response action')) }}</code>
            <br><br>

            <b>Timeline:</b>
            <ul class="timeline">
                {% for item in alert.get('timeline', []) %}
                    {% if item is string %}
                        <li>{{ item }}</li>
                    {% else %}
                        <li>{{ item.get('time', '') }} — {{ item.get('attack_type', '') }} — {{ item.get('alert', '') }}</li>
                    {% endif %}
                {% endfor %}
            </ul>
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
    critical_alerts = sum(1 for a in alerts if a.get("risk_level") == "Critical")

    block_decisions = sum(
        1 for a in alerts
        if "BLOCK" in a.get("response", "") or
           "block" in a.get("response", "") or
           "BLOCK" in a.get("response_action", "") or
           "block" in a.get("response_action", "")
    )

    top_attackers = Counter(a.get("source_ip", "unknown") for a in alerts).most_common(5)
    attack_counts = Counter(a.get("attack_type", "Unknown") for a in alerts).most_common(10)

    return render_template_string(
        HTML,
        alerts=recent,
        total_alerts=total_alerts,
        unique_attackers=unique_attackers,
        max_risk=max_risk,
        critical_alerts=critical_alerts,
        block_decisions=block_decisions,
        top_attackers=top_attackers,
        attack_counts=attack_counts
    )


@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
