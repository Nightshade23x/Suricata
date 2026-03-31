import json
import sqlite3
from flask import Flask, request, render_template_string

LOG_FILE = r"\\wsl$\Ubuntu\var\log\suricata\eve.json"

app = Flask(__name__)

last_position = 0


# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dest_ip TEXT,
        signature TEXT,
        severity INTEGER
    )
    """)

    conn.commit()
    conn.close()


# ---------------- CLASSIFICATION ----------------
def classify(signature):
    if signature is None:
        return "Unknown"

    signature = signature.lower()

    if "scan" in signature:
        return "Reconnaissance"
    elif "brute" in signature:
        return "Brute Force"
    elif "malware" in signature:
        return "Malware"
    elif "dos" in signature:
        return "DoS"
    else:
        return "General"


# ---------------- GET NEW ALERTS ----------------
def get_new_alerts():
    global last_position
    alerts = []

    with open(LOG_FILE, "r") as file:
        file.seek(last_position)

        for line in file:
            try:
                data = json.loads(line)
            except:
                continue

            if data.get("event_type") == "alert":

                signature = data.get("alert", {}).get("signature")
                severity = data.get("alert", {}).get("severity")

                if "INFO" in str(signature):
                    continue

                if severity is not None and severity <= 2:

                    alert_info = {
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "signature": signature,
                        "severity": severity,
                        "type": classify(signature)
                    }

                    alerts.append(alert_info)

        last_position = file.tell()

    return alerts


# ---------------- SAVE ALERTS ----------------
def save_alerts(alerts):
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()

    for alert in alerts:
        c.execute("""
        INSERT INTO alerts (src_ip, dest_ip, signature, severity)
        VALUES (?, ?, ?, ?)
        """, (alert["src_ip"], alert["dest_ip"], alert["signature"], alert["severity"]))

    conn.commit()
    conn.close()


# ---------------- FETCH ALERTS ----------------
def fetch_alerts(ip=None):
    conn = sqlite3.connect("alerts.db")
    c = conn.cursor()

    if ip:
        c.execute("SELECT * FROM alerts WHERE src_ip=? OR dest_ip=?", (ip, ip))
    else:
        c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20")

    data = c.fetchall()
    conn.close()

    return data


# ---------------- HTML ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Suricata Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: Arial; background: #0f172a; color: white; }
        h1 { color: #38bdf8; }
        .alert { background: #1e293b; padding: 10px; margin: 10px; border-radius: 8px; }
        .high { border-left: 5px solid red; }
        .medium { border-left: 5px solid orange; }
        input { padding: 8px; margin: 10px; }
    </style>
</head>
<body>

<h1>🚨 Suricata Dashboard</h1>

<form method="get">
    <input type="text" name="ip" placeholder="Search by IP">
    <button type="submit">Search</button>
</form>

<h2>Live Alerts</h2>
{% for alert in live_alerts %}
<div class="alert {{ 'high' if alert.severity == 1 else 'medium' }}">
    <p><b>Type:</b> {{ alert.type }}</p>
    <p><b>Source:</b> {{ alert.src_ip }}</p>
    <p><b>Destination:</b> {{ alert.dest_ip }}</p>
    <p><b>Signature:</b> {{ alert.signature }}</p>
</div>
{% endfor %}

<h2>History</h2>
{% for row in history %}
<div class="alert">
    <p>{{ row }}</p>
</div>
{% endfor %}

</body>
</html>
"""


# ---------------- ROUTE ----------------
@app.route("/")
def home():
    ip = request.args.get("ip")

    new_alerts = get_new_alerts()
    save_alerts(new_alerts)

    history = fetch_alerts(ip)

    return render_template_string(HTML, live_alerts=new_alerts, history=history)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    init_db()
    print("🚀 Dashboard running...")
    app.run(debug=True)