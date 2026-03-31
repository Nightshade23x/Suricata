import json
import time
from flask import Flask, render_template_string

# Suricata log path (WSL)
LOG_FILE = r"\\wsl$\Ubuntu\var\log\suricata\eve.json"

app = Flask(__name__)

# store last read position (so we only read new alerts)
last_position = 0


def get_new_alerts():
    global last_position
    alerts = []

    with open(LOG_FILE, "r") as file:
        file.seek(last_position)   # go to last read position

        for line in file:
            try:
                data = json.loads(line)
            except:
                continue

            if data.get("event_type") == "alert":

                signature = data.get("alert", {}).get("signature")
                severity = data.get("alert", {}).get("severity")

                # ignore noise
                if "INFO" in str(signature):
                    continue

                if severity is not None and severity <= 2:

                    alert_info = {
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "signature": signature,
                        "severity": severity,
                    }

                    alerts.append(alert_info)

        last_position = file.tell()   # update position

    return alerts


# simple HTML dashboard
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
    </style>
</head>
<body>
    <h1>🚨 Suricata Live Alerts</h1>

    {% if alerts %}
        {% for alert in alerts %}
            <div class="alert {{ 'high' if alert.severity == 1 else 'medium' }}">
                <p><b>Source:</b> {{ alert.src_ip }}</p>
                <p><b>Destination:</b> {{ alert.dest_ip }}</p>
                <p><b>Signature:</b> {{ alert.signature }}</p>
                <p><b>Severity:</b> {{ alert.severity }}</p>
            </div>
        {% endfor %}
    {% else %}
        <p>No new alerts...</p>
    {% endif %}

</body>
</html>
"""


@app.route("/")
def home():
    alerts = get_new_alerts()
    return render_template_string(HTML, alerts=alerts)


if __name__ == "__main__":
    print("🚀 Starting dashboard...")
    app.run(debug=True)